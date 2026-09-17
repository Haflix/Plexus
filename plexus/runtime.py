"""Cross-cutting runtime primitives for Plexus.

Mutable module-level runtime state shared by both the event subsystem and
the request/execute dispatch paths: the per-worker-thread sync-call-chain
threadlocal, the emit/execute recursion-guard ContextVars, the plugin
lifecycle timeout defaults, and the Phase 2b sync-bridge machinery
(``GatedExecutor`` / ``_bridge_wait`` / ``_held_permit``). Kept as a
near-neutral module: its ONLY plexus import is ``RequestException`` from
``exceptions`` (which itself imports nothing from the package), so core.py,
the events.py mixin, utils.py, and notifier.py can all pull from here
without a circular dependency. core.py re-exports the runtime-state names
for back-compat (utils.py pulls the timeouts; bare-name references inside
class Plexus methods keep resolving).
"""

import concurrent.futures
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from typing import NamedTuple, Optional

from .exceptions import RequestException


# Tracks the sync call chain on each threadpool worker thread.
# Used by execute_sync / _call_endpoint to detect circular sync calls
# that would deadlock the ThreadPoolExecutor.
_sync_call_chain = threading.local()


# Default plugin-readiness gate timeout (seconds). Used by
# _wait_for_plugin_ready before dispatching to a plugin endpoint;
# raises asyncio.TimeoutError on expiry. Per spec must not be reduced
# below 30 in normal operation. Configurable via
# general.plugin_ready_timeout in config.yml; tests may override
# self.plugin_ready_timeout directly.
DEFAULT_PLUGIN_READY_TIMEOUT: float = 60.0

# Default plugin-disable timeout (seconds). Wraps user on_disable in
# asyncio.wait_for in disable_plugin / _pop_plugin_under_lock so a
# misbehaving on_disable can't hang pop_plugin / _reload_plugin /
# purge_plugins indefinitely. close() already had its own 30s; this
# brings runtime hot-reload paths to parity. Configurable via
# general.plugin_disable_timeout in config.yml; tests may override
# self.plugin_disable_timeout directly.
DEFAULT_PLUGIN_DISABLE_TIMEOUT: float = 30.0

# C-017: Default plugin-enable timeout (seconds). Wraps user on_enable
# in asyncio.wait_for in _enable_plugin_under_lock so a misbehaving
# on_enable can't pin lifecycle_lock indefinitely (saturating
# _plugin_executor with 32 hung sync handlers was a documented DoS in
# the C-017 audit). Symmetric with the disable side; configurable via
# general.plugin_enable_timeout in config.yml; tests may override
# self.plugin_enable_timeout directly.
DEFAULT_PLUGIN_ENABLE_TIMEOUT: float = 30.0


# B-073: Internal event bus recursion guard. Module-level ContextVar
# (NOT instance attr) so the per-task counter is shared across emit
# calls in the same task while remaining isolated between tasks via
# Python's contextvars task-inheritance. Increment with
# ``token = _EMIT_DEPTH.set(...)``; restore with ``_EMIT_DEPTH.reset(token)``
# — naive ``set(get() - 1)`` corrupts inherited parent-task state under
# nested ``asyncio.create_task`` fan-out. ``_MAX_EMIT_DEPTH = 5`` aborts
# pathological recursive observer chains.
_EMIT_DEPTH: ContextVar[int] = ContextVar("_aio_emit_depth", default=0)
_MAX_EMIT_DEPTH: int = 5

# R2-FF-4: Execute-side recursion guard. Mirrors ``_EMIT_DEPTH`` for
# the sync-execute path. The framework's sync-endpoint thread pool has
# a fixed worker count (default 32); a chain of nested execute_sync
# calls fanning in faster than workers can drain deadlocks the pool.
# This ContextVar tracks per-task nesting depth so the framework can
# abort a runaway chain BEFORE the pool fills. ``_MAX_EXECUTE_DEPTH``
# is set conservatively below the worker count so other framework
# work (observer dispatch, networking) still gets pool slots.
# Increment with ``token = _EXECUTE_DEPTH.set(...)``; restore with
# ``_EXECUTE_DEPTH.reset(token)`` — naive ``set(get() - 1)`` corrupts
# inherited parent-task state under nested ``asyncio.create_task``
# fan-out, same trap _EMIT_DEPTH avoids.
_EXECUTE_DEPTH: ContextVar[int] = ContextVar("_aio_execute_depth", default=0)
_MAX_EXECUTE_DEPTH: int = 16


# ── Framework-stamped caller identity ─────────────────────────────────
#
# "Who is really making this call." At every framework->plugin dispatch the
# framework pushes the identity of the plugin it is about to enter as the
# innermost frame, so a plugin re-entering execute/publish/request sees its
# OWN identity -- the authoritative caller, never the ``author`` argument
# (that is a separate, gated CLAIM; see the capability gate below).
#
# Two parallel stores of the same shape (a tuple of CallerIdentity,
# outermost-first), because run_in_executor does not propagate a ContextVar
# into a worker thread:
#   _caller_chain         — async path (awaited handlers; copied into child
#                           tasks by create_task).
#   _sync_identity_chain  — sync path (handlers on a pool worker), seeded from
#                           the loop-side chain captured at dispatch.
# Distinct from ``_sync_call_chain`` (the flat "plugin.method" cycle-detection
# chain), whose ``target in chain`` membership tests depend on its shape.
#
# Stamping is gated by a per-Plexus ``_identity_active`` flag (default off):
# when off, every push/pop below is skipped, so a default node pays nothing
# per dispatch.

class CallerIdentity(NamedTuple):
    """One frame of the caller chain: the entered plugin's name + uuid, plus an
    ``exempt`` marker set when the framework enters a lifecycle hook (so the
    whole nested sub-chain is skipped by rate-limit charging). ``exempt`` rides
    every nested frame via the chain."""
    name: str
    uuid: str
    exempt: bool = False


_caller_chain: ContextVar[tuple] = ContextVar("_aio_caller_chain", default=())
_sync_identity_chain = threading.local()


def current_caller_chain() -> tuple:
    """The active caller chain (outermost-first tuple of CallerIdentity).

    Reads the sync threadlocal when this thread is a pool worker running a
    seeded sync handler (the ContextVar is not visible there); otherwise the
    async ContextVar. Returns ``()`` when no plugin frame is active.
    """
    sync = getattr(_sync_identity_chain, "chain", None)
    if sync:
        return sync
    return _caller_chain.get()


@contextmanager
def caller_chain_scope(ident: "CallerIdentity", active: bool):
    """Push ``ident`` onto the async caller chain for the block, then pop.

    A no-op when ``active`` is False. Implemented as a sync contextmanager
    (the set/reset are synchronous) so it wraps an awaited dispatch with a
    plain ``with`` -- the ContextVar token is reset in the same task that set
    it, which is correct across the inner ``await``.
    """
    if not active:
        yield
        return
    token = _caller_chain.set(_caller_chain.get() + (ident,))
    try:
        yield
    finally:
        _caller_chain.reset(token)


def seeded_sync_chain(active: bool, ident: "CallerIdentity"):
    """The chain to seed a sync worker's threadlocal with: the loop-side
    parent chain captured now, plus ``ident``. Returns ``None`` when
    ``active`` is False so the dispatch wrapper skips the threadlocal write
    entirely (zero overhead off). Call on the loop thread at dispatch.
    """
    if not active:
        return None
    return _caller_chain.get() + (ident,)


# ── Capability gate (identity assertion) ──────────────────────────────
#
# The caller chain above stamps who is really calling. This gate governs who a
# call may CLAIM to be -- the ``author`` / ``author_id`` passed to execute. With
# no grant configured the gate is inert (``author`` stays a plain routing
# label, the historical behaviour); once any grant exists, an author that
# differs from the real caller is an ASSERTION that must be authorised:
# ``system_caller`` to claim "system", ``impersonation_allowed`` (scope
# caller | ancestor | [list]) to claim another plugin. Default-deny, fail-closed
# (raises CapabilityException before dispatch), audited.
#
# ``_asserted_identity`` carries the active asserted identity down the call
# chain (a ContextVar, copied into child tasks). It drives the no-chaining rule
# -- an already-impersonating chain may only continue the SAME assertion -- and
# attribution of charges to the impersonated identity.

_asserted_identity: ContextVar = ContextVar("_aio_asserted_identity", default=None)

# Sync-bridge mirror of ``_asserted_identity`` (parallel to ``_sync_identity_chain``
# for the caller chain). A pool worker cannot see the ContextVar, so the active
# assertion is seeded into this threadlocal at the sync-endpoint dispatch and read
# back (``current_asserted_identity``) by the sync mirror when the endpoint body
# re-enters the bus, then re-seated loop-side onto the ContextVar across the bridge.
# Without it, a sync-endpoint re-entry under an active impersonation loses the
# assertion: the no-chaining gate is bypassed and the OUT charge mis-attributes.
# None = not seeded / no active assertion (the chain's None-skip convention).
_sync_asserted_identity = threading.local()


class CapabilityVerdict(NamedTuple):
    """Outcome of ``evaluate_capability``.

    allowed      -- False -> the caller (the gate) raises CapabilityException.
    author       -- effective name claim to carry forward.
    author_id    -- effective uuid claim; for an in-chain impersonation this is
                    the target frame's REAL uuid, not the caller-supplied value.
    asserted     -- the CallerIdentity to install in ``_asserted_identity`` for
                    the operation (None = no new scope: a self-call, or
                    continuing an assertion already active up the chain).
    is_assertion -- True when the claim differs from the real caller (audit it).
    reason       -- human-readable basis (for audit / the deny message).
    """
    allowed: bool
    author: str
    author_id: str
    asserted: Optional["CallerIdentity"]
    is_assertion: bool
    reason: str


def _same_ident(ident: "CallerIdentity", name: str, uuid: str) -> bool:
    return ident is not None and ident.name == name and ident.uuid == uuid


def evaluate_capability(real, chain, author, author_id, grant, active_asserted):
    """Pure capability decision. The framework-side gate handles the ContextVar
    reads, audit, and raise; this function is side-effect-free.

    real           -- CallerIdentity of the plugin making the call (chain's
                      innermost). The framework gate must short-circuit (no
                      gating) when the chain is EMPTY -- an empty chain is
                      framework/system origin, which is trusted, so this function
                      is only called with a real plugin frame.
    chain          -- the full caller chain (outermost-first); chain[-1] is real.
    author/author_id -- the claim passed to execute/publish/request.
    grant          -- real's grants: {"system_caller": bool,
                      "impersonation": "caller"|"ancestor"|list|None}. {} if none.
    active_asserted -- the CallerIdentity currently in _asserted_identity, or None.
    """
    # Claiming one's own identity is not an assertion -- always allowed.
    if author == real.name and author_id == real.uuid:
        return CapabilityVerdict(True, author, author_id, None, False, "self")

    # No-chaining: inside an active impersonation, only CONTINUING the same
    # asserted identity is allowed; any different new assertion is denied,
    # regardless of the caller's own grants (blocks laundering across budgets).
    if active_asserted is not None:
        if _same_ident(active_asserted, author, author_id):
            return CapabilityVerdict(True, author, author_id, None, True, "continue-same")
        return CapabilityVerdict(
            False, author, author_id, None, True,
            f"no-chaining: chain already asserts {active_asserted.name!r}; "
            f"{real.name!r} cannot newly assert {author!r}",
        )

    # Fresh assertion -> consult real's grants.
    if author == "system":
        if grant.get("system_caller"):
            return CapabilityVerdict(
                True, "system", "system",
                CallerIdentity("system", "system"), True, "system_caller grant",
            )
        return CapabilityVerdict(
            False, author, author_id, None, True,
            f"{real.name!r} claimed author='system' without the system_caller grant",
        )

    scope = grant.get("impersonation")
    if scope is None:
        return CapabilityVerdict(
            False, author, author_id, None, True,
            f"{real.name!r} attempted to impersonate {author!r} without "
            f"impersonation_allowed",
        )

    # Explicit [targets]: a static trust independent of the live chain. The
    # caller-supplied uuid is accepted (the operator authorised real to act as
    # these names).
    if isinstance(scope, (list, tuple)):
        if author in scope:
            return CapabilityVerdict(
                True, author, author_id,
                CallerIdentity(author, author_id), True, "explicit-target grant",
            )
        return CapabilityVerdict(
            False, author, author_id, None, True,
            f"{real.name!r} may impersonate {list(scope)!r}, not {author!r}",
        )

    # "caller" / "ancestor": the target must GENUINELY be in the live chain
    # (you can only impersonate someone who actually caused this call). Match by
    # name and adopt that frame's REAL uuid (caller cannot fake the uuid).
    ancestry = chain[:-1]  # everyone above real (real == chain[-1])
    if scope == "caller":
        candidates = (ancestry[-1],) if ancestry else ()
    elif scope == "ancestor":
        candidates = ancestry
    else:
        return CapabilityVerdict(
            False, author, author_id, None, True,
            f"{real.name!r} has an unrecognised impersonation scope {scope!r}",
        )
    match = next((f for f in candidates if f.name == author), None)
    if match is not None:
        return CapabilityVerdict(
            True, match.name, match.uuid, match, True, f"{scope} scope",
        )
    return CapabilityVerdict(
        False, author, author_id, None, True,
        f"{real.name!r} may impersonate its {scope} but {author!r} is not in the "
        f"live caller chain",
    )


@contextmanager
def asserted_identity_scope(ident: "Optional[CallerIdentity]"):
    """Install ``ident`` as the active asserted identity for the block, then
    restore. A no-op when ``ident`` is None (a self-call or a continue-same
    assertion adds no new scope). Used by the gate to wrap a gated operation so
    nested calls inherit the assertion (for the no-chaining check and for
    attributing charges to the impersonated identity)."""
    if ident is None:
        yield
        return
    token = _asserted_identity.set(ident)
    try:
        yield
    finally:
        _asserted_identity.reset(token)


@contextmanager
def establish_caller_chain(chain: tuple):
    """REPLACE the async caller chain with ``chain`` for the block, then
    restore. Used by the sync-bridge handoff: a plugin's sync handler carries
    its identity in the _sync_identity_chain threadlocal, which is invisible once
    a sync mirror bridges the operation onto the loop via
    run_coroutine_threadsafe. The mirror captures the worker chain and re-seats
    it here so the loop-side dispatch attributes to the originating handler.
    Distinct from ``caller_chain_scope`` (which APPENDS one frame): the loop
    context for a freshly-bridged coroutine is empty, so the whole captured
    chain is set, not appended. The caller guards on an empty chain.
    """
    token = _caller_chain.set(chain)
    try:
        yield
    finally:
        _caller_chain.reset(token)


def current_asserted_identity():
    """The active asserted (impersonation) identity, or None.

    Reads the sync threadlocal when this thread is a pool worker running a seeded
    sync handler (the ContextVar is invisible there); otherwise the async
    ContextVar. Mirrors ``current_caller_chain``. Used worker-side by the sync
    mirrors to capture the assertion active at the originating dispatch, so it can
    be re-seated loop-side across the bridge.
    """
    v = getattr(_sync_asserted_identity, "value", None)
    if v is not None:
        return v
    return _asserted_identity.get()


def seeded_sync_asserted(active: bool):
    """The asserted identity to seed a sync worker's threadlocal with: the value
    active at dispatch. Returns None when identity is off (the dispatch wrapper
    then skips the write -- zero overhead off) AND, harmlessly, when active with no
    impersonation (the worker read falls through to the ContextVar's None either
    way). Call on the loop thread at dispatch. Mirrors ``seeded_sync_chain``.
    """
    if not active:
        return None
    return _asserted_identity.get()


@contextmanager
def establish_asserted_identity(ident: "Optional[CallerIdentity]"):
    """Re-seat a worker-captured asserted identity onto the loop ContextVar for a
    bridged coroutine's lifetime (the sync-bridge handoff). Mirrors
    ``establish_caller_chain``. A no-op when ``ident`` is None: the freshly-bridged
    coroutine runs in a loop context whose ``_asserted_identity`` is already None,
    so "no active assertion" needs no install (and skipping avoids a needless
    set/reset)."""
    if ident is None:
        yield
        return
    token = _asserted_identity.set(ident)
    try:
        yield
    finally:
        _asserted_identity.reset(token)


# ── Phase 2b: deadlock-free sync bridge (native, stdlib-only) ──────────
#
# A sync endpoint body runs on a GatedExecutor carrier thread. When that
# body itself makes a sync-bridge call (execute_sync / publish_event_sync
# / ...), the carrier parks on a loop-side future. The old code parked
# while still occupying a pool worker; under fan-out (many concurrent
# bodies each nesting once) every worker parks and the pool deadlocks —
# a BREADTH problem, not depth. The fix splits the budget in two:
#
#   E (execution) — = the pool's effective worker budget; held while a
#       body runs, RELEASED at every park (see _bridge_wait) and
#       re-acquired on resume, so a parked parent always frees its slot
#       for the nested child it is blocked on.
#   M (thread ceiling) — acquired non-blocking at dispatch, held the FULL
#       carrier lifetime INCLUDING while parked; bounds total live carrier
#       threads and loud-rejects on saturation instead of queueing.
#
# Both are required: E-alone lets threads grow unbounded; M-alone
# re-deadlocks (a parked parent holds M, its child cannot acquire one).

# Per-worker record of the GatedExecutor whose E-permit this thread holds
# (``.gated``; None when not an active carrier) plus a ``.poisoned`` flag.
# A threading.local, NOT a ContextVar: a carrier and the bridge-park it
# performs run on the SAME worker thread/stack, and run_in_executor does
# NOT propagate contextvars into the worker (verified by ctxvar_probe).
# Holding the GatedExecutor (not just the semaphore) lets _bridge_wait
# consult the pool's shutdown flag.
_held_permit = threading.local()

# Bounded re-acquire budget for a parked carrier resuming after its bridge
# wait returns (seconds). Generous; only the saturation/shutdown give-up
# path ever waits anywhere near this long.
REACQUIRE_GRACE: float = 30.0

# Per-pool thread ceilings (M). Runaway-prevention backstops a typical
# deployment never tunes, so hardcoded here rather than exposed as config
# keys. The matching execution budgets (E) keep their existing
# general.*_workers config keys (sync dispatchers) / the bare
# max_workers=32 (the plugin executor).
PLUGIN_EXECUTOR_THREAD_CEILING: int = 128
SYNC_DISPATCHER_THREAD_CEILING: int = 32
SYNC_STREAM_THREAD_CEILING: int = 16


def _bridge_wait(future, timeout):
    """Single choke point for every blocking sync-bridge wait.

    Releases this carrier's execution (E) permit before parking — so a
    nested endpoint body always finds an execution slot — waits for the
    loop-side ``future``, then re-acquires E on resume. Owns
    ``future.cancel()`` on timeout (park sites no longer carry their own
    ``except TimeoutError`` block). On a failed/shutdown re-acquire it
    leaves the carrier permit-less and POISONS it, so any further
    sync-bridge call on this thread fails fast and the chain unwinds
    rather than doing bridge work without an execution permit (which would
    let live execution drift above E).

    E accounting is balanced on every path: on success the park's
    ``release`` is undone by the ``acquire`` and _carrier's finally
    releases once; on a failed re-acquire the park's release stands,
    nobody re-takes it, and _carrier sees no permit so it skips its own
    release. No permanent permit loss either way.

    Called only from a carrier thread; if ``_held_permit.gated`` is None
    (non-carrier caller, or an already-poisoned carrier), it degrades to a
    plain bounded ``future.result``.
    """
    g = getattr(_held_permit, "gated", None)
    if g is not None:
        g.e.release()                         # vacate execution slot while parked
    try:
        return future.result(timeout)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise
    finally:
        if g is not None:
            if g.shutting_down or not g.e.acquire(timeout=REACQUIRE_GRACE):
                _held_permit.gated = None
                _held_permit.poisoned = True


class GatedExecutor(concurrent.futures.Executor):
    """Execution-gated thread pool for the sync bridge.

    Wraps a PRIVATE ``ThreadPoolExecutor`` with the two semaphores
    described above. Subclasses ``concurrent.futures.Executor`` and
    duck-types ``submit`` so existing
    ``loop.run_in_executor(gated, fn, *args)`` dispatch sites are
    unchanged. Never exposes the inner pool (failure ordering depends on
    it staying private).

    The poison signal is a ``RequestException``, which plugin code MAY
    catch and continue — so the fail-fast unwind is BEST-EFFORT and the
    real bound is honest-probabilistic: peak live execution can transiently
    exceed E by the count of simultaneously-poisoned permit-less carriers,
    itself bounded by M and self-correcting as those carriers exit. Poison
    only triggers under saturation/shutdown (rare), so the drift is small
    and transient.
    """

    def __init__(self, name, exec_permits, thread_ceiling):
        # The thread ceiling (M) can never sit below the execution budget
        # (E): a pool must be able to run E carriers concurrently, else the
        # surplus E permits are unreachable (M caps admission first). Config
        # that sets workers above the ceiling thus raises the ceiling to
        # match rather than silently wasting concurrency.
        thread_ceiling = max(int(thread_ceiling), int(exec_permits))
        self.name = name
        self._ceiling = thread_ceiling
        self._pool = ThreadPoolExecutor(
            max_workers=thread_ceiling, thread_name_prefix=name
        )
        self.e = threading.Semaphore(exec_permits)        # E
        self._m = threading.Semaphore(thread_ceiling)     # M (twin of max_workers)
        self.shutting_down = False
        # Test-only instrumentation: live carrier count + peak. Mirrors M
        # exactly (incremented on M-admission, decremented wherever M is
        # released). The Phase-4 repro reads ``peak_threads``; never poke
        # Semaphore internals. The lock is never held across a blocking
        # call, so it introduces no ordering risk.
        self._count_lock = threading.Lock()
        self._thread_count = 0
        self.peak_threads = 0

    def submit(self, fn, *a, **kw):
        if self.shutting_down:
            raise RequestException(f"sync bridge '{self.name}' is shutting down")
        # M-admission MUST be non-blocking: blocking would re-deadlock (a
        # child waiting for an M-slot its own ancestor holds). Called
        # synchronously on the loop from _call_endpoint, so a saturation
        # RequestException surfaces as the request's error and reaches the
        # parked caller via the normal error path.
        if not self._m.acquire(blocking=False):
            raise RequestException(
                f"sync bridge '{self.name}' saturated: {self._ceiling} concurrent "
                f"in-flight sync calls; likely runaway sync fan-out — prefer async."
            )
        with self._count_lock:
            self._thread_count += 1
            self.peak_threads = max(self.peak_threads, self._thread_count)
        try:
            return self._pool.submit(self._carrier, fn, *a, **kw)
        except BaseException:
            # Roll back BOTH M and the live-count if the inner pool refuses
            # the work (e.g. shutdown race): _carrier will not run, so its
            # finally cannot do the release/decrement.
            with self._count_lock:
                self._thread_count -= 1
            self._m.release()
            raise

    def _carrier(self, fn, *a, **kw):
        # Reset stale threadlocal state from a prior task on this REUSED
        # worker BEFORE acquiring E, so a finally-skip on the previous task
        # cannot make us over-release here.
        _held_permit.gated = None
        _held_permit.poisoned = False
        # The E-acquire and the body run INSIDE the try so the finally always
        # releases M (and decrements the live count) even if e.acquire()
        # itself were to raise — M was taken in submit(), so a skipped finally
        # here would leak it. `held` stays False on that path (gated never
        # armed), so E is correctly not released (it was never acquired).
        try:
            self.e.acquire()
            _held_permit.gated = self
            return fn(*a, **kw)            # endpoint body; its parks call _bridge_wait
        finally:
            held = _held_permit.gated is self
            _held_permit.gated = None
            if held:                      # only release E if we still hold it
                self.e.release()
            with self._count_lock:
                self._thread_count -= 1
            self._m.release()             # M released only here -> held full lifetime

    def shutdown(self, wait=True, cancel_futures=False):
        # Set the flag FIRST so any carrier parked in _bridge_wait skips its
        # bounded re-acquire and proceeds permit-less to unwind, rather than
        # blocking on an E-slot that will never free during teardown (which
        # would hang shutdown(wait=True)).
        self.shutting_down = True
        self._pool.shutdown(wait=wait, cancel_futures=cancel_futures)
