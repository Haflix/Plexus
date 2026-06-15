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
from contextvars import ContextVar

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

# Per-pool thread ceilings (M). Runaway-prevention backstops a personal
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
