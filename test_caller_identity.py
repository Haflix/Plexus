"""Unit tests for the caller-identity primitives.

Pure tests of the runtime helpers in isolation: CallerIdentity, the async
ContextVar push/isolate/establish scopes, the sync-worker seed, and the
sync-vs-async read accessor. No Plexus, no event loop except the two cases
that explicitly assert ContextVar propagation across await / create_task.

Standalone runnable: ``python test_caller_identity.py`` (exit 0 = pass).
The framework-wiring side (that _call_endpoint / lifecycle / the sync bridge
actually call these at the right sites) is covered by TestIdentitySuite.
"""
import asyncio
import sys

from plexus.runtime import (
    CallerIdentity,
    _caller_chain,
    _sync_identity_chain,
    caller_chain_scope,
    current_caller_chain,
    establish_caller_chain,
    seeded_sync_chain,
)

_failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        _failures.append(name)


def _reset():
    """Clear any leaked context between tests."""
    _caller_chain.set(())
    if getattr(_sync_identity_chain, "chain", None):
        _sync_identity_chain.chain = ()


# ── CallerIdentity ────────────────────────────────────────────────────
def test_identity_shape():
    i = CallerIdentity("Plug", "uuid-1")
    check("identity.name", i.name == "Plug")
    check("identity.uuid", i.uuid == "uuid-1")
    check("identity.exempt default False", i.exempt is False)
    e = CallerIdentity("L", "u", True)
    check("identity.exempt set", e.exempt is True)
    # NamedTuple -> tuple equality / immutability
    check("identity is tuple", tuple(i) == ("Plug", "uuid-1", False))


# ── current_caller_chain: default + sync/async source ─────────────────
def test_current_default_empty():
    _reset()
    check("current default ()", current_caller_chain() == ())


def test_current_reads_contextvar():
    _reset()
    ident = CallerIdentity("A", "ua")
    _caller_chain.set((ident,))
    check("current reads ContextVar", current_caller_chain() == (ident,))
    _reset()


def test_current_prefers_sync_threadlocal():
    # On a worker the ContextVar is invisible; a seeded threadlocal wins.
    _reset()
    cv_ident = CallerIdentity("Loop", "ul")
    tl_ident = CallerIdentity("Worker", "uw")
    _caller_chain.set((cv_ident,))
    _sync_identity_chain.chain = (tl_ident,)
    check(
        "current prefers non-empty sync threadlocal",
        current_caller_chain() == (tl_ident,),
    )
    # Empty threadlocal falls back to the ContextVar.
    _sync_identity_chain.chain = ()
    check(
        "current falls back to ContextVar when threadlocal empty",
        current_caller_chain() == (cv_ident,),
    )
    _reset()


# ── caller_chain_scope: push / pop / nest / inactive ──────────────────
def test_scope_inactive_noop():
    _reset()
    ident = CallerIdentity("A", "ua")
    with caller_chain_scope(ident, False):
        check("scope inactive does not push", current_caller_chain() == ())
    check("scope inactive after exit ()", current_caller_chain() == ())


def test_scope_push_pop():
    _reset()
    ident = CallerIdentity("A", "ua")
    with caller_chain_scope(ident, True):
        check("scope pushes ident", current_caller_chain() == (ident,))
    check("scope pops on exit", current_caller_chain() == ())


def test_scope_nesting_appends():
    _reset()
    a = CallerIdentity("A", "ua")
    b = CallerIdentity("B", "ub")
    with caller_chain_scope(a, True):
        with caller_chain_scope(b, True):
            check("nested appends outermost-first", current_caller_chain() == (a, b))
        check("inner pop restores outer", current_caller_chain() == (a,))
    check("outer pop restores ()", current_caller_chain() == ())


def test_scope_restores_on_exception():
    _reset()
    a = CallerIdentity("A", "ua")
    try:
        with caller_chain_scope(a, True):
            raise ValueError("boom")
    except ValueError:
        pass
    check("scope resets after exception", current_caller_chain() == ())


# ── seeded_sync_chain ─────────────────────────────────────────────────
def test_seed_inactive_none():
    _reset()
    a = CallerIdentity("A", "ua")
    check("seed inactive -> None", seeded_sync_chain(False, a) is None)


def test_seed_active_parent_plus_ident():
    _reset()
    parent = CallerIdentity("P", "up")
    child = CallerIdentity("C", "uc")
    _caller_chain.set((parent,))
    check(
        "seed active = parent + (ident,)",
        seeded_sync_chain(True, child) == (parent, child),
    )
    _reset()
    check(
        "seed active from empty parent = (ident,)",
        seeded_sync_chain(True, child) == (child,),
    )
    _reset()


# ── establish_caller_chain: replace / restore ─────────────────────────
def test_establish_replaces_and_restores():
    _reset()
    a = CallerIdentity("A", "ua")
    captured = (CallerIdentity("X", "ux"), CallerIdentity("Y", "uy"))
    with caller_chain_scope(a, True):
        with establish_caller_chain(captured):
            check("establish replaces whole chain", current_caller_chain() == captured)
        check("establish restores prior", current_caller_chain() == (a,))
    check("after all ()", current_caller_chain() == ())


# ── asyncio: ContextVar survives await + copies into create_task ──────
async def _async_propagation():
    _reset()
    a = CallerIdentity("A", "ua")
    with caller_chain_scope(a, True):
        await asyncio.sleep(0)
        survives = current_caller_chain() == (a,)

        # create_task copies the current context -> child sees (a,)
        async def _child():
            return current_caller_chain()

        child_seen = await asyncio.create_task(_child())
    _reset()
    return survives, child_seen, a


def test_async_propagation():
    survives, child_seen, a = asyncio.run(_async_propagation())
    check("chain survives await (same task)", survives)
    check("create_task copies chain into child", child_seen == (a,))


def main():
    tests = [
        test_identity_shape,
        test_current_default_empty,
        test_current_reads_contextvar,
        test_current_prefers_sync_threadlocal,
        test_scope_inactive_noop,
        test_scope_push_pop,
        test_scope_nesting_appends,
        test_scope_restores_on_exception,
        test_seed_inactive_none,
        test_seed_active_parent_plus_ident,
        test_establish_replaces_and_restores,
        test_async_propagation,
    ]
    for t in tests:
        print(t.__name__)
        t()
    print()
    if _failures:
        print(f"FAILED: {len(_failures)} -> {_failures}")
        sys.exit(1)
    print("ALL PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
