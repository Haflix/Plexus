"""TestIdentityUnitSuite — pure-function unit tests for the caller-identity primitives.

Ported from the root-level ``test_caller_identity.py``. Self-contained:
imports CallerIdentity, _caller_chain, _sync_identity_chain, caller_chain_scope,
current_caller_chain, establish_caller_chain, seeded_sync_chain and exercises
them with synthetic identities. No Plexus boot needed. Two cases (propagation)
assert ContextVar semantics across await / asyncio.create_task — those bodies
are genuinely async.

Categories: ``shape`` (CallerIdentity struct), ``read`` (current_caller_chain),
``scope`` (caller_chain_scope / establish_caller_chain), ``seed``
(seeded_sync_chain), ``propagation`` (ContextVar across await / create_task).
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.runtime import (  # noqa: E402
    CallerIdentity,
    _caller_chain,
    _sync_identity_chain,
    caller_chain_scope,
    current_caller_chain,
    establish_caller_chain,
    seeded_sync_chain,
)

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


def _reset():
    """Clear any leaked context between tests."""
    _caller_chain.set(())
    if getattr(_sync_identity_chain, "chain", None):
        _sync_identity_chain.chain = ()


class TestIdentityUnitSuite(Plugin):
    """Pure-function unit suite for the caller-identity primitives."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestIdentityUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestIdentityUnitSuite disabled")

    @async_log_errors
    async def run(
        self,
        category: Optional[str] = None,
        host: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        bug_ids: Optional[List[str]] = None,
        skip_slow: bool = False,
        allow_destructive: bool = True,
    ) -> Dict[str, Any]:
        rec = CaseRecorder("TestIdentityUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        # shape cases
        await self._identity_shape(rec, kw)
        # read cases
        await self._current_default_empty(rec, kw)
        await self._current_reads_contextvar(rec, kw)
        await self._current_prefers_sync_threadlocal(rec, kw)
        # scope cases
        await self._scope_inactive_noop(rec, kw)
        await self._scope_push_pop(rec, kw)
        await self._scope_nesting_appends(rec, kw)
        await self._scope_restores_on_exception(rec, kw)
        await self._establish_replaces_and_restores(rec, kw)
        # seed cases
        await self._seed_inactive_none(rec, kw)
        await self._seed_active_parent_plus_ident(rec, kw)
        # propagation cases
        await self._async_propagation(rec, kw)

        return rec.to_dict()

    # ---------------- shape cases ----------------

    async def _identity_shape(self, rec, kw):
        async def body(c):
            i = CallerIdentity("Plug", "uuid-1")
            assert i.name == "Plug", "identity.name"
            assert i.uuid == "uuid-1", "identity.uuid"
            assert i.exempt is False, "identity.exempt default False"
            e = CallerIdentity("L", "u", True)
            assert e.exempt is True, "identity.exempt set"
            # NamedTuple -> tuple equality / immutability
            assert tuple(i) == ("Plug", "uuid-1", False), "identity is tuple"

        await rec.run_case(
            "identity.shape", body,
            tags=("identity", "shape"), category="shape", **kw
        )

    # ---------------- read cases ----------------

    async def _current_default_empty(self, rec, kw):
        async def body(c):
            _reset()
            assert current_caller_chain() == (), "current default ()"

        await rec.run_case(
            "identity.current_default_empty", body,
            tags=("identity", "read"), category="read", **kw
        )

    async def _current_reads_contextvar(self, rec, kw):
        async def body(c):
            _reset()
            ident = CallerIdentity("A", "ua")
            _caller_chain.set((ident,))
            assert current_caller_chain() == (ident,), "current reads ContextVar"
            _reset()

        await rec.run_case(
            "identity.current_reads_contextvar", body,
            tags=("identity", "read"), category="read", **kw
        )

    async def _current_prefers_sync_threadlocal(self, rec, kw):
        async def body(c):
            # On a worker the ContextVar is invisible; a seeded threadlocal wins.
            _reset()
            cv_ident = CallerIdentity("Loop", "ul")
            tl_ident = CallerIdentity("Worker", "uw")
            _caller_chain.set((cv_ident,))
            _sync_identity_chain.chain = (tl_ident,)
            assert current_caller_chain() == (tl_ident,), \
                "current prefers non-empty sync threadlocal"
            # Empty threadlocal falls back to the ContextVar.
            _sync_identity_chain.chain = ()
            assert current_caller_chain() == (cv_ident,), \
                "current falls back to ContextVar when threadlocal empty"
            _reset()

        await rec.run_case(
            "identity.current_prefers_sync_threadlocal", body,
            tags=("identity", "read"), category="read", **kw
        )

    # ---------------- scope cases ----------------

    async def _scope_inactive_noop(self, rec, kw):
        async def body(c):
            _reset()
            ident = CallerIdentity("A", "ua")
            with caller_chain_scope(ident, False):
                assert current_caller_chain() == (), "scope inactive does not push"
            assert current_caller_chain() == (), "scope inactive after exit ()"

        await rec.run_case(
            "identity.scope_inactive_noop", body,
            tags=("identity", "scope"), category="scope", **kw
        )

    async def _scope_push_pop(self, rec, kw):
        async def body(c):
            _reset()
            ident = CallerIdentity("A", "ua")
            with caller_chain_scope(ident, True):
                assert current_caller_chain() == (ident,), "scope pushes ident"
            assert current_caller_chain() == (), "scope pops on exit"

        await rec.run_case(
            "identity.scope_push_pop", body,
            tags=("identity", "scope"), category="scope", **kw
        )

    async def _scope_nesting_appends(self, rec, kw):
        async def body(c):
            _reset()
            a = CallerIdentity("A", "ua")
            b = CallerIdentity("B", "ub")
            with caller_chain_scope(a, True):
                with caller_chain_scope(b, True):
                    assert current_caller_chain() == (a, b), \
                        "nested appends outermost-first"
                assert current_caller_chain() == (a,), "inner pop restores outer"
            assert current_caller_chain() == (), "outer pop restores ()"

        await rec.run_case(
            "identity.scope_nesting_appends", body,
            tags=("identity", "scope"), category="scope", **kw
        )

    async def _scope_restores_on_exception(self, rec, kw):
        async def body(c):
            _reset()
            a = CallerIdentity("A", "ua")
            try:
                with caller_chain_scope(a, True):
                    raise ValueError("boom")
            except ValueError:
                pass
            assert current_caller_chain() == (), "scope resets after exception"

        await rec.run_case(
            "identity.scope_restores_on_exception", body,
            tags=("identity", "scope"), category="scope", **kw
        )

    async def _establish_replaces_and_restores(self, rec, kw):
        async def body(c):
            _reset()
            a = CallerIdentity("A", "ua")
            captured = (CallerIdentity("X", "ux"), CallerIdentity("Y", "uy"))
            with caller_chain_scope(a, True):
                with establish_caller_chain(captured):
                    assert current_caller_chain() == captured, \
                        "establish replaces whole chain"
                assert current_caller_chain() == (a,), "establish restores prior"
            assert current_caller_chain() == (), "after all ()"

        await rec.run_case(
            "identity.establish_replaces_and_restores", body,
            tags=("identity", "scope", "establish"), category="scope", **kw
        )

    # ---------------- seed cases ----------------

    async def _seed_inactive_none(self, rec, kw):
        async def body(c):
            _reset()
            a = CallerIdentity("A", "ua")
            assert seeded_sync_chain(False, a) is None, "seed inactive -> None"

        await rec.run_case(
            "identity.seed_inactive_none", body,
            tags=("identity", "seed"), category="seed", **kw
        )

    async def _seed_active_parent_plus_ident(self, rec, kw):
        async def body(c):
            _reset()
            parent = CallerIdentity("P", "up")
            child = CallerIdentity("C", "uc")
            _caller_chain.set((parent,))
            assert seeded_sync_chain(True, child) == (parent, child), \
                "seed active = parent + (ident,)"
            _reset()
            assert seeded_sync_chain(True, child) == (child,), \
                "seed active from empty parent = (ident,)"
            _reset()

        await rec.run_case(
            "identity.seed_active_parent_plus_ident", body,
            tags=("identity", "seed"), category="seed", **kw
        )

    # ---------------- propagation cases ----------------

    async def _async_propagation(self, rec, kw):
        async def body(c):
            # ContextVar survives await + copies into create_task.
            # body() is already a coroutine running inside the event loop, so we
            # inline the async logic directly (no asyncio.run() needed here).
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
            assert survives, "chain survives await (same task)"
            assert child_seen == (a,), "create_task copies chain into child"

        await rec.run_case(
            "identity.async_propagation", body,
            tags=("identity", "propagation", "contextvar"), category="propagation", **kw
        )
