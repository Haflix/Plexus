"""TestAuditPortUnitSuite — structured ports of the 2026-06-21 audit-bug
regression guards.

These guards previously lived ONLY in the gitignored
``plugins_test/audit_2026_06/`` pytest dir, so they never ran in the
``test_application.py`` gate. Each case here constructs the internal class
under test (decorator / Plugin / NetworkManager / EventMixin) directly — the
same ``object.__new__`` + stub idiom the existing ``*UnitSuite`` plugins use —
and asserts the FIXED behavior with ``expected_status="pass"`` (the inverse
polarity of the audit ``xfail`` guards), so a regression turns the gate RED.

Categories: ``decorators`` / ``networking`` / ``events``.
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import (  # noqa: E402
    async_log_errors,
    log_errors,
    async_gen_log_errors,
    async_gen_handle_errors,
)
from plexus.exceptions import RequestException  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


class _ConcretePlugin(Plugin):
    """Throwaway concrete Plugin subclass for the BUG-043 call-time-guard
    case. Plugin is abstract; this provides no-op lifecycle methods so
    ``object.__new__`` yields a usable instance without tripping the ABC
    instantiation guard."""

    def on_load(self, *args, **kwargs):
        pass

    async def on_enable(self):
        pass

    async def on_disable(self):
        pass


class _StubPlexusNoLoop:
    """Stands in for ``Plugin._plexus``. ``_check_framework_started`` reads
    only ``main_event_loop`` (None => framework not started yet)."""

    main_event_loop = None


class TestAuditPortUnitSuite(Plugin):
    """Structured ports of the audit-bug regression guards."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestAuditPortUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestAuditPortUnitSuite disabled")

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
        rec = CaseRecorder("TestAuditPortUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        # decorators
        await self._bug038_log_errors_closes_inner(rec, kw)
        await self._bug038_handle_errors_closes_inner(rec, kw)
        await self._bug043_call_time_guard(rec, kw)

        return rec.to_dict()

    # ----- decorators (BUG-038, BUG-043) -----

    async def _bug038_log_errors_closes_inner(self, rec, kw):
        # BUG-038: async_gen_log_errors drives the inner gen with a bare
        # ``async for ... yield`` and (before the fix) NO ``finally: await
        # async_gen.aclose()``. A consumer ``.aclose()`` on the wrapper
        # injected GeneratorExit at the wrapper's yield, bypassed
        # ``except Exception``, and propagated out WITHOUT closing the inner
        # gen, so its resource-release ``finally`` was deferred to GC. The
        # fix closes the inner gen synchronously with the wrapper aclose.
        # (aclose() is a synchronous-completion guarantee on CPython, so
        # this is deterministic — no GC timing involved.)
        async def body(c):
            state = {"inner_finally_ran": False}

            @async_gen_log_errors()
            async def streaming_endpoint():
                try:
                    for i in range(2):
                        yield i
                finally:
                    state["inner_finally_ran"] = True

            wrapper = streaming_endpoint()
            first = await wrapper.__anext__()
            c.expect(first, 0)
            # Inner finally must NOT have run yet (still suspended at yield).
            c.expect(state["inner_finally_ran"], False)
            await wrapper.aclose()
            # FIXED: inner finally ran synchronously with the wrapper aclose.
            assert state["inner_finally_ran"] is True, (
                "inner generator finally must run at wrapper aclose, not GC"
            )

        await rec.run_case(
            "decorators.async_gen_log_errors_closes_inner_on_aclose",
            body,
            tags=("decorators", "stream"),
            bug_ids=("BUG-038",),
            category="decorators",
            **kw,
        )

    async def _bug038_handle_errors_closes_inner(self, rec, kw):
        # BUG-038 sibling: async_gen_handle_errors has the structurally
        # identical missing-finally; same fix, same assertion.
        async def body(c):
            state = {"inner_finally_ran": False}

            @async_gen_handle_errors()
            async def streaming_endpoint():
                try:
                    for i in range(2):
                        yield i
                finally:
                    state["inner_finally_ran"] = True

            wrapper = streaming_endpoint()
            first = await wrapper.__anext__()
            c.expect(first, 0)
            c.expect(state["inner_finally_ran"], False)
            await wrapper.aclose()
            assert state["inner_finally_ran"] is True, (
                "inner generator finally must run at wrapper aclose, not GC"
            )

        await rec.run_case(
            "decorators.async_gen_handle_errors_closes_inner_on_aclose",
            body,
            tags=("decorators", "stream"),
            bug_ids=("BUG-038",),
            category="decorators",
            **kw,
        )

    async def _bug043_call_time_guard(self, rec, kw):
        # BUG-043: Plugin.request_event_stream was an async generator, so the
        # pre-start guard (``_check_framework_started``) did not fire until the
        # first ``__anext__`` instead of at call time (contradicting its own
        # comment + the sync sibling). The fix splits it into a plain method
        # that runs the guard at CALL time and returns the async-gen inner. So
        # with ``main_event_loop is None`` the bare CALL must raise
        # RequestException (not return a deferred async-gen).
        async def body(c):
            plugin = object.__new__(_ConcretePlugin)
            plugin._plexus = _StubPlexusNoLoop()
            plugin._logger = logging.getLogger("test.audit_port.BUG043")
            c.expect_exception(RequestException)
            # No await: the guard must raise synchronously at call time.
            plugin.request_event_stream("some-event")

        await rec.run_case(
            "utils.request_event_stream_pre_start_guard_call_time",
            body,
            tags=("utils", "stream"),
            bug_ids=("BUG-043",),
            category="decorators",
            **kw,
        )
