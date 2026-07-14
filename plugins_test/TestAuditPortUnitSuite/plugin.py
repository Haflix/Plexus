"""TestAuditPortUnitSuite — structured ports of the 2026-06-21 audit-bug
regression guards.

These guards previously lived ONLY in the gitignored
``plugins_test/audit_2026_06/`` pytest dir, so they never ran in the
``test_application.py`` gate. Each case here constructs the internal class
under test (decorator / Plugin / EventMixin) directly, the same
``object.__new__`` + stub idiom the existing ``*UnitSuite`` plugins use, and
asserts the FIXED behavior with ``expected_status="pass"`` (the inverse polarity
of the audit ``xfail`` guards), so a regression turns the gate RED.

Categories: ``decorators`` / ``events``. (The old ``networking`` cells that drove
the retired push/advert god-class internals were removed with the netcore
rewrite; that coverage now lives in the netcore transport/dispatch self-tests
plus wave-2.)
"""

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
from plexus.events import EventMixin  # noqa: E402
from plexus.core import Plexus  # noqa: E402
from plexus.runtime import _EMIT_DEPTH, _MAX_EMIT_DEPTH  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.2.0"


# --- events stubs -----------------------------------------------------------
class _EvPublisher:
    """Publisher stand-in: request_event_stream / publish_event read these."""

    plugin_name = "PublisherPlug"
    plugin_uuid = "pub-uuid-port"
    verbose_notifier = False


class _EvSub:
    """A subscription the topic-registry match returns for BUG-018."""

    sub_uuid = "sub-uuid-port"
    declared_id = None
    plugin_name = "TargetPlug"
    plugin_uuid = "owner-uuid-port"
    target_access_name = "missing_endpoint"
    target_plugin = "TargetPlug"
    target_plugin_uuid = "target-uuid-port"


class _EvTopicRegistry:
    def __init__(self, subs):
        self._subs = subs

    async def find_all(self, _topic):
        return list(self._subs)


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

        # events
        await self._bug017_depth_drop_preserves_suppressed_count(rec, kw)
        await self._bug018_stream_pre_dispatch_raise_emits_ended(rec, kw)

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

    # ----- events (BUG-017, BUG-018) -----

    async def _bug017_depth_drop_preserves_suppressed_count(self, rec, kw):
        # BUG-017: when _internal_emit is DROPPED by the recursive-emit depth
        # guard (returns without emitting), _emit_identity_audit must PRESERVE
        # the accumulated suppressed-count and NOT advance the window -- the
        # reset is gated on the emit actually firing. Pre-seed an expired window
        # with a non-zero count, drive _EMIT_DEPTH to the max so the real guard
        # drops the emit, call the real _emit_identity_audit, and assert the
        # count + window survived. Synchronous body; ContextVar reset in finally.
        import types as _types

        async def body(c):
            plx = object.__new__(Plexus)
            plx._logger = logging.getLogger("test.audit_port.BUG017")
            plx._identity_audit_log = {}
            plx._internal_observers = {}
            import threading
            plx._observer_lock = threading.Lock()

            real = _types.SimpleNamespace(name="caller-plugin", uuid="caller-uuid")
            verdict = _types.SimpleNamespace(reason="port-test-reason")
            asserted_author = "asserted-victim"
            asserted_author_id = "asserted-victim-id"
            denied = False
            key = (real.uuid, None if denied else asserted_author, denied)

            PRESEED_LAST_EMIT = -1.0e9
            PRESEEDED = 7
            plx._identity_audit_log[key] = {
                "last_emit": PRESEED_LAST_EMIT,
                "suppressed": PRESEEDED,
            }

            audit_topic = "_core/security/identity_asserted"
            emitted = []
            plx._internal_observers[audit_topic] = [
                lambda topic, payload: emitted.append((topic, dict(payload)))
            ]

            token = _EMIT_DEPTH.set(_MAX_EMIT_DEPTH)
            try:
                plx._emit_identity_audit(
                    real, asserted_author, asserted_author_id,
                    [real], verdict, denied,
                )
            finally:
                _EMIT_DEPTH.reset(token)

            # The depth guard dropped the emit (no observer dispatch).
            c.expect(emitted, [])
            post = plx._identity_audit_log.get(key)
            assert post is not None, "per-key audit state must not vanish"
            # FIXED: count preserved, window NOT advanced (reset gated on emit).
            c.expect(post["suppressed"], PRESEEDED)
            c.expect(post["last_emit"], PRESEED_LAST_EMIT)

        await rec.run_case(
            "events.identity_audit_depth_drop_preserves_suppressed_count",
            body, tags=("events", "audit"), bug_ids=("BUG-017",),
            category="events", **kw,
        )

    async def _bug018_stream_pre_dispatch_raise_emits_ended(self, rec, kw):
        # BUG-018: on request_event_stream's local-match branch, the
        # phase="started" lifecycle emit must have a matching phase="ended" even
        # when a pre-dispatch raise (here find_endpoint returns no target) fires
        # before the stream dispatch. Otherwise an observer leaks an open stream.
        # Drive the REAL request_event_stream with a find_endpoint stub that
        # returns (None, None, None) and assert started_count == ended_count == 1.
        async def body(c):
            records = []

            em = object.__new__(EventMixin)
            em._logger = logging.getLogger("test.audit_port.BUG018")
            import threading
            em._observer_lock = threading.Lock()
            em._internal_observers = {
                "_core/event/streamed": [
                    lambda topic, payload: records.append(dict(payload))
                ]
            }
            em.hostname = "localhost"
            em._lookup_event = lambda plugin, event_id: {"enabled": True}
            em._resolve_topic_for_event = (
                lambda plugin, event_id, topic_vars, event_entry=None: (
                    "test/stream/topic", {"enabled": True}
                )
            )
            em._rl_admit_out = lambda *a, **k: None
            em.topic_registry = _EvTopicRegistry([_EvSub()])
            em._sub_owner_active = lambda s: True
            em._sub_accepts_local = lambda s: True
            em._sub_accepts_author = lambda s, author: True

            async def _find_endpoint_none(**_kwargs):
                return (None, None, None)

            em.find_endpoint = _find_endpoint_none

            agen = em.request_event_stream(_EvPublisher(), "evt018", payload={"x": 1})
            try:
                async for _chunk in agen:
                    pass
            except BaseException:
                pass  # the pre-dispatch RequestException is expected

            started = [r for r in records if r.get("phase") == "started"]
            ended = [r for r in records if r.get("phase") == "ended"]
            # FIXED: exactly one started and one matching ended (no leaked open).
            c.expect(len(started), 1)
            c.expect(len(ended), 1)

        await rec.run_case(
            "events.request_event_stream_pre_dispatch_raise_emits_ended",
            body, tags=("events", "stream"), bug_ids=("BUG-018",),
            category="events", **kw,
        )
