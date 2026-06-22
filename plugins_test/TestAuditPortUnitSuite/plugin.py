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
from plexus.networking import NetworkManager, MSG_RESULT  # noqa: E402
from plexus.events import EventMixin  # noqa: E402
from plexus.core import Plexus  # noqa: E402
from plexus.networking_classes import Node  # noqa: E402
from plexus.runtime import _EMIT_DEPTH, _MAX_EMIT_DEPTH  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


# --- networking stub stream objects (object-identity tracking only) ---------
class _NetReader:
    """Minimal asyncio.StreamReader stand-in."""


class _PoolWriter:
    """Pooled-connection writer stand-in for the _get_connection cases. Carries
    the ``_aio_pool_generation`` the pull-side stale check reads; ``drain`` is a
    no-op (healthy)."""

    def __init__(self, generation: int = 0) -> None:
        self.closed = False
        self._aio_pool_generation = generation

    def write(self, _data):
        return None

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None

    def get_extra_info(self, *_a, **_k):
        return None


class _DrainTimeoutWriter:
    """Writer whose ``drain`` raises TimeoutError, to drive the
    _handle_execute_stream per-item drain-timeout early-return (BUG-007)."""

    def __init__(self) -> None:
        self.closed = False

    def write(self, _data):
        return None

    async def drain(self):
        raise asyncio.TimeoutError("simulated stuck-peer drain timeout")

    def close(self):
        self.closed = True

    def get_extra_info(self, *_a, **_k):
        return None


class _RecordingWriter:
    """Writer that records close()/write() for the BUG-030 cases."""

    def __init__(self) -> None:
        self.closed = False
        self.write_calls = 0

    def write(self, _data):
        self.write_calls += 1

    def close(self):
        self.closed = True

    async def drain(self):
        return None

    def get_extra_info(self, _name=None, default=None):
        return default


class _FakePlexusStream:
    """self.plexus stand-in for BUG-007: admit + execute_stream returning a
    tracked source async generator."""

    def __init__(self, source_agen_factory):
        self._factory = source_agen_factory
        self.last_agen = None

    def _rl_admit_inbound(self, _peer, _flag, _now=None):
        return None  # admitted

    def execute_stream(self, **_kwargs):
        self.last_agen = self._factory()
        return self.last_agen


class _FakePlexusRaisingTimeout:
    """self.plexus stand-in for BUG-030: execute()/execute_stream simulate a
    plugin ENDPOINT that raises a plain builtins.TimeoutError (NOT a drain
    timeout, yet the aliased type on 3.11+)."""

    def _rl_admit_inbound(self, _peer, _flag, _now=None):
        return None  # admitted

    async def execute(self, *_a, **_k):
        raise TimeoutError("handler endpoint timed out talking to upstream")

    def execute_stream(self, *_a, **_k):
        async def _agen():
            raise TimeoutError("stream handler endpoint timed out")
            yield  # pragma: no cover - makes this an async generator

        return _agen()


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


class _Pub019:
    """Publisher for BUG-019: hosts='remote' so the local fan-out is skipped
    and only the remote-dispatch block runs."""

    plugin_name = "pub-plugin"
    plugin_uuid = "pub-uuid"
    verbose_notifier = False
    events = {
        "evt": {"enabled": True, "topic": "demo/topic", "hosts": "remote"},
    }


class _StubNM019:
    """network stand-in for BUG-019: provides the per-peer dispatch dict, the
    in-lock recheck lock, nodes, and a publish_event_remote spy that records
    every ACTUALLY-scheduled fan-out."""

    def __init__(self, per_peer_dict, nodes):
        self.is_ready = True
        self._per_peer = per_peer_dict
        self.nodes = nodes
        self._adverts_struct_lock = asyncio.Lock()
        self._inflight_publishes = {}
        self.scheduled_calls = []

    async def _build_remote_dispatch(self, **_kwargs):
        return self._per_peer

    async def publish_event_remote(self, ip, *_a, **_k):
        self.scheduled_calls.append(ip)
        return None


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

        # networking
        await self._bug007_handle_execute_stream_closes_source(rec, kw)
        await self._bug024_pooled_writer_tracked_before_healthcheck(rec, kw)
        await self._bug025_drains_all_stale_in_one_call(rec, kw)
        await self._bug030_handle_execute_routes_handler_timeout(rec, kw)
        await self._bug030_handle_execute_stream_routes_handler_timeout(rec, kw)

        # events
        await self._bug017_depth_drop_preserves_suppressed_count(rec, kw)
        await self._bug018_stream_pre_dispatch_raise_emits_ended(rec, kw)
        await self._bug019_disabled_peer_not_overcounted(rec, kw)

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

    # ----- networking (BUG-007, BUG-024, BUG-025, BUG-030) -----

    async def _bug007_handle_execute_stream_closes_source(self, rec, kw):
        # BUG-007: _handle_execute_stream wraps its source-agen consumption in
        # try/finally: await agen.aclose(), so an early exit (here a per-item
        # drain TimeoutError -> writer.close(); return) closes the SOURCE
        # generator within the call -- its finally runs deterministically,
        # not deferred to GC.
        async def body(c):
            cleanup_ran = {"value": False}

            async def _source():
                try:
                    yield "item-0"
                    yield "item-1"  # never reached -> proves mid-stream exit
                finally:
                    cleanup_ran["value"] = True

            nm = object.__new__(NetworkManager)
            nm._logger = logging.getLogger("test.audit_port.BUG007")
            nm.plexus = _FakePlexusStream(_source)
            nm._self_impersonation_check = lambda a, w, l: False

            async def _b018b(author, author_id, ctx, writer, label):
                return author, author_id, False

            nm._apply_b018b_guard = _b018b
            nm._count_sent = lambda w, n: None

            async def _noop_end(writer):
                return None

            nm._send_end_stream = _noop_end

            writer = _DrainTimeoutWriter()
            data = {
                "plugin": "P", "method": "stream_it", "plugin_uuid": "u",
                "author": "remote", "author_id": "remote", "timeout": None,
                "author_host": None, "request_id": "r", "args": [],
            }
            await nm._handle_execute_stream(
                reader=None, writer=writer, data=data,
                conn_context={"peer_hostname": "stub-peer"},
            )
            # Sanity: took the drain-timeout early-return (writer closed).
            c.expect(writer.closed, True)
            # FIXED: source generator's finally ran within the call.
            assert cleanup_ran["value"] is True, (
                "source async generator must be aclose()d on early return, "
                "not left for GC"
            )

        await rec.run_case(
            "networking.handle_execute_stream_closes_source_on_early_return",
            body, tags=("networking", "stream"), bug_ids=("BUG-007",),
            category="networking", **kw,
        )

    async def _bug024_pooled_writer_tracked_before_healthcheck(self, rec, kw):
        # BUG-024: _get_connection adds a pooled writer to _checked_out_writers
        # IMMEDIATELY after pool.get() (before the async health check), so a
        # concurrent stop() drain can see+close it. We drive the REAL
        # _get_connection, park it inside the stubbed health check via an
        # asyncio.Event, and assert the writer is tracked DURING the check (the
        # buggy code only added it on the healthy return). Deterministic; the
        # real stop() drain logic is intentionally NOT reproduced here.
        async def body(c):
            IP = "10.0.0.7"
            key = (IP, 9999)
            nm = object.__new__(NetworkManager)
            nm._logger = logging.getLogger("test.audit_port.BUG024")
            nm.pool_size = 4
            nm.connection_pools = {}
            nm._checked_out_writers = set()
            nm._pool_generation = {key: 0}
            nm.peers_by_endpoint = {}
            nm._stopping = False
            nm._pool_key = lambda ip: key

            reader = _NetReader()
            writer = _PoolWriter(generation=0)  # matches current gen -> healthy
            nm.connection_pools[key] = asyncio.Queue(maxsize=nm.pool_size)
            nm.connection_pools[key].put_nowait((reader, writer))

            in_healthcheck = asyncio.Event()
            release = asyncio.Event()

            async def _send_message(_w, _mt, _d):
                in_healthcheck.set()
                await release.wait()

            async def _receive_message(_r):
                return (MSG_RESULT, {})

            nm._send_message = _send_message
            nm._receive_message = _receive_message

            task = asyncio.create_task(nm._get_connection(IP))
            try:
                await asyncio.wait_for(in_healthcheck.wait(), timeout=5.0)
                # FIXED: writer tracked before the health check completes.
                tracked_during = writer in nm._checked_out_writers
                release.set()
                _rd, wr = await asyncio.wait_for(task, timeout=5.0)
            finally:
                release.set()  # never let the task hang the suite
                if not task.done():
                    # Defensive: if setup ever failed before the happy path
                    # awaited the task, cancel it rather than orphan it.
                    task.cancel()
                    try:
                        await task
                    except BaseException:
                        pass

            c.expect(wr is writer, True)
            assert tracked_during is True, (
                "pooled writer must be in _checked_out_writers DURING the "
                "health check (tracked immediately after pool.get())"
            )

        await rec.run_case(
            "networking.get_connection_tracks_pooled_writer_before_healthcheck",
            body, tags=("networking", "pool"), bug_ids=("BUG-024",),
            category="networking", **kw,
        )

    async def _bug025_drains_all_stale_in_one_call(self, rec, kw):
        # BUG-025: _get_connection loops over pooled connections, draining ALL
        # stale-generation writers in ONE call (pool empty after) instead of
        # one-per-call. Seed 3 stale writers (generation != current), call once,
        # assert the pool is fully drained and a fresh connection is returned.
        async def body(c):
            IP = "10.0.0.8"
            key = (IP, 9999)
            nm = object.__new__(NetworkManager)
            nm._logger = logging.getLogger("test.audit_port.BUG025")
            nm.pool_size = 5
            nm.connection_pools = {}
            nm._checked_out_writers = set()
            nm._pool_generation = {key: 5}  # current generation
            nm.peers_by_endpoint = {}
            nm._stopping = False
            nm._pool_key = lambda ip: key

            pool = asyncio.Queue(maxsize=nm.pool_size)
            stale_writers = [_PoolWriter(generation=0) for _ in range(3)]
            for w in stale_writers:
                pool.put_nowait((_NetReader(), w))
            nm.connection_pools[key] = pool

            fresh_reader, fresh_writer = _NetReader(), _PoolWriter(generation=5)

            async def _create_connection(_ip):
                return (fresh_reader, fresh_writer)

            nm._create_connection = _create_connection

            _rd, wr = await nm._get_connection(IP)
            # All 3 stale writers drained in ONE call -> pool empty.
            c.expect(pool.empty(), True)
            c.expect(all(w.closed for w in stale_writers), True)
            c.expect(wr is fresh_writer, True)

        await rec.run_case(
            "networking.get_connection_drains_all_stale_in_one_call",
            body, tags=("networking", "pool"), bug_ids=("BUG-025",),
            category="networking", **kw,
        )

    async def _bug030_handle_execute_routes_handler_timeout(self, rec, kw):
        # BUG-030: a handler-raised plain TimeoutError must route to the
        # error-frame path (_send_error_pickled), not be misclassified as a
        # drain timeout and suppressed. The _DrainTimeout marker distinguishes
        # the two (on 3.11+ asyncio.TimeoutError IS builtins.TimeoutError).
        async def body(c):
            nm = object.__new__(NetworkManager)
            nm._logger = logging.getLogger("test.audit_port.BUG030e")
            nm.plexus = _FakePlexusRaisingTimeout()
            nm._self_impersonation_check = lambda a, w, l: False

            async def _b018b(author, author_id, ctx, writer, label):
                return author, author_id, False

            nm._apply_b018b_guard = _b018b
            sent = []

            async def _spy_send_error_pickled(_w, exc):
                sent.append(exc)

            nm._send_error_pickled = _spy_send_error_pickled

            writer = _RecordingWriter()
            data = {
                "plugin": "P", "method": "ep", "author": "remote",
                "author_id": "remote", "author_host": None, "request_id": "r",
                "args": [], "timeout": None,
            }
            await nm._handle_execute(None, writer, data, conn_context={})
            # FIXED: the handler TimeoutError round-trips via the error frame.
            assert len(sent) >= 1, (
                "handler-raised TimeoutError must route to _send_error_pickled, "
                "not be suppressed as a drain timeout"
            )

        await rec.run_case(
            "networking.handle_execute_routes_handler_timeout_to_error_frame",
            body, tags=("networking", "timeout"), bug_ids=("BUG-030",),
            category="networking", **kw,
        )

    async def _bug030_handle_execute_stream_routes_handler_timeout(self, rec, kw):
        # BUG-030 (stream): a streaming handler whose generator raises a plain
        # TimeoutError must emit the __STREAM_EXCEPTION__ frame (via
        # _send_stream_chunk), not be misclassified as a drain timeout.
        async def body(c):
            nm = object.__new__(NetworkManager)
            nm._logger = logging.getLogger("test.audit_port.BUG030s")
            nm.plexus = _FakePlexusRaisingTimeout()
            nm._self_impersonation_check = lambda a, w, l: False

            async def _b018b(author, author_id, ctx, writer, label):
                return author, author_id, False

            nm._apply_b018b_guard = _b018b
            nm._count_sent = lambda w, n: None
            chunks = []

            async def _spy_send_stream_chunk(_w, obj):
                chunks.append(obj)

            async def _noop_end(_w):
                return None

            nm._send_stream_chunk = _spy_send_stream_chunk
            nm._send_end_stream = _noop_end

            writer = _RecordingWriter()
            data = {
                "plugin": "P", "method": "ep", "plugin_uuid": "u",
                "author": "remote", "author_id": "remote", "author_host": None,
                "request_id": "r", "args": [], "timeout": None,
            }
            await nm._handle_execute_stream(None, writer, data, conn_context={})
            # FIXED: the handler TimeoutError surfaces as a stream-exception frame.
            assert len(chunks) >= 1, (
                "streaming handler TimeoutError must emit __STREAM_EXCEPTION__ "
                "via _send_stream_chunk, not be suppressed"
            )

        await rec.run_case(
            "networking.handle_execute_stream_routes_handler_timeout",
            body, tags=("networking", "timeout", "stream"),
            bug_ids=("BUG-030",), category="networking", **kw,
        )

    # ----- events (BUG-017, BUG-018, BUG-019) -----

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

    async def _bug019_disabled_peer_not_overcounted(self, rec, kw):
        # BUG-019: publish_event's returned count must equal the fan-out it
        # actually SCHEDULED, not the pre-loop per-peer snapshot. A peer present
        # in _build_remote_dispatch but disabled by the in-lock recheck must NOT
        # be counted. Two peers survive the build; one is disabled, so only one
        # publish_event_remote schedules and the returned count must be 1.
        async def body(c):
            per_peer = {"peer-keep": [object()], "peer-drop": [object()]}
            nodes = [
                Node(IP="10.0.0.2", hostname="peer-keep",
                     enabled=True, auto_discoverable=False),
                Node(IP="10.0.0.3", hostname="peer-drop",
                     enabled=False, auto_discoverable=False),
            ]

            es = object.__new__(EventMixin)
            es._logger = logging.getLogger("test.audit_port.BUG019")
            es.hostname = "port-own-host"
            es.networking_enabled = True
            es.network = _StubNM019(per_peer, nodes)
            es._rl_admit_out = lambda *a, **k: None
            es._emitted = []
            es._internal_emit = (
                lambda topic, /, **payload: es._emitted.append((topic, payload))
            )

            spawned = []

            def _spawn_tracked(coro, name=None):
                t = asyncio.ensure_future(coro)
                spawned.append(t)
                return t

            es._spawn_tracked = _spawn_tracked
            es._spawn_fire_and_forget = lambda coro, name=None: asyncio.ensure_future(coro)

            returned = await es.publish_event(_Pub019(), "evt", payload={"x": 1})
            # Drain the scheduled fan-out deterministically (no sleep reliance).
            if spawned:
                await asyncio.gather(*spawned, return_exceptions=True)

            nm = es.network
            # Only the enabled peer was dispatched (the disabled one skipped).
            c.expect(nm.scheduled_calls, ["10.0.0.2"])
            # FIXED: returned count matches the actually-scheduled fan-out.
            c.expect(returned, len(nm.scheduled_calls))

        await rec.run_case(
            "events.publish_event_count_excludes_disabled_peer",
            body, tags=("events", "remote"), bug_ids=("BUG-019",),
            category="events", **kw,
        )
