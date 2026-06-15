"""TestIdentitySuite — rate-limiter Step 2a (caller-identity) integration.

Proves the framework STAMPS the caller-identity chain at every
framework->plugin entry, with ``_identity_active`` forced on for the suite
(it ships off by default). Each case drives a real dispatch and reads
``current_caller_chain()`` from inside the entered handler, asserting the
entered plugin is the innermost frame -- catching a mis-wired site.

Coverage (design Section 2 / build-order 2a):
- execute push, async + sync (``_call_endpoint`` both branches)
- request_event push, async + sync handler (event branch, both)
- the sync-bridge handoff (execute_sync + request_event_sync from a sync
  handler: the originating identity must survive the run_coroutine_threadsafe
  hop -- a chain of length 2 proves it; length 1 would mean the worker seed
  was lost)
- both stream dispatchers (async-gen + sync-gen)
- ``_spawn_tracked`` isolation (a fan-out handler must NOT inherit the
  publisher's live frame)
- lifecycle exempt frame (``on_enable`` under stamping)
- zero-overhead-when-off (flag flipped off -> empty chain)

The suite SELF-TARGETS for the dispatch cases (a plugin may execute its own
endpoints) and uses TestIdentityTarget for the disable/enable lifecycle case.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import (  # noqa: E402
    async_log_errors,
    async_gen_log_errors,
    gen_log_errors,
    log_errors,
)
from plexus.runtime import current_caller_chain  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"
SELF = "TestIdentitySuite"
LIFECYCLE_TARGET = "TestIdentityTarget"


def _chain_list() -> List[list]:
    """Serialize the live caller chain to [[name, uuid, exempt], ...]."""
    return [[i.name, i.uuid, i.exempt] for i in current_caller_chain()]


class TestIdentitySuite(Plugin):

    # ── lifecycle ─────────────────────────────────────────────────────
    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestIdentitySuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestIdentitySuite disabled")

    # ── capture endpoints (entered BY the framework; read the chain) ──
    @async_log_errors
    async def capture_async(self) -> list:
        return _chain_list()

    @log_errors
    def capture_sync(self) -> list:
        return _chain_list()

    @async_gen_log_errors
    async def capture_async_stream(self):
        yield _chain_list()

    @gen_log_errors
    def capture_sync_stream(self):
        yield _chain_list()

    @async_log_errors
    async def on_capture_event(self, event) -> list:
        return _chain_list()

    @log_errors
    def on_capture_event_sync(self, event) -> list:
        return _chain_list()

    # ── relays (run AS the suite, then call back into the framework) ──
    @log_errors
    def relay_execute_sync(self) -> list:
        # Sync handler on a worker seeded with (suite,). The nested
        # execute_sync must carry that identity across the bridge so the
        # captured chain is (suite, suite) -- not (suite,).
        return self.execute_sync(SELF, "capture_async")

    @log_errors
    def relay_request_event_sync(self) -> list:
        # Same, through the events.py request_event_sync bridge.
        return self.request_event_sync("capture_req")

    @async_log_errors
    async def relay_async_request(self) -> list:
        # Runs with a LIVE (suite,) frame on the ContextVar, then fans out
        # via request_event. The fan-out task is spawned through
        # _spawn_tracked, which copies the parent context -> the handler must
        # see genuine ancestry (suite, suite). Length 2 proves the caller
        # frame propagates through the fan-out (it is NOT isolated away).
        return await self.request_event("capture_req")

    # ── suite driver ──────────────────────────────────────────────────
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
        rec = CaseRecorder("TestIdentitySuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        uuid = self.plugin_uuid
        prev = self._plexus._identity_active
        self._plexus._identity_active = True
        try:
            await self._case_execute_async(rec, kw, uuid)
            await self._case_execute_sync(rec, kw, uuid)
            await self._case_sync_bridge_execute(rec, kw, uuid)
            await self._case_event_async(rec, kw, uuid)
            await self._case_event_sync_handler(rec, kw, uuid)
            await self._case_request_event_sync_bridge(rec, kw, uuid)
            await self._case_fanout_ancestry(rec, kw, uuid)
            await self._case_stream_async(rec, kw, uuid)
            await self._case_stream_sync(rec, kw, uuid)
            await self._case_lifecycle_exempt(rec, kw)
            await self._case_inactive_zero_overhead(rec, kw)
        finally:
            self._plexus._identity_active = prev

        return rec.to_dict()

    # ── cases ─────────────────────────────────────────────────────────
    async def _case_execute_async(self, rec, kw, uuid):
        async def body(c):
            chain = await self.execute(SELF, "capture_async")
            _assert_eq(chain, [[SELF, uuid, False]], "execute async")
        await rec.run_case("identity.execute.async", body, **kw)

    async def _case_execute_sync(self, rec, kw, uuid):
        async def body(c):
            # capture_sync is a sync def -> dispatched on the plugin executor;
            # the worker threadlocal must be seeded with (suite,).
            chain = await self.execute(SELF, "capture_sync")
            _assert_eq(chain, [[SELF, uuid, False]], "execute sync (worker seed)")
        await rec.run_case("identity.execute.sync_seed", body, **kw)

    async def _case_sync_bridge_execute(self, rec, kw, uuid):
        async def body(c):
            chain = await self.execute(SELF, "relay_execute_sync")
            _assert_eq(
                chain,
                [[SELF, uuid, False], [SELF, uuid, False]],
                "sync-bridge execute_sync handoff (expected 2 frames)",
            )
        await rec.run_case("identity.bridge.execute_sync", body, **kw)

    async def _case_event_async(self, rec, kw, uuid):
        async def body(c):
            chain = await self.request_event("capture_req")
            _assert_eq(chain, [[SELF, uuid, False]], "request_event async handler")
        await rec.run_case("identity.event.async", body, **kw)

    async def _case_event_sync_handler(self, rec, kw, uuid):
        async def body(c):
            chain = await self.request_event("capture_req_sync")
            _assert_eq(
                chain, [[SELF, uuid, False]], "request_event sync handler (worker seed)"
            )
        await rec.run_case("identity.event.sync_handler", body, **kw)

    async def _case_request_event_sync_bridge(self, rec, kw, uuid):
        async def body(c):
            chain = await self.execute(SELF, "relay_request_event_sync")
            _assert_eq(
                chain,
                [[SELF, uuid, False], [SELF, uuid, False]],
                "sync-bridge request_event_sync handoff (expected 2 frames)",
            )
        await rec.run_case("identity.bridge.request_event_sync", body, **kw)

    async def _case_fanout_ancestry(self, rec, kw, uuid):
        async def body(c):
            # relay_async_request runs with a live (suite,) frame and fans out;
            # the fan-out delivery must INHERIT it -> handler sees (suite, suite).
            chain = await self.execute(SELF, "relay_async_request")
            _assert_eq(
                chain,
                [[SELF, uuid, False], [SELF, uuid, False]],
                "fan-out ancestry (delivery must inherit the publisher frame)",
            )
        await rec.run_case("identity.fanout.ancestry", body, **kw)

    async def _case_stream_async(self, rec, kw, uuid):
        async def body(c):
            chunks = []
            async for ch in self.execute_stream(SELF, "capture_async_stream"):
                chunks.append(ch)
            _assert_eq(chunks[0], [[SELF, uuid, False]], "execute_stream async-gen")
        await rec.run_case("identity.stream.async", body, **kw)

    async def _case_stream_sync(self, rec, kw, uuid):
        async def body(c):
            chunks = []
            async for ch in self.execute_stream(SELF, "capture_sync_stream"):
                chunks.append(ch)
            _assert_eq(chunks[0], [[SELF, uuid, False]], "execute_stream sync-gen (worker seed)")
        await rec.run_case("identity.stream.sync", body, **kw)

    async def _case_lifecycle_exempt(self, rec, kw):
        async def body(c):
            # Re-enable the target UNDER stamping; on_enable captures an
            # EXEMPT frame (Section 8).
            await self._plexus.disable_plugin(LIFECYCLE_TARGET)
            await self._plexus.enable_plugin(LIFECYCLE_TARGET)
            chain = await self.execute(LIFECYCLE_TARGET, "get_enable_capture")
            if not chain or len(chain) != 1:
                raise AssertionError(f"lifecycle: expected 1 frame, got {chain!r}")
            name, _uuid, exempt = chain[0]
            if name != LIFECYCLE_TARGET:
                raise AssertionError(f"lifecycle: wrong plugin {name!r}")
            if exempt is not True:
                raise AssertionError(f"lifecycle: frame not exempt: {chain!r}")
        await rec.run_case("identity.lifecycle.exempt", body, **kw)

    async def _case_inactive_zero_overhead(self, rec, kw):
        async def body(c):
            # Flip stamping OFF -> no frame pushed at all (Section 11).
            self._plexus._identity_active = False
            try:
                chain = await self.execute(SELF, "capture_async")
            finally:
                self._plexus._identity_active = True
            _assert_eq(chain, [], "identity off -> empty chain (zero overhead)")
        await rec.run_case("identity.inactive.zero_overhead", body, **kw)


def _assert_eq(actual, expected, what):
    if actual != expected:
        raise AssertionError(f"{what}: expected {expected!r}, got {actual!r}")
