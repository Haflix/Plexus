"""TestRemoteTarget — Phase 5 fixture (remote=True).

Provides the subnode-side endpoints + topic handlers that TestRemoteSuite
exercises across the wire. Each runtime subscription registered in
on_enable is unsubscribed in on_disable; cleanup is symmetric so
disable→re-enable cycles do not leak.
"""

import asyncio
from typing import Any

from plexus.utils import Plugin
from plexus.decorators import async_gen_log_errors, async_log_errors, log_errors
from plexus.exceptions import RequestException


class TestRemoteTarget(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._sub_ids: list[str] = []
        # TG-12 (B-029): callee-cancellation observability flags for the slow
        # TP-16: ordered record of per-peer publish_event payloads.
        self._order_log: list = []

    @async_log_errors
    async def on_enable(self):
        self._logger.debug("TestRemoteTarget.on_enable")

        # Code-driven hang sub on test/r/hang — B-020 driver. Registered
        # at runtime via subscribe_event(target_access_name=...) so publish_event
        # dispatch goes through execute() to the r_hang_topic_handler endpoint.
        sid_hang = await self._plexus.subscribe_event(
            "test/r/hang",
            self.plugin_name,
            self.plugin_uuid,
            target_access_name="r_hang_topic_handler",
        )
        self._sub_ids.append(sid_hang)

        # Stage N (PR4): request_event coverage. Four positive-guard subs
        # backing the new TestRemoteSuite.remote.request_event[*] cases.
        for topic, target in (
            ("test/r/req_basic",        "r_request_basic_handler"),
            ("test/r/req_raise",        "r_request_raise_handler"),
            ("test/r/req_stream_basic", "r_request_stream_basic_handler"),
            ("test/r/req_stream_raise", "r_request_stream_raise_handler"),
            ("test/r/req_stream_raise_reqexc",
             "r_request_stream_raise_reqexc_handler"),
            # B-024 huge-item guard: subscribe at runtime (default hosts="any")
            # so the parent's REMOTE request_event_stream reaches it, matching
            # the other remote stream handlers above. (The config-block
            # subscriptions: entry was hosts="local"-style and not reached over
            # the wire.)
            ("test/r/huge_stream", "r_topic_huge_stream"),
            # ── Wave-1 cross-node gap coverage ─────────────────────────
            ("test/r/order", "r_order_handler"),                    # TP-16
            ("test/r/req_stream_empty",
             "r_request_stream_empty_handler"),                     # TP-12
            ("test/r/req_stream_one",
             "r_request_stream_one_handler"),                       # TP-12 control
            ("test/r/req_stream_hang",
             "r_request_stream_hang_handler"),                      # TG-11
        ):
            sid = await self._plexus.subscribe_event(
                topic,
                self.plugin_name,
                self.plugin_uuid,
                target_access_name=target,
            )
            self._sub_ids.append(sid)

    @async_log_errors
    async def on_disable(self):
        self._logger.debug("TestRemoteTarget.on_disable")
        for sid in list(self._sub_ids):
            try:
                await self._plexus.unsubscribe_event(sid)
            except Exception:
                pass
        self._sub_ids = []

    # ── Plain remote-callable endpoints ─────────────────────────────────

    @async_log_errors
    async def r_open(self, value: Any = None) -> Any:
        return value

    @async_log_errors
    async def r_rl_configure(self, rate_limits: Any = None) -> dict:
        """Step 6 control endpoint: apply a `rate_limits` config (Section-10 shape)
        or CLEAR it (None) live on THIS node. Lets TestRemoteSuite drive a real
        two-node throttle without a static config that would throttle the other
        ~30 remote cases. Reuses the real Step-4 `parse_rate_limits` (so this also
        exercises Step 4 over the wire). The inbound admit for THIS call already
        ran against the still-empty sideband before this body executes, so
        configuring is never self-throttled."""
        from plexus.helpers.config import parse_rate_limits
        from plexus.ratelimiter import RateLimiter
        px = self._plexus
        cfg, sub_cfg, nodes_cfg = parse_rate_limits(rate_limits)
        # Reset to a FRESH limiter so each configure starts with full buckets and
        # no stale-token carryover from a prior case. (_rebuild_charge_sets
        # early-returns before pruning when nothing is configured, so a
        # clear-then-reconfigure would otherwise reconfigure the OLD bucket in
        # place -- reconfigure clamps tokens, never refills up -- inheriting the
        # prior case's drained level. Same pattern as TestRateLimitSuite._apply.)
        px._rate_limiter = RateLimiter()
        px._rate_limit_config = cfg
        px._rate_limit_sub_config = sub_cfg
        px._rate_limit_nodes_in_config = nodes_cfg
        await px._rebuild_charge_sets()
        return {"active": px._rate_limits_active}

    @async_log_errors
    async def r_rl_stats(self) -> list:
        """Step 6 readback: this node's RateLimiter.stats() snapshot. Lets the
        parent count exact per-bucket charges over the wire (e.g. Framework-IN
        charged once per remote request_event -- the carve-out + once property --
        without depending on throttle timing)."""
        return self._plexus._rate_limiter.stats()

    @async_log_errors
    async def r_call_parent(
        self, parent_hostname: Any = None, target_plugin: Any = None,
        method: Any = None, n: int = 1,
    ) -> dict:
        """Step 6 reverse-call: execute `method` on `target_plugin` at the PARENT
        `n` times and return {"ok": int, "throttled": int}. Drives the per-peer
        isolation e2e where the PARENT is the receiver and this subnode is one of
        two sender peers. The subnode's sole peer is the parent, so `hosts="remote"`
        routes there (parent_hostname is kept for explicitness / multi-peer
        futures). Throttle detection catches `RateLimitException` SPECIFICALLY (a
        `RequestException` subclass that round-trips the wire) so a routing/timeout
        error is never miscounted as a throttle -- it lands in neither tally."""
        from plexus.exceptions import RateLimitException
        ok = 0
        throttled = 0
        for _ in range(max(0, int(n))):
            try:
                await self.execute(target_plugin, method, {}, hosts="remote")
                ok += 1
            except RateLimitException:
                throttled += 1
            except Exception:
                # Not a throttle (routing/timeout/etc.) -> neither tally; the
                # caller detects a wiring fault as ok+throttled < n.
                pass
        return {"ok": ok, "throttled": throttled}

    @async_gen_log_errors
    async def r_async_gen(self, n: int = 3):
        for i in range(max(0, int(n))):
            yield f"r_{i}"

    @async_gen_log_errors
    async def r_async_gen_huge_item(self, size_mb: int = 101):
        size_bytes = max(1, int(size_mb)) * 1024 * 1024
        yield {"data": b"\xab" * size_bytes}

    @async_gen_log_errors
    async def r_async_gen_raises_after(self, n_yielded: int = 5):
        for i in range(max(0, int(n_yielded))):
            yield f"r_{i}"
        raise ValueError("midstream")

    # ── Topic handlers (subscribed via on_enable) ──────────────────────

    @async_log_errors
    async def r_topic_open(self, event=None) -> Any:
        # Subscriber endpoints receive an Event object under the new API.
        payload = event.payload if event is not None else None
        return {"received": payload}

    @async_gen_log_errors
    async def r_topic_huge_stream(self, event=None):
        # B-024 driver. _handle_request_event_stream emits ONE
        # MSG_STREAM_CHUNK per yielded item with chunk_length = pickled-size + 1.
        # If chunk_length exceeds MAX_MESSAGE_SIZE (100 MB on the receiver),
        # the receiver raises NetworkRequestException and the entire stream
        # is killed. _handle_execute_stream splits;
        # _handle_request_event_stream does NOT — that's the bug.
        # 101 MB triggers the rejection.
        yield {"data": b"\xab" * (101 * 1024 * 1024)}

    @async_log_errors
    async def r_hang_topic_handler(self, event=None):
        # B-020 driver: subscribed via on_enable to test/r/hang.
        # publish_event_sync against this from a SYNC context should NOT
        # block (post-Stage-D contract: publish_event_sync is fire-and-forget).
        # Reused by Stage N's request_event timeout-honored test — the
        # handler hangs forever, so any caller that waits for a result must
        # honor its own timeout to avoid deadlocking.
        await asyncio.Event().wait()

    # ── Stage N (PR4): request_event handler endpoints ─────────────────

    @async_log_errors
    async def r_request_basic_handler(self, event=None):
        """Happy-path request_event handler. Echoes the publisher payload
        back inside an envelope so the parent test can verify the round
        trip (payload preservation + Event metadata wrapping)."""
        payload = event.payload if event is not None else None
        return {"echoed": payload}

    @async_log_errors
    async def r_request_raise_handler(self, event=None):
        """Handler that raises a ValueError with a marker string. Verifies
        that remote handler exceptions surface to the caller as
        RequestException with the original message preserved."""
        raise ValueError("requested-error-marker")

    @async_gen_log_errors
    async def r_request_stream_basic_handler(self, event=None):
        """Async-gen handler yielding 3 chunks. The first chunk reaches
        the caller wrapped in an Event (LOCKED I); subsequent chunks are
        raw."""
        for i in range(3):
            yield {"chunk": i}

    @async_gen_log_errors
    async def r_request_stream_raise_handler(self, event=None):
        """Async-gen handler yielding 2 chunks then raising a ValueError.
        Verifies mid-stream errors propagate to the caller as
        RequestException with the original message preserved."""
        yield {"chunk": 0}
        yield {"chunk": 1}
        raise ValueError("midstream-error-marker")

    @async_gen_log_errors
    async def r_request_stream_raise_reqexc_handler(self, event=None):
        """Async-gen handler yielding 2 chunks then raising a
        RequestException. Covers the `except RequestException` mid-stream
        branch of _handle_request_event_stream (which sends the exception
        raw, distinct from the `except Exception` wrap branch that
        r_request_stream_raise_handler drives via ValueError)."""
        yield {"chunk": 0}
        yield {"chunk": 1}
        raise RequestException("reqexc-midstream-marker")

    # ── Wave-1 cross-node gap coverage: endpoints + topic handlers ──────

    @async_log_errors
    async def r_huge_result(self) -> dict:
        """TP-13: a >100MB UNARY execute result (101MB). The unary return path
        sends the pickled result via _send_stream_chunk (split across
        MSG_STREAM_CHUNK frames), so the bytes must arrive byte-exact despite
        exceeding MAX_MESSAGE_SIZE (parity with execute_stream)."""
        return {"data": b"\xab" * (101 * 1024 * 1024)}

    @async_log_errors
    async def r_order_handler(self, event=None):
        """TP-16: append each event payload to an ordered log so the parent can
        verify per-peer publish ORDER was preserved (no reorder)."""
        self._order_log.append(event.payload if event is not None else None)

    @async_log_errors
    async def r_read_order(self) -> list:
        """TP-16 readback: the recorded per-peer publish order."""
        return list(self._order_log)

    @async_log_errors
    async def r_reset_order(self) -> bool:
        """TP-16: clear the order log before a fresh publish sequence."""
        self._order_log = []
        return True

    @async_gen_log_errors
    async def r_request_stream_empty_handler(self, event=None):
        """TP-12: async generator that yields ZERO items. The consumer must
        see a clean close with no items (matched subscriber, empty stream)."""
        if False:  # pragma: no cover - forces async-generator type; yields nothing
            yield

    @async_gen_log_errors
    async def r_request_stream_one_handler(self, event=None):
        """TP-12 control: a 1-item stream, so the empty-vs-one distinction is
        observable."""
        yield {"chunk": 0}

    @async_gen_log_errors
    async def r_request_stream_hang_handler(self, event=None):
        """TG-11 (B-045): yield ONE chunk then hang forever, so the caller's
        stream idle/chunk-deadline TIMEOUT fires waiting for the 2nd chunk.
        The surfaced error must be a RequestException, not a raw
        asyncio.TimeoutError."""
        yield {"chunk": 0}
        await asyncio.Event().wait()
