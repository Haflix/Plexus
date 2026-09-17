"""NetFixTarget — wave-2 cross-node service fixture for the networking rewrite.

The cooperative peer-side plugin the wave-2 socket cells call over the wire:
plain unary endpoints, large-payload echo, tag-carrying endpoints, stream
endpoints (empty / N / huge-item / mid-raise / infinite / slow), a slow handler
with a side-effect flag (handler-timeout / catatonic cells), a network-ish raiser
(nested-Network wrap), the rate-control idiom (reused from TestRemoteTarget), and
two topic handlers (request_event / publish fan-out).

remote=True so its endpoints/subs export into the rewrite directory and route
cross-node. Runtime subscriptions (in on_enable) so the subs advertise to a
puller, mirroring TestRemoteTarget.

UUID-TARGET cells (TP-52a/52b): register this plugin as TWO config.yml INSTANCES
(same source, different names/uuids) and use ``whoami`` (returns plugin_uuid) to
tell which instance answered. That is a host-config concern; the plugin is generic.
"""

import asyncio
from typing import Any

from plexus.utils import Plugin
from plexus.decorators import async_gen_log_errors, async_log_errors, log_errors
from plexus.exceptions import NetworkRequestException


class NetFixTarget(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._sub_ids: list[str] = []
        # Side-effect flags for the handler-timeout / callee-cancel cells
        # (TG-12/B-029, TP-10): a handler sets its flag only if it RUNS TO
        # COMPLETION, so a cancelled handler leaves the flag UNSET.
        self._flags: dict[str, bool] = {}
        # Ordered fan-out log (TP-04 scheduled-count receiver-side, TP-54
        # whole-value-drop: the receiver sees the WHOLE value or NOTHING).
        self._fanout_log: list = []

    @async_log_errors
    async def on_enable(self):
        for topic, target in (
            ("fix/probe", "fix_probe_handler"),
            ("fix/fanout", "fix_fanout_handler"),
            ("fix/caller", "caller_echo_handler"),
        ):
            sid = await self._plexus.subscribe_event(
                topic, self.plugin_name, self.plugin_uuid,
                target_access_name=target,
            )
            self._sub_ids.append(sid)
        # B-092: a hosts="local" sub used ONLY by the net_hostile receiver-gate
        # cell. It opts out of remote publishers, so an inbound FANOUT/FIRST
        # from a peer must be rejected by _sub_accepts_remote_publisher at the
        # RECEIVER (manager.py:638). Being hosts="local" it is
        # remote_eligible=False (manager.py:527), so the serve-time export
        # filter (directory.py:184) drops it: invisible in peers' snapshots and
        # content_hash, so it cannot affect any other cell's routing/counts.
        lsid = await self._plexus.subscribe_event(
            "fix/localonly", self.plugin_name, self.plugin_uuid,
            target_access_name="fix_probe_handler", hosts="local",
        )
        self._sub_ids.append(lsid)

    @async_log_errors
    async def on_disable(self):
        for sid in list(self._sub_ids):
            try:
                await self._plexus.unsubscribe_event(sid)
            except Exception:
                pass
        self._sub_ids = []
        self._flags = {}
        self._fanout_log = []

    # ── Plain unary endpoints ───────────────────────────────────────────
    @async_log_errors
    async def echo_unary(self, payload: Any = None) -> Any:
        """Echo the payload back (TP-01/53/55, TG-05 boundary round-trips)."""
        return payload

    @async_log_errors
    async def add(self, a: int = 0, b: int = 0) -> int:
        """Small fast call (TP-56 concurrent-small-call, TG-03 fall-through)."""
        return int(a) + int(b)

    @async_log_errors
    async def echo_bytes(self, n_bytes: int = 0, fill: int = 0xAB) -> dict:
        """Return exactly n_bytes of a fill byte (large-payload / exact-boundary
        round-trip: TP-13/55, TG-05, TG-08). Byte-exactness is the assertion."""
        n = max(0, int(n_bytes))
        return {"n": n, "data": bytes([int(fill) & 0xFF]) * n}

    @async_log_errors
    async def whoami(self) -> dict:
        """Identify the answering instance (TG-03 hostname-lex order; TP-52a/52b
        uuid-target: two instances share a name but differ by plugin_uuid)."""
        return {
            "hostname": getattr(self._plexus, "hostname", None),
            "plugin_name": self.plugin_name,
            "plugin_uuid": self.plugin_uuid,
        }

    @async_log_errors
    async def tagged_probe(self) -> dict:
        """A tag-carrying endpoint (tag in plugin_config; the host may add
        ai_tool) for find_endpoints_by_tag cross-node discovery."""
        return {"ok": True, "hostname": getattr(self._plexus, "hostname", None)}

    @async_log_errors
    async def slow_handler(self, delay: float = 5.0, key: str = "slow") -> dict:
        """Sleep, THEN set the side-effect flag. If the callee cancels this
        handler on handler_timeout expiry (TG-12) or the caller's deadline fires
        (TP-10 catatonic), the sleep is interrupted and the flag stays UNSET —
        that UNSET flag is the observable that the handler was really cancelled."""
        await asyncio.sleep(max(0.0, float(delay)))
        self._flags[key] = True
        return {"done": True, "key": key}

    @async_log_errors
    async def get_flag(self, key: str = "slow") -> bool:
        """Read a side-effect flag (UNSET == the handler was cancelled)."""
        return bool(self._flags.get(key, False))

    @async_log_errors
    async def localonly_selftest(self) -> bool:
        """B-092 existence control for the net_hostile receiver-gate cell.
        True iff the hosts="local" sub on fix/localonly is present and enabled
        in this node's local registry (the SAME topic the cell sends a remote
        request to). Lets the cell attribute a remote "no pong" to the receiver
        gate (manager.py:638) rather than to a missing/typo'd sub. Checks the
        registry directly (an execute, not a gated event) so the gate under
        test is not involved in the existence proof itself."""
        # Check topic + enabled + TARGET: "exists on the right topic" alone
        # would let a sub mis-wired to a non-answering handler pass the
        # existence control while the negative ('no pong') passes for the wrong
        # reason. Pin that it routes to fix_probe_handler — the same handler the
        # cell's fix/probe control proves answers end-to-end.
        subs = await self._plexus.topic_registry.list_local_subs()
        return any(
            getattr(s, "topic_pattern", None) == "fix/localonly"
            and getattr(s, "enabled", True)
            and getattr(s, "target_access_name", None) == "fix_probe_handler"
            for s in subs
        )

    @async_log_errors
    async def reset_flags(self) -> bool:
        self._flags = {}
        return True

    @async_log_errors
    async def relay_call(self, target_plugin: str = "", endpoint: str = "",
                         args: Any = None, hosts: Any = "any") -> Any:
        """Reverse-call helper: execute another node's endpoint FROM this node
        (bidirectional-transfer TG-08, both-directions-heal TP-09). Returns the
        callee's value so the originating driver can assert byte-exactness."""
        return await self.execute(target_plugin, endpoint, args or {}, hosts=hosts)

    @async_log_errors
    async def raise_networkish(self) -> Any:
        """Raise a NetworkRequestException from the handler (TP-17b): the rewrite
        SENDER must wrap a Network/NoLocalSub handler-raise in a NON-Network
        RequestException so it PROPAGATES rather than silently falling through to
        the next candidate (which would re-run a side-effecting handler)."""
        raise NetworkRequestException("netfix-networkish-marker")

    # ── Rate control (reused idiom from TestRemoteTarget) ────────────────
    @async_log_errors
    async def r_rl_configure(self, rate_limits: Any = None) -> dict:
        """Apply (dict) or CLEAR (None) a rate_limits config live on THIS node,
        for the cross-node throttle cells (TG-01/01b/23). Reuses the real config
        parser + rebuild; the inbound admit for THIS call ran against the still-
        empty sideband before the body, so configuring is never self-throttled."""
        from plexus.helpers.config import parse_rate_limits
        from plexus.ratelimiter import RateLimiter
        px = self._plexus
        cfg, sub_cfg, nodes_cfg = parse_rate_limits(rate_limits)
        px._rate_limiter = RateLimiter()
        px._rate_limit_config = cfg
        px._rate_limit_sub_config = sub_cfg
        px._rate_limit_nodes_in_config = nodes_cfg
        await px._rebuild_charge_sets()
        return {"active": px._rate_limits_active}

    @async_log_errors
    async def r_rl_stats(self) -> list:
        """This node's RateLimiter.stats() snapshot — exact per-bucket charge
        counts over the wire (TG-01/23 accounting)."""
        return self._plexus._rate_limiter.stats()

    # ── Stream endpoints ────────────────────────────────────────────────
    @async_gen_log_errors
    async def stream_n(self, n: int = 3):
        """Yield N items (TP-03 basic, TG-05 multi-item)."""
        for i in range(max(0, int(n))):
            yield {"i": i}

    @async_gen_log_errors
    async def stream_empty(self):
        """Yield ZERO items — a clean-close empty stream (TP-12)."""
        if False:  # pragma: no cover - forces async-generator type, yields nothing
            yield

    @async_gen_log_errors
    async def stream_huge_item(self, size_mb: int = 9):
        """Yield ONE oversized item (TG-24: a single stream item exceeding the
        per-cid 8MB reassembly bound → that cid drops, the stream fails with a
        mapped error, the LINK STAYS UP). Default 9MB > the 8MB per-cid bound."""
        n = max(1, int(size_mb)) * 1024 * 1024
        yield {"data": b"\xab" * n}

    @async_gen_log_errors
    async def stream_mid_raise(self, n: int = 3):
        """Yield N items THEN raise (TG-10 mid-stream raise: consumer gets N
        items then the mapped exc TYPE)."""
        for i in range(max(0, int(n))):
            yield {"i": i}
        raise ValueError("netfix-midstream-marker")

    @async_gen_log_errors
    async def stream_infinite(self, tick: float = 0.05):
        """Yield forever (TP-56 HoL-block guard: a concurrent small call must
        still complete while this runs)."""
        i = 0
        while True:
            yield {"i": i}
            i += 1
            await asyncio.sleep(max(0.0, float(tick)))

    @async_gen_log_errors
    async def stream_slow(self, n: int = 3, delay: float = 30.0):
        """Yield one item then stall (TG-11 remote stream idle/chunk-deadline
        timeout → surfaces as a RequestException, not raw asyncio.TimeoutError)."""
        yield {"i": 0}
        await asyncio.sleep(max(0.0, float(delay)))
        for i in range(1, max(1, int(n))):
            yield {"i": i}

    # ── Topic handlers (subscribed in on_enable) ────────────────────────
    @async_log_errors
    async def fix_probe_handler(self, event=None):
        """Answer fix/probe (request_event basic, TP-05b, TP-35 STAR)."""
        # Record the invocation so a caller can assert the handler was (not)
        # reached — a PEER-SIDE marker, unlike the net/inbound counter which the
        # caller's own readback execute also bumps (TP-05b).
        self._flags["probe_invoked"] = True
        payload = event.payload if event is not None else None
        return {"pong": True, "payload": payload}

    @async_log_errors
    async def fix_who_handler(self, event=None):
        """request_event handler identifying the answering node (fall-through
        order TG-03): returns this node's hostname + plugin_uuid."""
        return {
            "hostname": getattr(self._plexus, "hostname", None),
            "plugin_name": self.plugin_name,
            "plugin_uuid": self.plugin_uuid,
        }

    @async_log_errors
    async def caller_echo_handler(self, event=None):
        """Return the framework-RESOLVED caller identity (from the authenticated
        record cross-node), for the system-caller-spoof (TP-71) + anti-spoof
        (TP-72) Type-X cells: a hostile peer asserting author='system' must NOT be
        honored (author != 'system' for a non-system record)."""
        return {
            "author": getattr(event, "author", None),
            "author_id": getattr(event, "author_id", None),
            "author_host": getattr(event, "author_host", None),
        }

    @async_log_errors
    async def fix_fanout_handler(self, event=None):
        """Record each fan-out payload in order (TP-04 count receiver-side,
        TP-54 whole-value-drop: whole value or nothing, never partial)."""
        self._fanout_log.append(event.payload if event is not None else None)

    @async_log_errors
    async def fanout_log(self) -> list:
        """Readback of the recorded fan-out order/contents."""
        return list(self._fanout_log)

    @async_log_errors
    async def reset_fanout(self) -> bool:
        self._fanout_log = []
        return True
