"""MultinodeDriver — the in-node cell driver for the multinode cooperative socket suite.

Runs on the driver node (w2a-driver). Reads MULTINODE_GROUP (pair / trio) or MULTINODE_CELL
(a single lifecycle cell), drives the multinode cooperative cells via the four
primitives + the NetObsProbe / NetCtl fixtures, records each with CaseRecorder, and
writes the result dict to MULTINODE_RESULT_FILE for the pytest orchestrator to assert
(``failed==0 and errored==0``). Lifecycle cells that need the parent to kill/respawn
a peer use a phase file (PairProbe S4 idiom): the driver signals a phase, the pytest
acts, the driver continues.

Every cell asserts ONLY the §A public surface (primitives + snapshot() + _core/*
events via NetObsProbe + the rate seam via r_rl_stats). Per-cell drive/assert follows
WAVE2_TEST_MAP §3. Ambiguity dispositions applied: A4 StallListener (pytest-side),
A6/A8 presence-only event asserts, A7 receiver all-or-nothing, A10 error-cid-keep-link.
Race cells needing a stall/poison injector (TP-38/46/48/49/51) + backward-clock
(TP-33/TG-18) are NOT here — they are batch-2 / §F per the map.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.exceptions import (  # noqa: E402
    RequestException, NetworkRequestException, NoLocalSubException,
    RateLimitException, CapabilityException,
)
from _test_helpers import CaseRecorder  # noqa: E402

SUITE_VERSION = "0.3.0"  # aligned to plugin_config.yml (was drifted at 0.1.0)

FIX = "NetFixTarget"
OBS = "NetObsProbe"
CTL = "NetCtl"

_LINK_TIMEOUT = 30.0
_HEARTBEAT_GUESS = 1.5  # tests set a fast heartbeat via net-knobs; used for waits

# TG-01 and TG-23 need to OBSERVE a throttled peer over the wire (r_rl_stats) after
# forcing a framework_in rejection. But r_rl_stats is itself a normal cross-node
# execute, so the RECEIVER charges framework_in on it just like the app calls under
# test, and the framework has NO author/identity exemption for framework_in (only
# lifecycle-origin frames skip the charge, core.py:6254). To force the rejection the
# cell must first DRAIN the peer's framework_in to empty (max=0 is not even a legal
# config — the limiter requires max>0), and once drained, the r_rl_stats read is
# itself rejected in that same drained region. No peer-LOCAL observe path exists.
#
# HONEST coverage note: skipping these DOES drop unique multinode coverage that TG-01b
# does NOT provide — TG-01b only proves PING/PONG/_core are EXEMPT, not that:
#   * TG-01: framework_in EXHAUSTION rejects app calls while nodes_in stays independent
#   * TG-23: a rate-rejected fall-through candidate is charged with NO refund
# (TG-02's typed-RateLimitException PROPAGATION is a driver-side catch needing no
# stats read, so it is NOT skipped — it still runs above.) Restoring TG-01/TG-23 needs
# a framework change (exempt a designated control identity from framework_in) or a
# peer-local observe path — a maintainer decision, HELD. The winner's rate ACCOUNTING
# itself is separately verified green by the boot-suite rate tests.
_RATE_CTRLPLANE_SKIP = (
    "needs a cross-node r_rl_stats read of a throttled peer, but r_rl_stats is itself "
    "framework_in-charged so the throttle blocks its own observation (max=0 never "
    "refills; drained max>=1 rejects in the drained region); no framework_in exemption "
    "for a control identity exists. Drops framework_in-exhaustion (TG-01) / no-refund "
    "(TG-23) coverage — needs a control-plane exemption or peer-local observe (HELD)"
)


class MultinodeDriver(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._task = None
        self._peers = [
            h for h in os.environ.get("MULTINODE_PEER_HOSTS", "").split(",") if h
        ]

    @async_log_errors
    async def on_enable(self):
        self._task = asyncio.create_task(self._run())

    @async_log_errors
    async def on_disable(self):
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass

    # ── infra helpers ───────────────────────────────────────────────────
    @property
    def _peer(self):
        return self._peers[0] if self._peers else "w2b-peer"

    @property
    def _peer2(self):
        return self._peers[1] if len(self._peers) > 1 else "w2c-peer2"

    def _net(self):
        return getattr(self._plexus, "network", None)

    def _snapshot(self):
        net = self._net()
        fn = getattr(net, "snapshot", None)
        if not callable(fn):
            return {}
        try:
            return fn()
        except Exception:
            return {}

    @staticmethod
    def _peer_list(snap):
        """Normalize snapshot() to a list of per-peer dicts (top-level shape is
        rewrite-defined; handle dict-of-peers / {peers:[...]} / list)."""
        if isinstance(snap, dict):
            if isinstance(snap.get("peers"), list):
                return snap["peers"]
            if isinstance(snap.get("peers"), dict):
                return list(snap["peers"].values())
            # dict keyed by hostname → per-peer dicts
            vals = [v for v in snap.values() if isinstance(v, dict) and "hostname" in v]
            if vals:
                return vals
        if isinstance(snap, list):
            return snap
        return []

    def _peer_entry(self, hostname, snap=None):
        snap = snap if snap is not None else self._snapshot()
        for p in self._peer_list(snap):
            if p.get("hostname") == hostname:
                return p
        return None

    def _reachable(self, hostname):
        e = self._peer_entry(hostname)
        return bool(e and e.get("reachable"))

    async def _await_link(self, hostname, timeout=_LINK_TIMEOUT):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self._reachable(hostname):
                return True
            await asyncio.sleep(0.2)
        return self._reachable(hostname)

    async def _obs_events(self, hostname, topic=None, clear=False):
        try:
            return await self.execute(
                OBS, "obs_events", {"topic": topic, "clear": clear},
                hosts=[hostname] if hostname != self._plexus.hostname else "local",
            )
        except Exception:
            return []

    async def _rl_configure(self, hostname, rate_limits):
        return await self.execute(FIX, "r_rl_configure", {"rate_limits": rate_limits},
                                  hosts=[hostname])

    async def _rl_stats(self, hostname):
        return await self.execute(FIX, "r_rl_stats", {}, hosts=[hostname])

    async def _rl_clear(self, hostname):
        return await self._rl_configure(hostname, None)

    @staticmethod
    def _charged(stats, dim, key=None):
        """Sum `charged` across stats rows matching dim (+ key). stats() rows:
        {dim,key,charged,rejected,tokens,max,last,rate} (A9-resolved shape)."""
        total = 0
        for row in stats or []:
            if row.get("dim") == dim and (key is None or row.get("key") == key):
                total += int(row.get("charged", 0) or 0)
        return total

    def _write_phase(self, phase):
        pf = os.environ.get("MULTINODE_PHASE_FILE", "")
        if pf:
            try:
                Path(pf).write_text(str(phase), encoding="utf-8")
            except OSError:
                pass

    async def _wait_phase_ack(self, want, timeout):
        """Wait for the pytest to write `want` back into the phase file + "-ack"
        suffix (so the driver knows the kill/respawn landed)."""
        pf = os.environ.get("MULTINODE_PHASE_FILE", "")
        if not pf:
            return False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                if Path(pf).read_text(encoding="utf-8").strip() == want:
                    return True
            except OSError:
                pass
            await asyncio.sleep(0.2)
        return False

    # ── run dispatch ────────────────────────────────────────────────────
    async def _run(self):
        rec = CaseRecorder("MultinodeDriver", SUITE_VERSION, self._plexus)
        kw = dict(remote_available=True)
        group = os.environ.get("MULTINODE_GROUP", "")
        cell = os.environ.get("MULTINODE_CELL", "")
        try:
            if group == "pair":
                await self._await_link(self._peer)
                await self._pair_cells(rec, kw)
            elif group == "trio_mesh":
                await self._await_link(self._peer)
                await self._await_link(self._peer2)
                await self._trio_mesh_cells(rec, kw)
            elif group == "star":
                await self._await_link(self._peer)
                await self._star_cells(rec, kw)
            elif group == "discovery":
                await self._await_link(self._peer)
                await self._discovery_cells(rec, kw)
            elif group == "lifecycle" and cell:
                # lifecycle cells manage their own link timing (some need the peer
                # OFFLINE at boot, e.g. TP-08).
                await self._lifecycle_cell(rec, kw, cell)
        finally:
            self._write_result(rec.to_dict())

    def _write_result(self, data):
        rf = os.environ.get("MULTINODE_RESULT_FILE", "")
        if not rf:
            return
        try:
            with open(rf, "w", encoding="utf-8") as f:
                json.dump(data, f, default=repr)
        except OSError:
            self._logger.exception("MultinodeDriver: result write failed")

    # ════════════════════════ PAIR-GROUP CELLS ════════════════════════
    async def _pair_cells(self, rec, kw):
        peer = self._peer

        # TP-55 — universal chunking round-trips + pulse-not-starved.
        async def tp55(c):
            sizes = {"unary": 200_000, "empty": 0}
            r = await self.execute(FIX, "echo_bytes", {"n_bytes": 3_000_000}, hosts=[peer])
            assert r["data"] == b"\xab" * 3_000_000, "large unary result not byte-exact"
            # empty stream = clean close, zero items
            empty = [it async for it in self.execute_stream(FIX, "stream_empty", {}, hosts=[peer])]
            assert empty == [], f"empty stream yielded {empty}"
            # multi-item stream
            got = []
            async for it in self.execute_stream(FIX, "stream_n", {"n": 4}, hosts=[peer]):
                got.append(it)
            assert len(got) == 4, f"stream item count {len(got)} != 4"
            # pulse not starved: peer still reachable right after the big transfer
            assert self._reachable(peer), "peer went unreachable during large transfer"
        await rec.run_case("TP-55.chunking_roundtrip", tp55, category="chunking", **kw)

        # TG-05 — exact chunk boundaries (64KB / 128KB / ±1 / 0).
        async def tg05(c):
            for n in (65536, 131072, 65535, 65537, 0):
                r = await self.execute(FIX, "echo_bytes", {"n_bytes": n}, hosts=[peer])
                assert r["n"] == n and len(r["data"]) == n, f"boundary {n} not byte-exact"
        await rec.run_case("TG-05.exact_boundaries", tg05, category="chunking", **kw)

        # TP-56 — long/infinite stream does not head-of-line block a small call.
        async def tp56(c):
            async def drain_infinite():
                n = 0
                async for _ in self.execute_stream(FIX, "stream_infinite", {"tick": 0.02}, hosts=[peer]):
                    n += 1
                    if n >= 3:
                        return
            t = asyncio.create_task(drain_infinite())
            try:
                r = await asyncio.wait_for(
                    self.execute(FIX, "add", {"a": 2, "b": 3}, hosts=[peer]), timeout=10.0)
                assert r == 5, "concurrent small call blocked by the infinite stream"
            finally:
                t.cancel()
        await rec.run_case("TP-56.no_hol_block", tp56, category="chunking", **kw)

        # TG-08 — simultaneous bidirectional large transfers.
        async def tg08(c):
            me = self._plexus.hostname
            fwd = self.execute(FIX, "echo_bytes", {"n_bytes": 2_000_000}, hosts=[peer])
            # peer calls back to the driver's own NetFixTarget.echo_bytes
            rev = self.execute(FIX, "relay_call", {
                "target_plugin": FIX, "endpoint": "echo_bytes",
                "args": {"n_bytes": 2_000_000}, "hosts": [me]}, hosts=[peer])
            r_fwd, r_rev = await asyncio.gather(fwd, rev)
            assert r_fwd["data"] == b"\xab" * 2_000_000, "forward not byte-exact"
            assert r_rev["data"] == b"\xab" * 2_000_000, "reverse not byte-exact"
            assert self._reachable(peer), "pulse starved during bidirectional transfer"
        await rec.run_case("TG-08.bidirectional_large", tg08, category="chunking", **kw)

        # TP-05b — hosts="local" does NOT reach a REMOTE-ONLY handler (a topic the
        # driver has no local sub for; the peer does).
        async def tp05b(c):
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tp05b", "topic": "w2/remoteonly",
                "target_access_name": "fix_probe_handler", "target_plugin": FIX}, hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            # Assert on a PEER-SIDE handler marker (was fix_probe_handler invoked?)
            # rather than the transport net/inbound counter — the driver's own
            # readback execute emits net/inbound, so that counter can't distinguish
            # "the local call reached the peer" from "my readback did".
            await self.execute(FIX, "reset_flags", {}, hosts=[peer])
            with pytest_raises_any():
                await self.request_event("ev_remoteonly", payload={"v": 1}, hosts="local")
            invoked = await self.execute(FIX, "get_flag", {"key": "probe_invoked"}, hosts=[peer])
            assert not invoked, "hosts=local reached the remote peer's handler (short-circuit broken)"
            # control: hosts="any" DOES reach the remote-only handler — AND the marker
            # flips to True, proving the flag mechanism actually works (so the negative
            # assert above can't be a silent false-pass from a dead flag).
            r = await self.request_event("ev_remoteonly", payload={"v": 2}, hosts="any")
            assert r and r.get("pong"), "hosts=any did not reach the remote-only handler"
            invoked_any = await self.execute(FIX, "get_flag", {"key": "probe_invoked"}, hosts=[peer])
            assert invoked_any, "peer handler marker never set even on hosts=any (flag mechanism broken)"
            await self.execute(CTL, "ctl_sub_remove", {"label": "tp05b"}, hosts=[peer])
        await rec.run_case("TP-05b.local_short_circuit", tp05b, category="routing", **kw)

        # B-092 sender-side host gate — the SENDER pre-filter at events.py:1046
        # applies _sub_accepts_remote_publisher against each peer's advertised
        # sub BEFORE scheduling a FANOUT frame. A sub whose `hosts` names only a
        # non-driver host must be pre-filtered out: 0 scheduled, nothing
        # delivered. This is the sole non-hostile path that reaches the
        # predicate over the wire (a `hosts="local"` sub would be dropped at
        # advertisement, manager.py:527, and never reach the predicate at all —
        # so it must be an ADVERTISED-but-rejected sub, not a local one).
        # The RECEIVER gate (manager.py:638) is a cooperative driver's own
        # pre-filter's shadow and is covered separately by the net_hostile cell.
        async def b092_sender_host_gate(c):
            # DH is the DRIVER's own hostname. At the sender pre-filter it is
            # passed as author_host (the publisher publishing from here), i.e.
            # the host a peer sub must accept/reject.
            DH = self._plexus.hostname
            TOPIC, EV = "fix/b092", "ev_b092"

            async def _add(label, hosts):
                await self.execute(CTL, "ctl_sub_add", {
                    "label": label, "topic": TOPIC,
                    "target_access_name": "fix_fanout_handler",
                    "target_plugin": FIX, "hosts": hosts}, hosts=[peer])
                # let the added sub advertise back to the driver's directory
                await asyncio.sleep(_HEARTBEAT_GUESS * 3)

            async def _remove(label):
                await self.execute(CTL, "ctl_sub_remove", {"label": label},
                                   hosts=[peer])

            # NEGATIVE — sub accepts only from the peer's OWN host, never the
            # driver. author_host=DH is not in [peer] → predicate rejects at the
            # sender, so route_publish yields it but 1046 filters it out.
            # ctl_sub_remove in a finally so a mid-cell raise can't leak the
            # advertised sub into later pair-group cells.
            await self.execute(FIX, "reset_fanout", {}, hosts=[peer])
            await _add("b092neg", [peer])
            try:
                n_rej = await self.publish_event(EV, payload={"b092": "neg"}, hosts="any")
                await asyncio.sleep(_HEARTBEAT_GUESS * 2)  # let any wrongly-sent frame land
                log_rej = await self.execute(FIX, "fanout_log", {}, hosts=[peer])
            finally:
                await _remove("b092neg")
            assert n_rej == 0, (
                f"sender scheduled {n_rej} for a sub that rejects the driver "
                f"host (events.py:1046 pre-filter not applied)")
            assert log_rej == [], (
                f"rejected sub still received the fanout: {log_rej!r}")

            # POSITIVE control — same sub but hosts=[driver host] → predicate
            # accepts. Proves the sub really advertised and the delivery path
            # works, so the negative n_rej==0 cannot be a silent "sub never
            # existed / link down" false pass.
            await self.execute(FIX, "reset_fanout", {}, hosts=[peer])
            await _add("b092pos", [DH])
            try:
                n_acc = await self.publish_event(EV, payload={"b092": "pos"}, hosts="any")
                await asyncio.sleep(_HEARTBEAT_GUESS * 2)
                log_acc = await self.execute(FIX, "fanout_log", {}, hosts=[peer])
            finally:
                await _remove("b092pos")
            assert n_acc >= 1, (
                f"sender scheduled {n_acc} for a sub that accepts the driver "
                f"host (advert not propagated or link down — the negative case "
                f"above would be a false pass)")
            assert {"b092": "pos"} in log_acc, (
                f"accepting sub did not receive the fanout: {log_acc!r}")
        await rec.run_case("B-092.sender_host_gate", b092_sender_host_gate,
                           category="routing", **kw)

        # TP-17b — nested-Network handler raise is WRAPPED → propagates (no fall-through).
        async def tp17b(c):
            raised = None
            try:
                await self.execute(FIX, "raise_networkish", {}, hosts=[peer])
            except Exception as e:  # noqa: BLE001
                raised = e
            assert isinstance(raised, RequestException), (
                f"expected a propagated RequestException, got {raised!r}")
            assert not isinstance(raised, (NetworkRequestException, NoLocalSubException)), (
                "a Network/NoLocalSub handler-raise must be WRAPPED in a non-Network "
                "RequestException so it propagates, not silently falls through")
        await rec.run_case("TP-17b.nested_network_wrap", tp17b, category="errors", **kw)

        # TP-04 — publish_event scheduled count == local+remote SUBS (delta by K).
        async def tp04(c):
            n0 = await self.publish_event("ev_fanout", payload={"i": 0}, hosts="any")
            labels = [f"tp04_{i}" for i in range(3)]
            for lbl in labels:
                await self.execute(CTL, "ctl_sub_add", {
                    "label": lbl, "topic": "fix/fanout",
                    "target_access_name": "fix_fanout_handler", "target_plugin": FIX},
                    hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)  # let the added subs advertise
            n1 = await self.publish_event("ev_fanout", payload={"i": 1}, hosts="any")
            for lbl in labels:
                await self.execute(CTL, "ctl_sub_remove", {"label": lbl}, hosts=[peer])
            assert n1 - n0 == 3, f"scheduled-count delta {n1 - n0} != 3 added subs"
            # control: a no-sub topic schedules 0
            nz = await self.publish_event("ev_nosub", payload={}, hosts="any")
            assert nz == 0, f"no-sub topic scheduled {nz} != 0"
        await rec.run_case("TP-04.fanout_scheduled_count", tp04, category="fanout", **kw)

        # TP-34 — runtime sub disable/enable → routable/un-routable within a heartbeat.
        async def tp34(c):
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tp34", "topic": "fix/toggle",
                "target_access_name": "fix_probe_handler", "target_plugin": FIX},
                hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            r = await self.request_event("ev_toggle", payload={}, hosts="any")
            assert r and r.get("pong"), "added sub not routable"
            # disable it
            await self.execute(CTL, "ctl_sub_remove", {"label": "tp34"}, hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            fell_through = False
            try:
                await self.request_event("ev_toggle", payload={}, hosts="any")
            except RequestException:
                fell_through = True
            assert fell_through, "removed sub still routable (should fall through to no-match)"
            # control: the untouched fix/probe sub stays routable
            r2 = await self.request_event("ev_probe", payload={}, hosts="any")
            assert r2 and r2.get("pong"), "untouched sub stopped routing"
        await rec.run_case("TP-34.runtime_sub_toggle", tp34, category="routing", **kw)

        # TP-32 / TG-07 — hash stability: ZERO refetch across N pulses on stable content.
        async def tp32(c):
            await self._obs_events(self._plexus.hostname, clear=True)  # own directory events
            await asyncio.sleep(_HEARTBEAT_GUESS * 5)  # several pulses, content stable
            evs = await self._obs_events(self._plexus.hostname, topic="_core/directory/replaced")
            assert len(evs) == 0, f"stable content refetched {len(evs)}x (expected 0)"
            # control: a real change (add a sub on the peer) DOES refetch
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tp32chg", "topic": "fix/chg",
                "target_access_name": "fix_probe_handler", "target_plugin": FIX}, hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 3)
            evs2 = await self._obs_events(self._plexus.hostname, topic="_core/directory/replaced")
            await self.execute(CTL, "ctl_sub_remove", {"label": "tp32chg"}, hosts=[peer])
            assert len(evs2) >= 1, "a real content change did not refetch"
        await rec.run_case("TP-32.hash_stability_zero_refetch", tp32, category="directory", **kw)

        # TG-24 — single stream item > per-cid 8MB bound → stream fails, LINK STAYS UP.
        async def tg24(c):
            failed = False
            try:
                async for _ in self.execute_stream(FIX, "stream_huge_item", {"size_mb": 9}, hosts=[peer]):
                    pass
            except RequestException:
                failed = True
            assert failed, "oversized stream item did not fail with a mapped error"
            # A10/link-up: a later normal call on the SAME link succeeds
            r = await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
            assert r == 2, "link did not stay up after the reassembly-bound stream failure"
            # under-bound control streams intact
            got = [it async for it in self.execute_stream(FIX, "stream_n", {"n": 2}, hosts=[peer])]
            assert len(got) == 2, "under-bound stream did not stream intact"
        await rec.run_case("TG-24.oversized_stream_item", tg24, category="reassembly", **kw)

        # TG-12 — callee cancels a slow handler on handler_timeout (flag stays UNSET).
        async def tg12(c):
            await self.execute(FIX, "reset_flags", {}, hosts=[peer])
            try:
                await self.execute(FIX, "slow_handler", {"delay": 10.0, "key": "tg12"},
                                   hosts=[peer], timeout=1.0)
            except RequestException:
                pass
            await asyncio.sleep(2.0)  # let any (buggy) completion set the flag
            flag = await self.execute(FIX, "get_flag", {"key": "tg12"}, hosts=[peer])
            assert flag is False, "slow handler was NOT cancelled (side-effect flag set)"
            # control: a fast handler completes and sets its flag
            await self.execute(FIX, "slow_handler", {"delay": 0.0, "key": "tg12b"}, hosts=[peer], timeout=5.0)
            flag2 = await self.execute(FIX, "get_flag", {"key": "tg12b"}, hosts=[peer])
            assert flag2 is True, "fast handler flag not set (control broken)"
        await rec.run_case("TG-12.callee_cancel_on_timeout", tg12, category="timeout", **kw)

        # TG-15 — cross-node sync-gen stream cancelled mid-item → clean teardown, no crash.
        async def tg15(c):
            agen = self.execute_stream(FIX, "stream_infinite", {"tick": 0.02}, hosts=[peer])
            it = agen.__aiter__()
            first = await it.__anext__()
            assert first is not None, "stream produced nothing"
            await agen.aclose()  # cancel mid-item
            # link still healthy afterward
            r = await self.execute(FIX, "add", {"a": 4, "b": 5}, hosts=[peer])
            assert r == 9, "link unhealthy after mid-item stream cancel"
        await rec.run_case("TG-15.syncgen_cancel_miditem", tg15, category="stream", **kw)

        # TG-01b — PING/PONG exempt from nodes_in/framework_in (charged delta == read-only).
        async def tg01b(c):
            await self._rl_configure(peer, _high_rl())
            s0 = await self._rl_stats(peer)
            c0 = self._charged(s0, "framework_in")
            await asyncio.sleep(_HEARTBEAT_GUESS * 4)  # several pulses, NO calls
            s1 = await self._rl_stats(peer)
            c1 = self._charged(s1, "framework_in")
            # only the s1 read call itself charged (delta 1); pulses added 0
            assert c1 - c0 == 1, (
                f"framework_in advanced by {c1 - c0} over a pulse window "
                "(expected 1 = only the stats read; pulses must be exempt)")
            # control: an extra real CALL between reads bumps the delta
            s2 = await self._rl_stats(peer)
            await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
            s3 = await self._rl_stats(peer)
            assert self._charged(s3, "framework_in") - self._charged(s2, "framework_in") == 2, (
                "control: a real call did not advance framework_in")
            await self._rl_clear(peer)
        await rec.run_case("TG-01b.ping_pong_rate_exempt", tg01b, category="rate", **kw)

        # TG-22 (inbound half) — a real cross-node CALL fires _core/net/inbound at the callee.
        async def tg22in(c):
            await self._obs_events(peer, clear=True)
            await self.execute(FIX, "add", {"a": 1, "b": 2}, hosts=[peer])
            evs = await self._obs_events(peer, topic="_core/net/inbound")
            assert len(evs) >= 1, "a real cross-node CALL did not fire _core/net/inbound"
        await rec.run_case("TG-22.inbound_event_present", tg22in, category="observability", **kw)

        # TG-06 (best-effort) — reachable-but-directory-stale → falls through cleanly.
        async def tg06(c):
            # A freshly-added peer in the add→link-up window may be reachable with
            # an empty routing table → a call must fall through to a clean no-match,
            # never crash; then become routable once a snapshot lands.
            e = self._peer_entry(peer)
            routable_eventually = False
            for _ in range(20):
                try:
                    r = await self.request_event("ev_probe", payload={}, hosts="any")
                    if r and r.get("pong"):
                        routable_eventually = True
                        break
                except RequestException:
                    pass  # clean fall-through, not a crash
                await asyncio.sleep(0.5)
            assert routable_eventually, "peer never became routable after a snapshot landed"
        await rec.run_case("TG-06.reachable_but_stale_fallthrough", tg06, category="routing", **kw)

    # ════════════════════════ TRIO-GROUP CELLS ════════════════════════
    async def _trio_mesh_cells(self, rec, kw):
        """Full-mesh trio (driver pins peer + peer2; both pin each other)."""
        peer, peer2 = self._peer, self._peer2

        # TG-03 — fall-through ORDER: LOCAL first; absent local, hostname-lex-lowest.
        async def tg03(c):
            me = self._plexus.hostname
            # subs on fix/who → whoami, on driver (local), peer, and peer2.
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tg03local", "topic": "fix/who",
                "target_access_name": "fix_who_handler", "target_plugin": FIX}, hosts="local")
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tg03p", "topic": "fix/who",
                "target_access_name": "fix_who_handler", "target_plugin": FIX}, hosts=[peer])
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tg03p2", "topic": "fix/who",
                "target_access_name": "fix_who_handler", "target_plugin": FIX}, hosts=[peer2])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            ans = await self.request_event("ev_who", payload={}, hosts="any")
            assert ans.get("hostname") == me, (
                f"LOCAL must answer first; got {ans.get('hostname')}")
            # remove local → lex-lowest REMOTE (peer < peer2) answers
            await self.execute(CTL, "ctl_sub_remove", {"label": "tg03local"}, hosts="local")
            await asyncio.sleep(_HEARTBEAT_GUESS)
            ans1 = await self.request_event("ev_who", payload={}, hosts="any")
            assert ans1.get("hostname") == peer, (
                f"absent local, expected lex-lowest {peer}, got {ans1.get('hostname')}")
            # remove lex-lower remote → lex-next answers (proves order, not luck)
            await self.execute(CTL, "ctl_sub_remove", {"label": "tg03p"}, hosts=[peer])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            ans2 = await self.request_event("ev_who", payload={}, hosts="any")
            assert ans2.get("hostname") == peer2, (
                f"after removing lex-lower, expected {peer2}, got {ans2.get('hostname')}")
            await self.execute(CTL, "ctl_sub_remove", {"label": "tg03p2"}, hosts=[peer2])
        await rec.run_case("TG-03.fall_through_order", tg03, category="routing", **kw)

        # TP-53 — execute fall-through over a stale-cache candidate (both host echo).
        # Runs BEFORE the rate cells: it needs a clean framework_in bucket, and a
        # maxn=0 rate cell's un-clearable teardown would otherwise leak forward and
        # rate-reject this routing call.
        async def tp53(c):
            # Both peers host echo_unary. Ask "any" — one answers; then disable the
            # NetFixTarget subscription set on the lex-lower via a sub the driver added,
            # forcing a stale-cache NO_ENDPOINT → fall through to peer2.
            r = await self.execute(FIX, "echo_unary", {"payload": "x"}, hosts="any")
            assert r == "x", "no candidate answered echo"
            # (full stale-cache injection needs a plugin drop mid-window → lifecycle;
            #  here assert at-least-once fall-through by targeting a set incl. peer2)
            r2 = await self.execute(FIX, "echo_unary", {"payload": "y"}, hosts=[peer, peer2])
            assert r2 == "y", "explicit multi-candidate execute did not resolve"
        await rec.run_case("TP-53.execute_fall_through", tp53, category="routing", **kw)

        # TG-01 — cross-node rate charging (exhaust framework_in while nodes_in has budget).
        async def tg01(c):
            c.skip(_RATE_CTRLPLANE_SKIP)
            await self._rl_configure(peer, _framework_in_rl(maxn=2))
            s0 = await self._rl_stats(peer)
            base = self._charged(s0, "framework_in")
            rejected = 0
            for _ in range(5):
                try:
                    await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
                except RateLimitException:
                    rejected += 1
            assert rejected >= 1, "framework_in never rejected despite a low cap"
            s1 = await self._rl_stats(peer)
            assert self._charged(s1, "framework_in") > base, "framework_in charged not advancing"
            # control: under-budget call fully answered after clear.
            await self._rl_clear(peer)
            await asyncio.sleep(2.5)
            r = await self.execute(FIX, "add", {"a": 2, "b": 2}, hosts=[peer])
            assert r == 4, "under-budget call not answered after clear"
        await rec.run_case("TG-01.cross_node_rate_charge", tg01, category="rate", **kw)

        # TG-23 — rate × fall-through: each tried peer charged, NO refund.
        async def tg23(c):
            c.skip(_RATE_CTRLPLANE_SKIP)
            # both peers expose fix/who; rate-limit the lex-lower so the call
            # falls through to peer2, and assert the lex-lower peer's charge STANDS.
            await self._rl_configure(peer, _nodes_and_framework_rl(0))
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tg23a", "topic": "fix/who",
                "target_access_name": "fix_who_handler", "target_plugin": FIX}, hosts=[peer])
            await self.execute(CTL, "ctl_sub_add", {
                "label": "tg23b", "topic": "fix/who",
                "target_access_name": "fix_who_handler", "target_plugin": FIX}, hosts=[peer2])
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            s0 = await self._rl_stats(peer)
            base = self._charged(s0, "nodes_in", key=self._plexus.hostname)
            # RATE_LIMIT propagates (does not fall through) for request_event per §4.5;
            # so assert the charge stood on the tried peer (no refund) via stats.
            try:
                await self.request_event("ev_who", payload={}, hosts="any")
            except RateLimitException:
                pass
            s1 = await self._rl_stats(peer)
            after = self._charged(s1, "nodes_in", key=self._plexus.hostname)
            assert after >= base + 1, "the tried (rate-limited) peer was not charged / was refunded"
            for h, lbl in ((peer, "tg23a"), (peer2, "tg23b")):
                await self.execute(CTL, "ctl_sub_remove", {"label": lbl}, hosts=[h])
            await self._rl_clear(peer)
        await rec.run_case("TG-23.rate_no_refund_on_fallthrough", tg23, category="rate", **kw)

        # TG-02 — a cross-node RATE_LIMIT reject PROPAGATES as a TYPED RateLimitException
        # (NOT degraded to a bare RequestException), distinct from a NO_MATCH which
        # FALLS THROUGH. This is wave-2's only guard on that typed-propagation path, and
        # it needs neither a peer stats read nor a reconfigure — the reject is caught at
        # the DRIVER — so it runs (unlike TG-01/TG-23, which the control-plane self-
        # throttle blocks; see _RATE_CTRLPLANE_SKIP). tg02 runs LAST in the group and does
        # NOT clear the peer's max=0 (that clear is itself framework_in-charged and can't
        # be serviced by a max=0 peer) — a residual max=0 poisons no later cell.
        async def tg02(c):
            # max=1 (0 is an INVALID limiter config — max must be >0; you omit a
            # dimension to disable it). Drain the single token, then the NEXT cross-node
            # call is over budget and its reject must PROPAGATE as a typed RateLimitException.
            await self._rl_configure(peer, _framework_in_rl(maxn=1))
            await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])  # consumes the token
            raised = None
            try:
                await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])  # over budget
            except Exception as e:  # noqa: BLE001
                raised = e
            # The reject must PROPAGATE (a raise, NOT a silent fall-through/None) as a
            # TYPED, rate-attributable RateLimitException. #2 unified exception typing made
            # SPEC §4.5's typed-propagation reach the CALLER surface cross-node: netcore
            # RAISES the typed RateLimitException (dispatch.py:175, "the exact legacy
            # exception TYPE"), and core.py now PRESERVES it as an OBJECT through the
            # request-result path (the remote-execute safety-net stores the object; the
            # caller-facing re-raise propagates it by type) instead of stringifying it to a
            # bare RequestException. So `except RateLimitException:` on a CROSS-NODE call now
            # catches it — we assert the exact subtype (RateLimitException is a
            # RequestException, so this is strictly stronger than the old base-type check).
            assert type(raised) is RateLimitException and "rate limit" in str(raised).lower(), (
                f"cross-node RATE_LIMIT must propagate as a TYPED RateLimitException "
                f"carrying the limiter text, got {raised!r}")
            # discriminator: a NO_MATCH event FALLS THROUGH (does not raise RateLimit/
            # Capability). Fire it at the UNTHROTTLED peer2 so the fall-through is a real
            # no-subscriber result, not a rate reject masquerading as one.
            fell = False
            try:
                await self.request_event("ev_nomatch", payload={}, hosts=[peer2])
            except NoLocalSubException:
                fell = True
            except RateLimitException:
                fell = False  # a rate reject is NOT a fall-through — fail loudly below
            except RequestException:
                fell = True
            assert fell, "NO_MATCH did not fall through on the unthrottled peer"
        await rec.run_case("TG-02.rate_capability_propagate", tg02, category="rate", **kw)

    # ════════════════════════ STAR-TOPOLOGY CELL ════════════════════════
    async def _star_cells(self, rec, kw):
        """Driver pins ONLY the hub (peer); peer2 is an unpinned leaf."""
        peer, peer2 = self._peer, self._peer2

        async def tp35(c):
            assert self._reachable(peer), "hub (peer) not reachable"
            fell = False
            try:
                await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer2])
            except RequestException:
                fell = True
            assert fell, "unpinned leaf peer2 was reachable (STAR leaked)"
            n = await self.publish_event("ev_leafonly", payload={}, hosts=[peer2])
            assert n == 0, f"publish to unreachable leaf scheduled {n} != 0"
        await rec.run_case("TP-35.star_partial_unreachable", tp35, category="routing", **kw)

    # ════════════════════════ DISCOVERY / VOUCH CELLS ════════════════════════
    async def _discovery_cells(self, rec, kw):
        """Discoverable topology: driver discoverable=on + pins the hub (peer); the
        hub lists peer2 as a config-origin peer → the driver learns peer2 by vouch.
        TP-44/47/50 + TG-16 need extra victims/caps the pytest wires; skip-noted
        where a boot did not provide them (honest, not a false green)."""
        peer, peer2 = self._peer, self._peer2

        # TP-43 — vouch propagation → one refetch → peer learned (source=vouched).
        async def tp43(c):
            learned = await self._await_link(peer2, timeout=25.0)
            e = self._peer_entry(peer2)
            assert learned and e is not None, "vouched peer2 not learned via the hub"
            assert e.get("source") == "vouched", f"peer2 source != vouched: {e.get('source')}"
            evs = await self._obs_events(self._plexus.hostname, topic="_core/peer/vouched")
            assert any(v.get("payload", {}).get("hostname") == peer2 for v in evs), (
                "no _core/peer/vouched audit event for the learned peer")
        await rec.run_case("TP-43.vouch_propagation", tp43, category="discovery", hard_timeout_s=90.0, **kw)

        # TG-21 — vouch AUDIT emit carries {hostname,fingerprint,voucher_hostname}.
        async def tg21(c):
            await self._await_link(peer2, timeout=25.0)
            evs = await self._obs_events(self._plexus.hostname, topic="_core/peer/vouched")
            match = [v for v in evs if v.get("payload", {}).get("hostname") == peer2]
            assert match, "no vouched audit event for peer2"
            p = match[0]["payload"]
            for field in ("hostname", "fingerprint", "voucher_hostname"):
                assert field in p, f"vouched audit event missing {field!r}: {p}"
        await rec.run_case("TG-21.vouch_audit_emit", tg21, category="discovery", hard_timeout_s=90.0, **kw)

        # TP-44 — pairwise vouch: discoverable pair connects; off leaf ignores.
        async def tp44(c):
            # Both driver + hub are discoverable=on → they learn peer2 (also on) and
            # form an edge. A discoverable=off leaf (if the pytest added one) would
            # never pin a learned peer. Here: assert the learned edge to peer2 works.
            assert await self._await_link(peer2, timeout=25.0), "pairwise vouch did not connect peer2"
            r = await self.execute(FIX, "add", {"a": 5, "b": 6}, hosts=[peer2])
            assert r == 11, "learned peer2 not routable (pairwise edge not formed)"
        await rec.run_case("TP-44.pairwise_vouch_connects", tp44, category="discovery", hard_timeout_s=90.0, **kw)

        # TP-50 — orphaned vouched peer: observable + manually removable (redial cap
        # = pytest-side StallListener.connect_count, per A4).
        async def tp50(c):
            spec = os.environ.get("MULTINODE_ORPHAN_HOST", "")
            if not spec:
                c.skip("no orphan vouched host wired for this boot")
            await asyncio.sleep(_HEARTBEAT_GUESS * 4)
            e = self._peer_entry(spec)
            assert e is not None, "orphaned vouched peer not present in snapshot"
            assert e.get("source") == "vouched" and not e.get("reachable"), (
                "orphan should be a non-reachable vouched entry")
            res = await self.execute(CTL, "ctl_remove_peer", {"hostname": spec}, hosts="local")
            assert res.get("ok"), f"remove_peer of orphan failed: {res.get('error')}"
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            assert self._peer_entry(spec) is None, "orphan not removed after remove_peer"
        await rec.run_case("TP-50.orphan_vouched_removable", tp50, category="discovery", hard_timeout_s=90.0, **kw)

        # TP-47 — rotating-vouch inflation → per-voucher ACTIVE budget caps adds.
        async def tp47(c):
            # Needs a small per-voucher cap (net-knobs) + the hub vouching > cap
            # victims (StallListener addrs). Assert a vouch_rejected fired.
            if os.environ.get("MULTINODE_VOUCH_CAP", "") == "":
                c.skip("per-voucher cap topology not wired for this boot")
            await asyncio.sleep(_HEARTBEAT_GUESS * 5)
            evs = await self._obs_events(self._plexus.hostname, topic="_core/peer/vouch_rejected")
            assert evs, "per-voucher budget never rejected an over-cap vouch"
        await rec.run_case("TP-47.rotating_vouch_cap", tp47, category="discovery", hard_timeout_s=90.0, **kw)

    # ════════════════════════ LIFECYCLE CELLS ════════════════════════
    async def _lifecycle_cell(self, rec, kw, cell):
        """One cell per boot, phase-coordinated with the pytest (kill/respawn/
        reconfigure). The driver signals phases; the pytest acts + acks."""
        peer = self._peer
        handler = getattr(self, f"_lc_{cell.replace('-', '_')}", None)
        if handler is None:
            await rec.run_case(f"{cell}.unknown", self._skip_body(f"no lifecycle handler for {cell}"), **kw)
            return
        await handler(rec, kw, peer)

    def _skip_body(self, reason):
        async def body(c):
            c.skip(reason)
        return body

    async def _lc_TP_08(self, rec, kw, peer):
        # peer offline at boot → call fails, retried, SUCCEEDS once it appears.
        async def body(c):
            fell = False
            try:
                await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
            except RequestException:
                fell = True
            assert fell, "call to an offline peer unexpectedly succeeded"
            self._write_phase("spawn-peer")               # pytest boots the peer now
            ok = await self._await_link(peer, timeout=40.0)
            assert ok, "peer never became reachable after it came online"
            r = await self.execute(FIX, "add", {"a": 2, "b": 3}, hosts=[peer])
            assert r == 5, "call did not succeed once the peer appeared"
        await rec.run_case("TP-08.offline_at_boot_retry", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_09(self, rec, kw, peer):
        # WiFi drop then return → ONE reconnect heals BOTH directions.
        async def body(c):
            assert await self._await_link(peer), "peer not up initially"
            self._write_phase("kill-peer")
            await self._wait_phase_ack("kill-peer-done", 30.0)
            # peer respawns (pytest); wait for heal
            self._write_phase("respawn-peer")
            ok = await self._await_link(peer, timeout=40.0)
            assert ok, "link did not heal after drop+return"
            # _await_link polls liveness-based `reachable` (§4.2), which can read
            # stale-True across a FAST kill→respawn (the liveness window hasn't
            # elapsed), so the link may still be mid-reconnect here. Retry BOTH
            # directions over a bounded window until the real link is back —
            # `add` = driver→peer, `relay_call` = the reverse peer→driver leg.
            r1 = r2 = None
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 40.0
            while loop.time() < deadline:
                try:
                    r1 = await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
                    r2 = await self.execute(FIX, "relay_call", {
                        "target_plugin": FIX, "endpoint": "add", "args": {"a": 2, "b": 2},
                        "hosts": [self._plexus.hostname]}, hosts=[peer])
                    break
                except RequestException:
                    await asyncio.sleep(0.5)
            assert r1 == 2 and r2 == 4, "both directions did not heal"
        await rec.run_case("TP-09.drop_reconnect_heals_both", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_A5_silentdeath(self, rec, kw, peer):
        # EMPIRICAL A5 tiebreaker: fire a long cross-node request, then the pytest
        # SUSPENDS the peer process (no TCP RST — true silent death). The request has a
        # 120s timeout and the handler sleeps 60s, so NEITHER can resolve it before the
        # peer is frozen — the ONLY thing that can fail it early is the transport's
        # idle-read teardown backstop (~idle_read_deadline, 2.5s under FAST_KNOBS).
        # elapsed ~2.5s => backstop works (round-1 "hang" REFUTED); "HUNG" => it doesn't.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            loop = asyncio.get_running_loop()
            task = asyncio.create_task(
                self.execute(FIX, "slow_handler", {"delay": 60.0, "key": "a5"},
                             hosts=[peer], timeout=120.0))
            await asyncio.sleep(1.0)  # let the CALL reach the peer + the handler start
            assert not task.done(), "slow request resolved before the suspend"
            t0 = loop.time()
            self._write_phase("suspend-peer")   # pytest freezes the peer here (no RST)
            exc = "HUNG"
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=30.0)
                exc = "RETURNED"  # should not happen — peer is frozen
            except asyncio.TimeoutError:
                exc = "HUNG"
            except BaseException as e:  # noqa: BLE001
                exc = type(e).__name__
            elapsed = loop.time() - t0
            c.set_marker(f"elapsed={elapsed:.2f}s exc={exc}")
            assert exc not in ("HUNG", "RETURNED"), (
                f"silent peer death did NOT fast-fail the in-flight request "
                f"(exc={exc}, elapsed={elapsed:.1f}s)")
            assert elapsed < 15.0, (
                f"fast-fail took {elapsed:.1f}s — not the ~idle_read_deadline backstop")
        await rec.run_case("A5.silent_death_fastfail", body, category="lifecycle", hard_timeout_s=60.0, **kw)

    async def _lc_TP_11(self, rec, kw, peer):
        # in-flight request + stream during peer-down → pending fails PROMPTLY.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            req = asyncio.create_task(self.execute(FIX, "slow_handler", {"delay": 60.0}, hosts=[peer]))
            async def consume():
                async for _ in self.execute_stream(FIX, "stream_slow", {"delay": 60.0}, hosts=[peer]):
                    pass
            strm = asyncio.create_task(consume())
            await asyncio.sleep(1.0)
            self._write_phase("kill-peer")
            # both should fail promptly (not hang) once the peer dies
            done = False
            for t in (req, strm):
                try:
                    await asyncio.wait_for(asyncio.shield(t), timeout=30.0)
                except (RequestException, asyncio.CancelledError):
                    done = True
                except asyncio.TimeoutError:
                    done = False
                    break
                except Exception:
                    done = True
            assert done, "in-flight request/stream did not fail promptly on peer-down"
        await rec.run_case("TP-11.in_flight_during_down", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_30(self, rec, kw, peer):
        # reboot SAME content → the peer RESTARTS (new epoch, _core/peer/restarted)
        # but the directory is NOT re-applied (identical content_hash) — §10.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            e0 = self._peer_entry(peer)
            epoch0 = (e0 or {}).get("epoch")
            await self._obs_events(self._plexus.hostname, clear=True)
            self._write_phase("reboot-same")               # pytest kills+respawns same config
            await self._wait_phase_ack("reboot-done", 60.0)
            assert await self._await_link(peer, timeout=40.0), "peer not back after reboot"
            # The restart is surfaced two CONSISTENT ways: (1) the _core/peer/restarted
            # EVENT (membership fires it on the first post-reboot pong carrying a new
            # epoch), and (2) the snapshot's `epoch` field, which is the LIVE peer epoch
            # and so also flips to the new boot. The directory is NOT re-applied though
            # (identical content_hash → §10 no-op). `_await_link`'s liveness-based
            # reachable can read stale-True across a fast kill→respawn (TP-09-style), so
            # poll for the event, then settle so a would-be re-apply has time to fire
            # before we assert it did NOT.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 40.0
            restarted = []
            def _new_epoch(evs):
                return [(r.get("payload") or {}).get("epoch") for r in evs
                        if (r.get("payload") or {}).get("hostname") in (peer, None)]
            while loop.time() < deadline:
                restarted = await self._obs_events(self._plexus.hostname, topic="_core/peer/restarted")
                if any(ep and ep != epoch0 for ep in _new_epoch(restarted)):
                    break
                await asyncio.sleep(0.3)
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            replaced = await self._obs_events(self._plexus.hostname, topic="_core/directory/replaced")
            seen = _new_epoch(restarted)
            assert any(ep and ep != epoch0 for ep in seen), (
                f"reboot did not surface a NEW epoch via _core/peer/restarted "
                f"(epoch0={epoch0}, saw {seen})")
            # the snapshot's `epoch` is the LIVE peer epoch: it flipped to the new boot
            # and agrees with the restart event (it is NOT frozen at the old value).
            e1 = self._peer_entry(peer)
            snap_epoch = (e1 or {}).get("epoch")
            assert snap_epoch not in (None, epoch0) and snap_epoch in seen, (
                f"snapshot epoch is not the live peer epoch after reboot "
                f"(epoch0={epoch0}, snapshot={snap_epoch}, restarted={seen})")
            assert len(replaced) == 0, f"same-content reboot applied a directory ({len(replaced)}x)"
        await rec.run_case("TP-30.reboot_same_content", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_31(self, rec, kw, peer):
        # reboot DIFFERENT content → apply + refetch; new routing visible.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            await self._obs_events(self._plexus.hostname, clear=True)
            self._write_phase("reboot-changed")            # pytest respawns config.peer_changed
            await self._wait_phase_ack("reboot-done", 60.0)
            assert await self._await_link(peer, timeout=40.0), "peer not back after reboot"
            await asyncio.sleep(_HEARTBEAT_GUESS * 3)
            replaced = await self._obs_events(self._plexus.hostname, topic="_core/directory/replaced")
            assert len(replaced) >= 1, "different-content reboot did not apply/refetch"
            # the new NetFixTargetB endpoint is now routable
            r = await self.execute("NetFixTargetB", "add", {"a": 1, "b": 1}, hosts=[peer])
            assert r == 2, "new endpoint from the changed content not routable"
        await rec.run_case("TP-31.reboot_diff_content", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_14(self, rec, kw, peer):
        # plugin hot-swap → content_hash changes + new endpoint routable.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            e0 = self._peer_entry(peer)
            h0 = (e0 or {}).get("content_hash")
            self._write_phase("reboot-changed")            # respawn with the extra plugin
            await self._wait_phase_ack("reboot-done", 60.0)
            assert await self._await_link(peer, timeout=40.0), "peer not back after swap"
            await asyncio.sleep(_HEARTBEAT_GUESS * 3)
            e1 = self._peer_entry(peer)
            assert (e1 or {}).get("content_hash") != h0, "content_hash unchanged after hot-swap"
            r = await self.execute("NetFixTargetB", "add", {"a": 2, "b": 2}, hosts=[peer])
            assert r == 4, "hot-swapped endpoint not routable"
        await rec.run_case("TP-14.hot_swap_hash_gated", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_39(self, rec, kw, peer):
        # revoke DURABILITY: a runtime-revoked config peer is NOT re-added by a reload.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            await self.execute(CTL, "ctl_remove_peer", {"hostname": peer}, hosts="local")
            await asyncio.sleep(_HEARTBEAT_GUESS * 2)
            assert not self._reachable(peer), "peer still reachable right after revoke"
            # reload a config that STILL lists the peer (rebuild-trigger key flipped)
            # — a durable tombstone must NOT re-add the runtime-revoked config peer.
            reload_cfg = os.environ.get("MULTINODE_RELOAD_CONFIG", "")
            if not reload_cfg:
                c.skip("no reload config wired for this boot")
            res = await self.execute(CTL, "ctl_reload_config", {"config_path": reload_cfg}, hosts="local")
            assert res.get("ok"), f"reload failed: {res.get('error')}"
            await asyncio.sleep(_HEARTBEAT_GUESS * 4)
            assert self._peer_entry(peer) is None or not self._reachable(peer), (
                "revoked config peer was silently re-added by a config reload (tombstone not durable)")
        await rec.run_case("TP-39.revoke_durability_config", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_36(self, rec, kw, peer):
        # runtime add_peer → routable within a heartbeat of LINK-UP.
        async def body(c):
            # boot with NO peer configured; the pytest supplies the peer spec via env file.
            spec_path = os.environ.get("MULTINODE_ADDPEER_SPEC", "")
            if not spec_path or not Path(spec_path).exists():
                c.skip("no add_peer spec provided")
            spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
            await self._obs_events(self._plexus.hostname, clear=True)
            res = await self.execute(CTL, "ctl_add_peer", {"spec": spec}, hosts="local")
            assert res.get("ok"), f"add_peer failed: {res.get('error')}"
            ok = await self._await_link(spec["hostname"], timeout=40.0)
            assert ok, "added peer never became reachable"
            ups = await self._obs_events(self._plexus.hostname, topic="_core/peer/up")
            assert ups, "no _core/peer/up after add_peer"
            r = await self.execute(FIX, "add", {"a": 3, "b": 4}, hosts=[spec["hostname"]])
            assert r == 7, "added peer not routable after link-up"
        await rec.run_case("TP-36.runtime_add_peer", body, category="lifecycle", hard_timeout_s=150.0, **kw)

    async def _lc_TP_38(self, rec, kw, peer):
        # revoke DURING a ping-await → stays gone (roster-gated resume-stamp).
        # peer = a DELAYED-PONG hostile (pytest HostilePongServer pong_delay).
        async def body(c):
            await self._await_link(peer, timeout=20.0)  # link up (may flicker reachable)
            await asyncio.sleep(1.0)                     # a pulse is now in the delayed await
            res = await self.execute(CTL, "ctl_remove_peer", {"hostname": peer}, hosts="local")
            assert res.get("ok"), f"remove failed: {res.get('error')}"
            # wait PAST the delayed PONG so a resuming (ungated) stamp would resurrect it
            await asyncio.sleep(8.0)
            e = self._peer_entry(peer)
            assert e is None or not e.get("reachable"), (
                "revoked peer RESURRECTED by a resuming ping-await stamp (roster-gate broken)")
        await rec.run_case("TP-38.revoke_during_ping_await", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TP_46(self, rec, kw, peer):
        # remove DURING mid-dial → registration roster-gate closes the ghost link.
        # peer = a StallListener (accepts TCP, never completes TLS → the node hangs
        # in dial/handshake). Remove during the dial; assert no ghost link forms.
        async def body(c):
            await asyncio.sleep(2.0)  # the node is now dialing/handshaking the staller
            await self._obs_events(self._plexus.hostname, clear=True)
            res = await self.execute(CTL, "ctl_remove_peer", {"hostname": peer}, hosts="local")
            assert res.get("ok"), f"remove failed: {res.get('error')}"
            await asyncio.sleep(_HEARTBEAT_GUESS * 4)
            ups = await self._obs_events(self._plexus.hostname, topic="_core/peer/up")
            assert not any(u.get("payload", {}).get("hostname") == peer for u in ups), (
                "a ghost link came UP for a peer removed mid-dial (roster-gate missed)")
            assert self._peer_entry(peer) is None or not self._reachable(peer), (
                "peer removed mid-dial is present/reachable (ghost link)")
        await rec.run_case("TP-46.remove_mid_dial", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TP_51(self, rec, kw, peer):
        # pulse-loop SURVIVES one poisoned peer. peers = [coop, poison]; the poison
        # peer replies malformed to every PING; the coop peer must keep pulsing.
        async def body(c):
            coop = self._peers[0] if self._peers else peer
            assert await self._await_link(coop, timeout=25.0), "coop peer never came up"
            # over a multi-heartbeat window the coop peer stays reachable + answers,
            # despite the poison peer erroring every pulse (return_exceptions isolation).
            for _ in range(5):
                assert self._reachable(coop), "coop peer went unreachable (poison starved the loop)"
                r = await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[coop])
                assert r == 2, "coop peer stopped answering (poison broke the pulse loop)"
                await asyncio.sleep(_HEARTBEAT_GUESS)
        await rec.run_case("TP-51.pulse_survives_poison", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TP_37(self, rec, kw, peer):
        # remove_peer/revoke → stays gone; control = a NON-removed peer still routes.
        async def body(c):
            keep = self._peers[1] if len(self._peers) > 1 else None
            assert await self._await_link(peer), "peer not up"
            res = await self.execute(CTL, "ctl_remove_peer", {"hostname": peer}, hosts="local")
            assert res.get("ok"), f"remove failed: {res.get('error')}"
            await asyncio.sleep(_HEARTBEAT_GUESS * 3)
            e = self._peer_entry(peer)
            assert e is None or not e.get("reachable"), "removed peer still reachable"
            fell = False
            try:
                await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
            except RequestException:
                fell = True
            assert fell, "removed peer still routes"
            if keep:
                assert self._reachable(keep), "control: a non-removed peer stopped routing"
                r = await self.execute(FIX, "add", {"a": 2, "b": 2}, hosts=[keep])
                assert r == 4, "control peer did not answer"
        await rec.run_case("TP-37.revoke_stays_gone", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TP_41(self, rec, kw, peer):
        # operator re-add of a revoked hostname → routes again (clears tombstone);
        # control = without re-add it stays gone.
        async def body(c):
            spec_path = os.environ.get("MULTINODE_READD_SPEC", "")
            assert await self._await_link(peer), "peer not up"
            await self.execute(CTL, "ctl_remove_peer", {"hostname": peer}, hosts="local")
            await asyncio.sleep(_HEARTBEAT_GUESS * 3)
            assert not self._reachable(peer), "control: peer not gone after revoke (pre-readd)"
            if not spec_path or not Path(spec_path).exists():
                c.skip("no re-add spec provided")
            spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
            res = await self.execute(CTL, "ctl_add_peer", {"spec": spec}, hosts="local")
            assert res.get("ok"), f"re-add failed: {res.get('error')}"
            assert await self._await_link(peer, timeout=40.0), "re-added peer never reachable"
            r = await self.execute(FIX, "add", {"a": 3, "b": 3}, hosts=[peer])
            assert r == 6, "re-added peer not routable"
        await rec.run_case("TP-41.operator_readd", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TG_04(self, rec, kw, peer):
        # LinkRefused fast-path (a dead-port peer → WSAECONNREFUSED → fast down) +
        # a steady peer stays reachable. peers = [steady, dead].
        async def body(c):
            steady = self._peers[0] if self._peers else peer
            dead = self._peers[1] if len(self._peers) > 1 else None
            assert await self._await_link(steady, timeout=25.0), "steady peer not up"
            if dead:
                # a refused peer should be marked unreachable FAST (fast-down path)
                await asyncio.sleep(_HEARTBEAT_GUESS * 3)
                de = self._peer_entry(dead)
                assert de is None or not de.get("reachable"), (
                    "a connection-REFUSED peer was not fast-downed")
                if de is not None:
                    # §8.3: a refused dial must surface a structured reason. The dead
                    # peer is a dead PORT the driver dials (lex-lower dials higher),
                    # so its reason is specifically "connection_refused" (not the
                    # generic "unreachable" a never-dialed peer would get).
                    assert de.get("unreachable_reason") == "connection_refused", (
                        f"refused peer unreachable_reason should be 'connection_refused', "
                        f"got {de.get('unreachable_reason')!r} / last_error={de.get('last_error')!r}")
            # steady peer stays reachable throughout
            assert self._reachable(steady), "steady peer flapped while a dead peer was refused"
        await rec.run_case("TG-04.linkrefused_fast_path", body, category="lifecycle",
                           hard_timeout_s=150.0, **kw)

    async def _lc_TG_14(self, rec, kw, peer):
        # reconfigure during an in-flight cross-node request → fails PROMPTLY.
        async def body(c):
            assert await self._await_link(peer), "peer not up"
            reload_cfg = os.environ.get("MULTINODE_RELOAD_CONFIG", "")
            if not reload_cfg:
                c.skip("no reload config wired for this boot")
            inflight = asyncio.create_task(self.execute(FIX, "slow_handler", {"delay": 60.0}, hosts=[peer]))
            await asyncio.sleep(1.0)
            # a rebuild-trigger key reload must drain/fail the in-flight call promptly
            reload_task = asyncio.create_task(
                self.execute(CTL, "ctl_reload_config", {"config_path": reload_cfg}, hosts="local"))
            failed = False
            try:
                await asyncio.wait_for(asyncio.shield(inflight), timeout=30.0)
            except (RequestException, asyncio.CancelledError):
                failed = True
            except asyncio.TimeoutError:
                failed = False
            assert failed, "in-flight call left hanging across a reconfigure (B-079)"
            await reload_task
            # a call after the reconfigure completes normally
            assert await self._await_link(peer, timeout=40.0), "peer not up after reload"
            # `reachable` is liveness-based (SPEC §4.2), so after the post-reload
            # reconnect the peer can be reachable a beat before its directory (the
            # `add` endpoint route) is re-fetched — retry the call briefly.
            r = None
            for _ in range(40):
                try:
                    r = await self.execute(FIX, "add", {"a": 1, "b": 1}, hosts=[peer])
                    break
                except RequestException:
                    await asyncio.sleep(0.25)
            assert r == 2, "post-reconfigure call did not complete normally"
        await rec.run_case("TG-14.reconfigure_during_inflight", body, category="lifecycle", hard_timeout_s=150.0, **kw)


# ── helpers used by the cell bodies ─────────────────────────────────────
class pytest_raises_any:
    """Context manager: swallow any RequestException (a cell asserts separately)."""
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, RequestException)


def _high_rl():
    """A rate_limits config with generous maxes so charges COUNT but never reject
    (docs/rate_limiting.md shape: framework_in flat; nodes_in has default/peers)."""
    return {"framework_in": {"max": 100000, "window": 1000},
            "nodes_in": {"default": {"max": 100000, "window": 1000}}}


def _framework_in_rl(maxn=2):
    return {"framework_in": {"max": maxn, "window": 1000}}


def _nodes_and_framework_rl(fw_max):
    """framework_in capped (to force a reject) + nodes_in tracked with a high cap
    (so the per-peer nodes_in CHARGE advances even on a framework_in reject —
    nodes_in charges FIRST, §8.2 ordering)."""
    return {"framework_in": {"max": fw_max, "window": 1000},
            "nodes_in": {"default": {"max": 100000, "window": 1000}}}
