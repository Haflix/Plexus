"""TestNetPairUnitSuite — in-process minimal-NM regression guards for the
networking advert/liveness layer (the B-085 "P-cell" family).

These are the fast, deterministic, no-socket half of the B-085 networking
failure-angle matrix (B-085 in the bug tracker). They construct a
``NetworkManager`` skeleton via ``object.__new__`` carrying ONLY the attributes
the REAL method under test reads (the same minimal-NM idiom the other
``*UnitSuite`` plugins use), drive the real method, and assert the FIXED /
correct behavior with ``expected_status="pass"`` so a regression turns the gate
RED. The real-socket half (concurrent-boot convergence, drop+reconnect, revoke)
lives separately in ``plugins_test/networking_pair/`` behind ``PLEXUS_PAIR_TEST``.

SCOPE NOTE: only behaviors that are CORRECT today belong here (pass-polarity).
Repros for still-OPEN advert-layer bugs (HUNT-013/052/093/094) stay as xfail
guards in the gitignored ``plugins_test/hunt_2026_06/`` dir and get promoted
here (flipped to pass-polarity) once they are fixed.

MACHINERY-SPECIFIC TAG: several of these cases poke methods B-086 (the planned
advert-layer rework: delete the tiebreak / ack-retry / delta / restart-detect
machinery for a level-triggered reconcile model) will delete or restructure.
They are deliberately tagged so their removal/rewrite ALONGSIDE B-086 is not read
as a regression — they guard today's implementation, not the eventual one. The
durable, rework-surviving guards are the OUTCOME-level socket cells in
``networking_pair/`` (see B-085 / B-086 in the tracker).
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.networking import NetworkManager  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.6.0"


# --- minimal stand-ins -----------------------------------------------------
class _StubNode:
    """Minimal Node stand-in for the liveness helpers. Only ``.enabled`` and
    ``.hostname`` are read by ``_record_heartbeat_miss`` / ``_mark_node_dead``."""

    def __init__(self, hostname: str, enabled: bool = True) -> None:
        self.hostname = hostname
        self.enabled = enabled


def _base_nm() -> NetworkManager:
    """NetworkManager skeleton with just a logger; callers add the attributes
    their method-under-test reads."""
    nm = object.__new__(NetworkManager)
    nm._logger = logging.getLogger("test.NetPairUnit")
    return nm


# --- A1 (netcore #2 seam): unary re-entry must forward the caller identity ---
class _A1FakePlugin:
    """A matchable remote plugin for _RematchRegistry._match_execute: enabled,
    remote, with one remote + accessible endpoint."""

    def __init__(self, name: str = "PlugX") -> None:
        self.plugin_name = name
        self.enabled = True
        self.plugin_uuid = ""
        self.remote = True
        self.endpoints = {
            "ep1": {"remote": True, "accessible_by_other_plugins": True}
        }


class _A1RecordingCore:
    """Records the kwargs the re-entry passes to core.execute so the test can
    assert the caller identity is forwarded (not defaulted to local-system)."""

    def __init__(self) -> None:
        self.plugins = {"PlugX": _A1FakePlugin("PlugX")}
        self.execute_kwargs: Optional[Dict[str, Any]] = None

    async def execute(self, plugin, endpoint, **kwargs):
        self.execute_kwargs = dict(plugin=plugin, endpoint=endpoint, **kwargs)
        return {"ok": True}


class TestNetPairUnitSuite(Plugin):
    """In-process minimal-NM guards for the networking advert/liveness layer."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestNetPairUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestNetPairUnitSuite disabled")

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
        rec = CaseRecorder("TestNetPairUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        await self._b082_advertise_reports_skip(rec, kw)
        await self._b082_initial_exchange_releases_slot_on_skip(rec, kw)
        await self._p4_heartbeat_strikes_then_mark_dead(rec, kw)
        await self._a1_unary_execute_forwards_caller_identity(rec, kw)
        await self._a3_discovery_reachable_via_legacy_config(rec, kw)
        await self._theme2_new_knobs_wired(rec, kw)
        await self._node_ips_removed_schema_fails_loud(rec, kw)
        await self._theme2_legacy_aliases_and_idle_guard(rec, kw)
        await self._peer_down_on_silent_death(rec, kw)

        return rec.to_dict()

    # ----- peer/down (MED): silent death must emit _core/peer/down -----

    async def _peer_down_on_silent_death(self, rec, kw):
        # peer/down (netcore completeness gap, MED): a SILENT peer death (liveness
        # age-out / link drop / hard-refuse) must emit `_core/peer/down` on the
        # reachable->unreachable transition, EDGE-triggered (once), not only on an
        # explicit revoke. Drives the REAL Membership._recompute_reachable with a
        # minimal object (no sockets), asserting the emit + idempotency.
        async def body(c):
            import time as _time
            from plexus.netcore.membership import Membership

            captured = []
            mem = object.__new__(Membership)
            mem._roster = {"peerX": object(), "peerY": object()}
            mem._last_seen = {
                "peerX": _time.monotonic(), "peerY": _time.monotonic()}
            mem._liveness_timeout = 30.0
            mem._reachable_set = frozenset({"peerX", "peerY"})
            mem._observe = lambda ev, payload: captured.append((ev, payload))

            # both fresh -> both stay reachable, NO peer/down.
            mem._recompute_reachable()
            assert not captured, f"no peer/down expected when all fresh; got {captured}"
            assert mem._reachable_set == frozenset({"peerX", "peerY"})

            # peerX ages out past the liveness window -> silent death.
            mem._last_seen["peerX"] = _time.monotonic() - 100.0
            mem._recompute_reachable()
            downs = [p for (ev, p) in captured if ev == "_core/peer/down"]
            assert len(downs) == 1 and downs[0]["hostname"] == "peerX", (
                "exactly one _core/peer/down for peerX expected on the silent-death "
                f"transition; got {captured}"
            )
            assert downs[0].get("reason") == "unreachable", downs[0]
            assert mem._reachable_set == frozenset({"peerY"})

            # EDGE-triggered: a second pass must NOT re-emit (not every pulse).
            captured.clear()
            mem._recompute_reachable()
            assert not captured, (
                "_core/peer/down must fire ONCE on the transition edge, not every "
                f"pulse; got {captured}"
            )

        await rec.run_case(
            "networking.peer_down_on_silent_death",
            body,
            tags=("networking", "netcore", "observability"),
            category="networking",
            **kw,
        )

    # ----- A3 (Theme 2): discovery must be reachable via documented config -----

    async def _a3_discovery_reachable_via_legacy_config(self, rec, kw):
        # A3 (netcore completeness gap, MED): netcore gates §4.7 vouch-discovery on
        # the canonical `discoverable` key, but nothing in the config layer ever
        # wrote it -- operators only ever produced `auto_discoverable`/
        # `direct_discoverable`, so discovery was UNREACHABLE via documented config.
        # Theme 2 maps legacy -> canonical in `_build_network_manager` (inject
        # `discoverable` into a copy of nw_cfg before the ctor). Drives the REAL
        # `_build_network_manager` with a minimal fake self, asserting a config with
        # only `auto_discoverable: true` turns the netcore discovery gate ON.
        async def body(c):
            import logging as _log
            import tempfile as _tf
            import types as _types

            Plexus = self._plexus.__class__
            tmp = _tf.mkdtemp(prefix="a3_")
            cfgpath = str(Path(tmp) / "config.yml")
            open(cfgpath, "w").close()
            fake = _types.SimpleNamespace(
                config_path=cfgpath, _logger=_log.getLogger("test.A3"),
                hostname="a3node")

            # legacy auto_discoverable, NO canonical key -> discovery ON
            nm = Plexus._build_network_manager(
                fake, {"networking": {"auto_discoverable": True}})
            assert nm.membership._discoverable is True, (
                "A3 regression: auto_discoverable=true did not enable the netcore "
                "discovery gate -- the legacy->canonical `discoverable` mapping in "
                "_build_network_manager is missing/broken; discovery is unreachable "
                "via documented config."
            )
            # no discovery keys -> OFF (fail-safe)
            nm_off = Plexus._build_network_manager(fake, {"networking": {}})
            assert nm_off.membership._discoverable is False, (
                "discovery must default OFF when no discovery key is set"
            )
            # explicit canonical `discoverable` wins on its own
            nm_c = Plexus._build_network_manager(
                fake, {"networking": {"discoverable": True}})
            assert nm_c.membership._discoverable is True

        await rec.run_case(
            "networking.discovery_reachable_via_legacy_config",
            body,
            tags=("networking", "netcore", "discovery"),
            category="networking",
            **kw,
        )

    # ----- Theme 2: new deployment knobs must be wired from config -----

    async def _theme2_new_knobs_wired(self, rec, kw):
        # Theme 2: the 4 new deployment knobs + connect_timeout are wired from the
        # networking config into Transport/Membership (they already existed as ctor
        # params but manager.py never read a config key for them). A `<=0` value
        # falls back to the compiled-in default (same guard as the reassembly caps).
        async def body(c):
            import tempfile as _tf
            import types as _types
            from plexus.netcore.manager import NetworkManager
            from plexus.netcore.transport import (
                PER_PEER_REASSEMBLY_CAP, PER_PEER_CID_CAP,
                STREAM_IDLE_DEADLINE, CONNECT_TIMEOUT,
            )
            from plexus.netcore.membership import VOUCHER_ACTIVE_CAP

            core = _types.SimpleNamespace(hostname="knobnode")
            cfg = {
                "per_peer_reassembly_cap": 32 * 1024 * 1024,
                "per_peer_cid_cap": 128,
                "stream_idle_deadline": 90.0,
                "connect_timeout": 20.0,
                "vouch_active_cap": 200,
            }
            nm = NetworkManager(core, networking_config=cfg,
                                config_dir=_tf.mkdtemp(prefix="knob_"))
            assert nm.transport.per_peer_cap == 32 * 1024 * 1024, nm.transport.per_peer_cap
            assert nm.transport.per_peer_cid_cap == 128, nm.transport.per_peer_cid_cap
            assert nm.transport._stream_idle == 90.0, nm.transport._stream_idle
            assert nm.transport._connect_timeout == 20.0, nm.transport._connect_timeout
            assert nm.membership._voucher_cap == 200, nm.membership._voucher_cap

            # <=0 / bad values fall back to the compiled-in defaults.
            bad = {
                "per_peer_reassembly_cap": -1,
                "per_peer_cid_cap": 0,
                "stream_idle_deadline": 0,
                "connect_timeout": -5,
                "vouch_active_cap": -10,
            }
            nm2 = NetworkManager(core, networking_config=bad,
                                 config_dir=_tf.mkdtemp(prefix="knob0_"))
            assert nm2.transport.per_peer_cap == PER_PEER_REASSEMBLY_CAP
            assert nm2.transport.per_peer_cid_cap == PER_PEER_CID_CAP
            assert nm2.transport._stream_idle == STREAM_IDLE_DEADLINE
            assert nm2.transport._connect_timeout == CONNECT_TIMEOUT
            assert nm2.membership._voucher_cap == VOUCHER_ACTIVE_CAP

        await rec.run_case(
            "networking.theme2_new_knobs_wired",
            body,
            tags=("networking", "netcore", "config"),
            category="networking",
            **kw,
        )

    async def _node_ips_removed_schema_fails_loud(self, rec, kw):
        # Restored migration guard (deep-hunt 2026-07-14): the REMOVED `node_ips:`
        # schema is not a netcore knob, so without a guard it would be silently
        # absorbed by the tolerant `**_legacy` sink -> a peerless, non-functional
        # node with no error. The manager now fails LOUD on `node_ips:` presence,
        # pointing at the `peers:` schema.
        async def body(c):
            import tempfile as _tf
            import types as _types
            from plexus.netcore.manager import NetworkManager

            core = _types.SimpleNamespace(hostname="legacynode")
            raised = None
            try:
                NetworkManager(core, networking_config={"node_ips": ["10.0.0.1"]},
                               config_dir=_tf.mkdtemp(prefix="nodeips_"))
            except RuntimeError as e:
                raised = e
            assert raised is not None, "node_ips: must raise RuntimeError, not be silently ignored"
            msg = str(raised)
            assert "node_ips" in msg and "peers" in msg, msg
            # a config WITHOUT node_ips still constructs fine (guard is presence-gated).
            ok = NetworkManager(core, networking_config={},
                                config_dir=_tf.mkdtemp(prefix="nonodeips_"))
            assert ok is not None

        await rec.run_case(
            "networking.node_ips_removed_schema_fails_loud",
            body,
            tags=("networking", "netcore", "config", "migration"),
            category="networking",
            **kw,
        )

    # ----- Theme 2: G2 legacy aliases + the idle_read <=0 self-DoS guard -----

    async def _theme2_legacy_aliases_and_idle_guard(self, rec, kw):
        # The legacy timeout keys map to netcore's canonical keys in
        # `_build_network_manager`; an explicit canonical key wins over its legacy
        # alias; and a non-positive value falls back to the default — the last is a
        # regression guard for the `inbound_idle_timeout: 0` self-DoS (0 idle-read
        # deadline expires every read immediately, tearing down every peer link).
        async def body(c):
            import logging as _log
            import tempfile as _tf
            import types as _types

            Plexus = self._plexus.__class__
            tmp = _tf.mkdtemp(prefix="alias_")
            cfgpath = str(Path(tmp) / "config.yml")
            open(cfgpath, "w").close()

            def _fake():
                return _types.SimpleNamespace(
                    config_path=cfgpath, _logger=_log.getLogger("test.alias"),
                    hostname="aliasnode")

            # legacy aliases map to canonical netcore keys
            nm = Plexus._build_network_manager(_fake(), {"networking": {
                "inbound_idle_timeout": 45.0, "request_timeout": 90.0}})
            assert nm.transport._idle_read_deadline == 45.0, nm.transport._idle_read_deadline
            assert nm.transport._stream_idle == 90.0, nm.transport._stream_idle

            # explicit canonical key wins over its legacy alias
            nm2 = Plexus._build_network_manager(_fake(), {"networking": {
                "idle_read_deadline": 55.0, "inbound_idle_timeout": 45.0}})
            assert nm2.transport._idle_read_deadline == 55.0, nm2.transport._idle_read_deadline

            # non-positive alias value -> default (self-DoS guard). hb defaults 10 so
            # the idle-read default is max(2*10, 20) = 20.
            nm3 = Plexus._build_network_manager(_fake(), {"networking": {
                "inbound_idle_timeout": 0}})
            assert nm3.transport._idle_read_deadline == max(2.0 * 10.0, 20.0), (
                "inbound_idle_timeout:0 must fall back to the default idle-read "
                f"deadline, NOT 0 (an idle_read of 0 expires every read immediately "
                f"-> teardown loop on every link); got "
                f"{nm3.transport._idle_read_deadline}"
            )

            # explicit discoverable=False must win over auto_discoverable=True
            nm4 = Plexus._build_network_manager(_fake(), {"networking": {
                "discoverable": False, "auto_discoverable": True}})
            assert nm4.membership._discoverable is False, (
                "explicit discoverable=False must not be overridden by a truthy "
                "legacy alias"
            )

        await rec.run_case(
            "networking.theme2_legacy_aliases_and_idle_guard",
            body,
            tags=("networking", "netcore", "config"),
            category="networking",
            **kw,
        )

    # ----- A1: unary cross-node execute must forward the caller identity -----

    async def _a1_unary_execute_forwards_caller_identity(self, rec, kw):
        # A1 (netcore completeness gap, security): the UNARY inbound re-entry
        # `_RematchRegistry.execute` must forward author/author_id/author_host to
        # core.execute, exactly like its 3 sibling re-entries (execute_stream /
        # request_event / request_event_stream). Before the fix it called
        # core.execute WITHOUT them, so core defaulted author="system" -> rewrote
        # it to the callee hostname -> is_local_system=True: a system_caller=False
        # peer ran as the callee's LOCAL-SYSTEM principal on the unary path,
        # bypassing the system_caller gate. Drives the REAL _RematchRegistry with
        # a recording fake core and asserts the caller identity reaches
        # core.execute; a revert drops the kwargs so this guard turns RED. (This
        # checks the identity FORWARDING the system_caller / is_local_system gate
        # depends on; the gate itself is exercised cross-node by the netcore
        # dispatch self-test + wave-2.)
        async def body(c):
            from plexus.netcore.types import (
                CallerCtx,
                ExecuteSelector,
                PeerIdentity,
            )

            core = _A1RecordingCore()
            reg = NetworkManager._RematchRegistry(core)
            selector = ExecuteSelector("PlugX", "ep1")
            # authenticated peer RECORD: hostname "peer-a", system_caller=False.
            identity = PeerIdentity("peer-a", False)
            # wire-asserted caller: author_host is a DIFFERENT, spoofable value so the
            # test proves the AUTHENTICATED identity.hostname (not the wire's
            # author_host) is what reaches core.execute.
            caller = CallerCtx("PlugX", "uuid-x", "spoofed-host", "req-1")

            await reg.execute(selector, {"v": 1}, identity, caller)

            kwargs = core.execute_kwargs
            assert kwargs is not None, "re-entry never called core.execute"
            assert kwargs.get("author") == "PlugX", (
                "A1 regression: unary re-entry did not forward author to "
                f"core.execute (got {kwargs.get('author')!r}). Without it core "
                "defaults author='system' -> the peer runs as the callee's "
                "local-system principal, bypassing the system_caller gate."
            )
            assert kwargs.get("author_id") == "uuid-x", (
                f"A1 regression: author_id not forwarded (got {kwargs.get('author_id')!r})"
            )
            assert kwargs.get("author_host") == "peer-a", (
                "A1 regression: author_host must be the AUTHENTICATED peer hostname "
                f"(identity.hostname='peer-a'), NOT the wire-asserted author_host "
                f"('spoofed-host'); got {kwargs.get('author_host')!r}. The callee must "
                "render a REMOTE request keyed on the authenticated host."
            )

        await rec.run_case(
            "networking.unary_reentry_forwards_caller_identity",
            body,
            tags=("networking", "security", "netcore"),
            category="networking",
            **kw,
        )

    # ----- B-082: advertise/initial-exchange invariant (fixed this sprint) -----

    async def _b082_advertise_reports_skip(self, rec, kw):
        # B-082 fix (plexus 0.69.13): advertise_subs_remote returns a bool so a
        # caller that pairs a _snapshot_sent slot-claim with the send can tell a
        # genuine send apart from a SKIP. When is_ready is False (pre-ready
        # discovery / mid-shutdown) it must return False WITHOUT sending and
        # WITHOUT raising. Before the fix it returned None (bare return), which
        # the caller could not distinguish from a completed send.
        async def body(c):
            c.skip("old-NM advert/liveness internals (advertise_subs / initial-exchange slot / strike-death) retired by the netcore rewrite; covered by netcore membership/directory self-tests + wave-2")
            nm = _base_nm()
            nm.is_ready = False
            sent = await nm.advertise_subs_remote("10.0.0.9", "peer-B")
            # Must be an explicit False (the skip signal), not None/truthy.
            assert sent is False, (
                "advertise_subs_remote must return False when is_ready is False "
                f"(no send, no raise); got {sent!r}. B-082 regression: the "
                "caller can no longer tell a skipped send from a real one, so "
                "_perform_initial_exchange will poison the _snapshot_sent slot."
            )

        await rec.run_case(
            "networking.advertise_subs_remote_reports_skip_when_not_ready",
            body,
            tags=("networking", "advert"),
            bug_ids=("B-082",),
            category="networking",
            **kw,
        )

    async def _b082_initial_exchange_releases_slot_on_skip(self, rec, kw):
        # B-082 root fix: _perform_initial_exchange claims _snapshot_sent[host]
        # BEFORE calling advertise_subs_remote, and (post-fix) RELEASES it when
        # advertise reports it did not send. In the pre-ready window advertise
        # skips (returns False) without raising, so the slot must be popped —
        # otherwise it is poisoned as "sent" with nothing on the wire and every
        # later exchange short-circuits (the B-082 deadlock). Drives the REAL
        # _perform_initial_exchange + REAL advertise_subs_remote (is_ready=False
        # path), asserting the slot is NOT left claimed.
        async def body(c):
            c.skip("old-NM advert/liveness internals (advertise_subs / initial-exchange slot / strike-death) retired by the netcore rewrite; covered by netcore membership/directory self-tests + wave-2")
            nm = _base_nm()
            nm.is_ready = False
            nm._snapshot_sent = {}
            nm._peer_session_ids = {}
            nm._adverts_struct_lock = asyncio.Lock()

            await nm._perform_initial_exchange("10.0.0.9", "peer-B")

            assert "peer-B" not in nm._snapshot_sent, (
                "B-082 regression: _perform_initial_exchange left "
                "_snapshot_sent['peer-B'] claimed after advertise_subs_remote "
                "skipped the send (is_ready=False). The slot is poisoned as "
                "'sent' with nothing transmitted; later discovery/reciprocal "
                "triggers will short-circuit on it forever (the deadlock B-082 "
                "fixed). The slot must be released when the send was skipped."
            )

        await rec.run_case(
            "networking.perform_initial_exchange_releases_slot_on_skipped_send",
            body,
            tags=("networking", "advert"),
            bug_ids=("B-082",),
            category="networking",
            **kw,
        )

    # ----- P4 (HUNT-092 death half): strike-then-die mechanics (correct today) -----

    async def _p4_heartbeat_strikes_then_mark_dead(self, rec, kw):
        # The N-strikes liveness DEATH path (C-044). This is the CORRECT half of
        # HUNT-092 / B-088 (the BUG is that a struck-dead peer is never
        # re-probed; that recovery gap is guarded by the socket cells, not
        # here). Here we pin the death mechanics: _record_heartbeat_miss
        # tolerates misses below heartbeat_strikes and signals dead at the
        # threshold (clearing the counter), and _mark_node_dead disables the
        # node, drops its advert state, clears its miss counter, and is
        # idempotent. Drives the REAL helpers; _drop_peer_advert_state is stubbed
        # to a recorder (its own state-drop is guarded elsewhere).
        async def body(c):
            c.skip("old-NM advert/liveness internals (advertise_subs / initial-exchange slot / strike-death) retired by the netcore rewrite; covered by netcore membership/directory self-tests + wave-2")
            nm = _base_nm()
            nm.heartbeat_strikes = 2
            nm._heartbeat_misses = {}
            drop_calls: List[str] = []

            async def _stub_drop(host):
                drop_calls.append(host)

            nm._drop_peer_advert_state = _stub_drop  # type: ignore[assignment]

            class _Plexus:
                requests: Dict[str, Any] = {}

            nm.plexus = _Plexus()
            node = _StubNode("peer-B", enabled=True)

            # Miss 1/2: tolerated (below threshold), counter increments.
            r1 = await nm._record_heartbeat_miss(node)
            c.expect(r1, False)
            c.expect(nm._heartbeat_misses.get("peer-B"), 1)

            # Miss 2/2: threshold reached -> signal dead, counter cleared.
            r2 = await nm._record_heartbeat_miss(node)
            c.expect(r2, True)
            c.expect("peer-B" in nm._heartbeat_misses, False)

            # Mark dead: disable + drop advert state + (already-clear) counter.
            await nm._mark_node_dead(node)
            c.expect(node.enabled, False)
            c.expect(drop_calls, ["peer-B"])
            c.expect("peer-B" in nm._heartbeat_misses, False)

            # Idempotent: a second mark is a no-op (node already disabled),
            # so _drop_peer_advert_state is NOT called again.
            await nm._mark_node_dead(node)
            c.expect(node.enabled, False)
            c.expect(drop_calls, ["peer-B"])

        await rec.run_case(
            "networking.heartbeat_strikes_then_mark_node_dead",
            body,
            tags=("networking", "liveness"),
            bug_ids=("HUNT-092", "B-088"),
            category="networking",
            **kw,
        )
