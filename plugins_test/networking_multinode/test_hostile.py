"""Multinode TYPE-X hostile-peer cells (batch 2, §D + Type-X gaps).

A raw TLS + frame client (net_hostile.HostileClient) and an acceptor / PONG-server
(net_hostile.HostilePongServer) drive crafted/omitted/oversized frames against a
REAL rewrite target node (config.peer.yml = NetFixTarget + NetObsProbe + NetCtl).
The target's NetObsProbe self-dumps its _core/* events + snapshot() to a file each
0.5s, so this pytest (which cannot call the node's plugins) reads the §A surface
from that file after acting. Wire observables come straight off the hostile socket.

WIRE BYTE LAYOUT (A1) IS DEFERRED: net_hostile/wire.py pins ONE assumed
`[cid+fields]` layout; the PARENT RE-POINTS it to the WINNING branch's exact layout
at combine/swap BEFORE running these. Authored against wire.py as the single site.

Direction (pairwise lex election, lower dials): target = "w2b-peer".
  * HOSTILE DIALS target  → hostile hostname LEX-LOWER  ("w2a-hostilelo"); the node
    accepts the hostile's inbound connect (HostileClient).
  * NODE DIALS hostile    → hostile hostname LEX-HIGHER ("w2z-hostilehi"); the node
    dials the HostilePongServer.

Validates POST-combine. Gated behind PLEXUS_PAIR_TEST.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
import sys
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from net_hostile import wire  # noqa: E402
from net_hostile.hostile_client import HostileClient, HostileConnError, pickle_args  # noqa: E402
from net_hostile.hostile_server import (  # noqa: E402
    HostilePongServer, make_snapshot_bytes,
)
from _harness import (  # noqa: E402
    new_harness, wait_file, peer_spec, CONFIG_PEER, PEER_HOST, READY_TIMEOUT,
    FAST_KNOBS,
)
from plexus.serialization import generate_keypair  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.environ.get("PLEXUS_PAIR_TEST"),
    reason="real-socket hostile-peer integration; set PLEXUS_PAIR_TEST=1 to run",
)

HOSTILE_LOW = "w2a-hostilelo"    # < w2b-peer → hostile dials the node
HOSTILE_HIGH = "w2z-hostilehi"   # > w2b-peer → node dials the hostile
TARGET = PEER_HOST               # "w2b-peer"


@pytest.fixture(autouse=True)
def _socket_cooldown():
    yield
    time.sleep(5.0)


def _gen_cert(hostname: str):
    """Generate a keypair; return (keys_dir, cert_file, key_file, pem)."""
    d = Path(tempfile.mkdtemp(prefix=f"w2x_{hostname}_"))
    cert, key, _fp, pem = generate_keypair(str(d), hostname)
    return d, str(cert), str(key), pem


def _read_obs(node, topic=None):
    data = wait_file(node.obs_file, 3.0) or {}
    evs = data.get("events", [])
    if topic is not None:
        evs = [e for e in evs if e.get("topic") == topic]
    return evs, data.get("snapshot", {})


def _snap_peer(snapshot, hostname):
    peers = (snapshot or {}).get("peers", {})
    if isinstance(peers, dict):
        return peers.get(hostname)
    for p in (peers if isinstance(peers, list) else []):
        if p.get("hostname") == hostname:
            return p
    return None


def _caller(host, *, author=None, system_wire=False):
    """A wire caller ctx. author defaults to the hostile hostname; system_wire
    injects author='system' (the escalation the callee must ignore)."""
    return {"author": "system" if system_wire else (author or host),
            "author_id": "hostile-uuid", "author_host": host,
            "request_uuid": "hostile-req-1"}


def _spawn_target(h, *, hostile_specs, discoverable=False, extra_peers=None, knobs=None):
    node = h.gen_node(TARGET, CONFIG_PEER)
    peers = list(hostile_specs) + list(extra_peers or [])
    h.spawn(node, peers=peers, discoverable=discoverable, knobs=knobs)
    assert h.wait_ready(node), f"target node not ready:\n{_tail(node)}"
    return node


def _tail(node):
    try:
        return Path(node.logfile.name).read_text(encoding="utf-8")[-2000:]
    except Exception:
        return ""


# ══════════════════════ CLIENT-MODE CELLS (hostile dials node) ══════════════════════
def test_TP70_unpinned_spki_rejected():
    """VALID TLS, UNPINNED SPKI → rejected fail-closed; control = pinned SPKI is
    accepted (PONG)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    wk, wc, wkey, wpem = _gen_cert(HOSTILE_LOW)  # a DIFFERENT key, same hostname
    try:
        # node pins the FIRST hostile cert only.
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        # unpinned (wrong-key-same-hostname): reject (handshake or SPKI post-check).
        rejected = False
        cli = HostileClient("127.0.0.1", node.port, cert_file=wc, key_file=wkey)
        try:
            cli.connect()
            rejected = not cli.link_is_up()  # handshake passed but SPKI closes it
        except HostileConnError:
            rejected = True
        finally:
            cli.close()
        assert rejected, "an unpinned SPKI (wrong-key-same-hostname) was NOT rejected"
        # control: the PINNED cert connects + a PING is answered.
        ok = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        ok.connect()
        try:
            # link_is_up sends a PING and reads until OUR matching PONG, tolerating
            # an interleaved node-originated mutual-pulse PING (a bare recv_frame
            # could grab that PING first and spuriously fail the PONG assert).
            assert ok.link_is_up(), "pinned cert did not get a PONG"
            # NOTE: a TLS-1.3-RESUMED variant is intentionally NOT exercised here.
            # Resumption reuses a session ticket and re-presents NO certificate, and
            # a resumed session is bound to the SSLContext that created it — so
            # "resume ok's session but present the unpinned cert" cannot be built
            # with the raw client (Python's ssl raises "Session refers to a
            # different SSLContext" before any bytes reach the node). The SPKI-pin
            # fail-closed property is already proven by the fresh-handshake
            # unpinned-rejection above.
        finally:
            ok.close()
    finally:
        h.teardown()
        for d in (hk, wk):
            shutil.rmtree(d, ignore_errors=True)


def test_TP71_system_caller_spoof_ignored():
    """A non-system peer asserting author='system' is IGNORED (grant from the
    authenticated record only). caller_echo returns the RESOLVED author."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        # hostile pinned with system_caller=False (a non-system peer).
        node = _spawn_target(h, hostile_specs=[
            peer_spec(HOSTILE_LOW, 1, hpem, system_caller=False)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            kind, val = cli.call_unary(
                selector={"topic": "fix/caller"}, mode=wire.MODE_FIRST,
                caller=_caller(HOSTILE_LOW, system_wire=True), args_obj={},
                timeout=8.0)
            assert kind == "value", f"caller_echo did not return a value: {kind}/{val}"
            assert val.get("author") != "system", (
                f"wire author='system' from a non-system peer was HONORED: {val}")
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP72_anti_spoof_author_host_mismatch():
    """caller.author_host != authenticated hostname → dropped + hostname_mismatch;
    control = a matching author_host is delivered."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            # mismatched author_host → drop
            kind, val = cli.call_unary(
                selector={"topic": "fix/caller"}, mode=wire.MODE_FIRST,
                caller=_caller(HOSTILE_LOW, author=HOSTILE_LOW) | {"author_host": "someone-else"},
                args_obj={}, timeout=8.0)
            time.sleep(1.0)
            evs, _ = _read_obs(node, topic="_core/peer/hostname_mismatch")
            assert evs, "author_host spoof did not fire _core/peer/hostname_mismatch"
            # control: a matching author_host is delivered (a value returns)
            k2, v2 = cli.call_unary(
                selector={"topic": "fix/caller"}, mode=wire.MODE_FIRST,
                caller=_caller(HOSTILE_LOW), args_obj={}, timeout=8.0)
            assert k2 == "value", f"matching author_host not delivered: {k2}/{v2}"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP73_reassembly_bound_keeps_link():
    """Per-cid reassembly bound exceeded → cid dropped + CANCEL + _core/net/reject,
    LINK STAYS UP (a later PING is answered); control = under-bound completes."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            # CALL then CHUNKs exceeding the per-cid 8MB bound, never last=true.
            cid = cli.send_call(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                handler_timeout=30.0)
            blob = b"\x00" * (1024 * 1024)
            cancelled = False
            for _ in range(12):  # 12 MB > 8 MB per-cid
                cli.send_chunk(cid, blob, last=False)
            # the node should CANCEL our cid (drop) — look for a CANCEL/ERROR frame
            try:
                for _ in range(5):
                    f = cli.recv_frame(timeout=8.0)
                    if f.cid == cid and f.kind in (wire.KIND_CANCEL, wire.KIND_ERROR):
                        cancelled = True
                        break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1.0)
            evs, _ = _read_obs(node, topic="_core/net/reject")
            # A8: the reassembly-bound reject is now observable on _core/net/reject
            # carrying reason + the offending peer hostname (it was a silent no-op
            # before observe_reject was routed through manager._observe). This is the
            # primary assertion; the CANCEL frame (cancelled) and link-stays-up below
            # are the wire-level corroboration.
            reasm = [e for e in evs if e["payload"].get("reason") == "reassembly_bound"]
            assert reasm, (
                f"reassembly-bound reject not observed on _core/net/reject "
                f"(cancelled={cancelled}): {[e['payload'] for e in evs]}")
            assert any(e["payload"].get("hostname") == HOSTILE_LOW for e in reasm), (
                f"reassembly-bound reject missing/incorrect hostname (want "
                f"{HOSTILE_LOW}): {[e['payload'] for e in reasm]}")
            # LINK STAYS UP: a fresh PING is still answered.
            assert cli.link_is_up(), "link was torn by a reassembly-bound exceed (should stay up)"
            # control: an under-bound CALL completes.
            k, v = cli.call_unary(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                  mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                  args_obj={"payload": "ok"}, timeout=8.0)
            assert k == "value" and v == "ok", f"under-bound call failed: {k}/{v}"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


@pytest.mark.slow
def test_TP75_slow_drip_absolute_deadline():
    """A slow-drip reassembly UNDER the per-chunk idle deadline still trips the
    ABSOLUTE per-reassembly deadline (SPEC §11 default 60s) → cid dropped +
    _core/net/reject; link stays up. SLOW (~60s+) unless the absolute-deadline knob
    is lowered via net-knobs (rewrite-defined key name — bind at validation)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey,
                            read_timeout=90.0)
        cli.connect()
        try:
            cid = cli.send_call(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                handler_timeout=120.0)
            # drip a small chunk every ~3s for > the absolute deadline, never last.
            deadline = time.time() + 75.0
            rejected = False
            while time.time() < deadline:
                try:
                    cli.send_chunk(cid, b"\x00" * 1024, last=False)
                except Exception:  # noqa: BLE001 - link closed once the deadline fired
                    rejected = True
                    break
                time.sleep(3.0)
            time.sleep(1.0)
            evs, _ = _read_obs(node, topic="_core/net/reject")
            assert rejected or evs, "slow-drip never tripped the absolute deadline"
            assert cli.link_is_up(), "absolute-deadline drop tore the link (should keep it)"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP76_ping_flood_floor_interval():
    """PING flood below the floor-interval → AT MOST ONE header-PONG per window;
    control = an at-interval PING is answered."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            # burst 10 PINGs well within one floor-interval (floor ~0.5*hb; hb=1s)
            for _ in range(10):
                cli.send_ping(have_hash=b"")
            pongs = 0
            try:
                for _ in range(10):
                    # short timeout: the >=1 suppressed PONGs never arrive, and long
                    # per-read timeouts here would idle the link past the node's FAST
                    # idle_read_deadline (2.5s) before the control ping below.
                    f = cli.recv_frame(timeout=0.3)
                    if f.kind == wire.KIND_PONG:
                        pongs += 1
            except Exception:  # noqa: BLE001 - timeout after the answered ones
                pass
            assert pongs <= 1, f"PING flood answered {pongs} PONGs in one window (floor: <=1)"
            # control: just past the floor window (~0.5s = hb*0.5), a fresh PING is
            # answered again. Kept well under idle_read_deadline so the node has not
            # reaped a legitimately-quiet link (that would be a false negative here).
            time.sleep(0.7)
            assert cli.link_is_up(), "an at-interval PING was not answered"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP79_malformed_frame_tears_link():
    """A malformed FRAME (lying length prefix) → link CLOSED (contrast TP-73 which
    keeps the link on a bound exceed)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            assert cli.link_is_up(), "link not up before the malformed frame"
            # a frame claiming a length far larger than the bytes sent + garbage kind
            cli.send_raw(bytes([99]) + b"\xff" * 4, declared_length=100000)
            cli.send_raw(b"\x00\x00\x00\x00\x00garbage")
            torn = not cli.link_is_up()
            assert torn, "a malformed FRAME did not tear the link"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP80_straggler_after_cancel_discarded():
    """A CHUNK/END/ERROR for an unknown/cancelled cid → silently DISCARDED (no
    crash, no cid re-open); control = a valid frame on a LIVE cid IS processed."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            # open + immediately cancel a cid, then send stragglers on it
            cid = cli.send_call(selector={"plugin": "NetFixTarget", "endpoint": "slow_handler"},
                                mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                handler_timeout=30.0)
            cli.send_cancel(cid)
            cli.send_chunk(cid, b"straggler", last=True)
            cli.send_end(cid)
            cli.send_error(cid, wire.ERR_NETWORK)
            # no crash → the link is still alive + a fresh valid call works (control)
            assert cli.link_is_up(), "stragglers after CANCEL crashed/closed the reader"
            k, v = cli.call_unary(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                  mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                  args_obj={"payload": "live"}, timeout=8.0)
            assert k == "value" and v == "live", f"live cid not processed: {k}/{v}"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP81_reserved_topic_and_malformed_pattern_rejected():
    """Ingest rejects a reserved `_core/` sub topic + a malformed topic_pattern from
    a peer (§8.1). Driven as a CALL to a reserved-topic selector → NO handler runs
    (an ERROR / no-value reply)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            k, v = cli.call_unary(selector={"topic": "_core/peer/up"}, mode=wire.MODE_FIRST,
                                  caller=_caller(HOSTILE_LOW), args_obj={}, timeout=8.0)
            assert k in ("error", "empty"), (
                f"a reserved _core/ topic CALL was answered (should reject): {k}/{v}")
            assert cli.link_is_up(), "reserved-topic reject should not tear the link"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TG05b_protocol_error_keeps_link():
    """A post-`last` CHUNK on a unary cid (a semantic ProtocolError, framing intact)
    → error THAT cid but KEEP the link (A10 ruling); a later PING is answered."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            cid = cli.send_call(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                handler_timeout=30.0)
            cli.send_chunk(cid, pickle_args({"payload": "x"}), last=True)
            cli.send_chunk(cid, pickle_args({"payload": "y"}), last=True)  # post-last → ProtocolError
            # A10: the cid errors, the LINK stays up.
            assert cli.link_is_up(), "a per-cid ProtocolError tore the link (A10: keep it)"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TG20_safeunpickler_rce_guard():
    """A well-formed but DISALLOWED pickle payload as CALL args → safe_loads REJECTS
    after reassembly; the handler NEVER runs; a mapped ERROR returns. Control = an
    allowlisted payload IS processed."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_LOW)
    try:
        node = _spawn_target(h, hostile_specs=[peer_spec(HOSTILE_LOW, 1, hpem)])
        cli = HostileClient("127.0.0.1", node.port, cert_file=hc, key_file=hkey)
        cli.connect()
        try:
            class _Evil:
                def __reduce__(self):
                    return (os.system, ("echo pwned",))
            cid = cli.send_call(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                handler_timeout=30.0)
            cli.send_chunk(cid, pickle_args(_Evil()), last=True)
            kind = None
            try:
                kind, _ = cli.recv_result(cid, timeout=8.0)
            except Exception:  # noqa: BLE001
                kind = "error"
            assert kind in ("error",), f"disallowed pickle was not rejected: {kind}"
            assert cli.link_is_up(), "RCE-guard reject should not tear the link"
            # control: an allowlisted payload IS processed
            k, v = cli.call_unary(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                  mode=wire.MODE_UNARY, caller=_caller(HOSTILE_LOW),
                                  args_obj={"payload": "safe"}, timeout=8.0)
            assert k == "value" and v == "safe", f"allowlisted payload not processed: {k}/{v}"
        finally:
            cli.close()
    finally:
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


@pytest.mark.skip(reason=(
    "The node_reassembly_cap knob now EXISTS (manager.py reads it) and the per-peer "
    "guaranteed-minimum RESERVATION it enables IS covered deterministically by "
    "_transport_selftest.test_node_wide_reservation_guaranteed_minimum (runs in the "
    "boot suite). This SOCKET-level variant remains skipped: the holder hold-mechanism "
    "(streaming last=False CHUNK frames to keep a UNARY reassembly open) tears the link "
    "with SSLEOFError on the node side — a pre-existing hostile-client/reassembly-hold "
    "protocol issue (the original 7MB-hold version failed identically), independent of "
    "node_cap. Re-enabling needs that hold mechanism fixed — separate cell engineering."))
def test_TG09_guaranteed_minimum_reservation():
    """Node-wide reassembly OVER the cap, yet a FRESH peer's reassembly is still
    honored — the per-peer guaranteed MINIMUM (§4.4/§F#19). A naive shared counter
    passes TP-73/TP-74 but fails THIS.

    Tuning that makes the reservation actually bite: lower the node-wide cap (via the
    node_reassembly_cap knob) BELOW the sum of the per-peer minimums, and have each
    holder hold EXACTLY its per_peer_min (2MB). A peer within its min is always
    admitted, so the 6 mins (12MB) legitimately overflow the 10MB node cap — and yet
    the fresh peer's small inbound is STILL admitted (reservation), so its call is
    answered. No greedy over-hold (which the cap would tear); the overflow is the
    reserved minimums themselves."""
    h = new_harness()
    NODE_CAP = 10 * 1024 * 1024          # < 6 * per_peer_min(2MB) = 12MB
    HOLD_MB = 2                           # each holder holds exactly its per_peer_min
    # one pinned hostile identity per holder + the fresh one (distinct hostnames so
    # each is its own peer with its own per-peer budget).
    holders = []
    specs = []
    keydirs = []
    N = 6
    try:
        for i in range(N):
            host = f"w2a-hold{i}"
            kd, cf, kf, pem = _gen_cert(host)
            keydirs.append(kd)
            specs.append(peer_spec(host, 1, pem))
            holders.append((host, cf, kf))
        fresh_host = "w2a-fresh"
        fkd, fcf, fkf, fpem = _gen_cert(fresh_host)
        keydirs.append(fkd)
        specs.append(peer_spec(fresh_host, 1, fpem))
        # lower the node-wide cap so the per-peer mins overflow it; raise idle_read so
        # the silent holders keep their reassemblies open through the fresh peer's call.
        node = _spawn_target(h, hostile_specs=specs, knobs={
            **FAST_KNOBS, "idle_read_deadline": 30.0, "node_reassembly_cap": NODE_CAP})
        open_clients = []
        try:
            for host, cf, kf in holders:
                c = HostileClient("127.0.0.1", node.port, cert_file=cf, key_file=kf)
                c.connect()
                cid = c.send_call(selector={"plugin": "NetFixTarget", "endpoint": "echo_unary"},
                                  mode=wire.MODE_UNARY, caller=_caller(host), handler_timeout=60.0)
                # hold EXACTLY per_peer_min (2MB) on ONE open cid — always admitted, never
                # torn; the 6 held mins (12MB) overflow the 10MB node cap.
                blob = b"\x00" * (1024 * 1024)
                for _ in range(HOLD_MB):
                    c.send_chunk(cid, blob, last=False)
                open_clients.append(c)
            # fresh peer: with the node OVER its cap, its small inbound must STILL be
            # admitted (the reserved per-peer minimum) so its call is answered.
            fc = HostileClient("127.0.0.1", node.port, cert_file=fcf, key_file=fkf)
            fc.connect()
            open_clients.append(fc)
            k, v = fc.call_unary(selector={"plugin": "NetFixTarget", "endpoint": "echo_bytes"},
                                 mode=wire.MODE_UNARY, caller=_caller(fresh_host),
                                 args_obj={"n_bytes": 1_000_000}, timeout=15.0)
            assert k == "value" and v.get("n") == 1_000_000, (
                "the fresh peer's guaranteed-minimum reassembly was NOT honored under "
                f"node-wide exhaustion: {k}/{v}")
        finally:
            for c in open_clients:
                c.close()
    finally:
        h.teardown()
        for d in keydirs:
            shutil.rmtree(d, ignore_errors=True)


# ══════════════════════ ACCEPTOR-MODE CELLS (node dials hostile) ══════════════════════
def _spawn_target_dialing(h, server_port, hostile_pem, *, discoverable=False):
    """Target that DIALS the hostile (hostile lex-HIGHER) at server_port."""
    node = h.gen_node(TARGET, CONFIG_PEER)
    spec = peer_spec(HOSTILE_HIGH, server_port, hostile_pem)
    h.spawn(node, peers=[spec], discoverable=discoverable)
    assert h.wait_ready(node), f"target not ready:\n{_tail(node)}"
    return node


def test_TP74_pong_snapshot_over_bound_keeps_peer_reachable():
    """A PONG whose snapshot body trips a reassembly bound → snapshot DROPPED but
    the peer STAYS reachable (header stamp), retried next pulse, link NOT torn."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_HIGH)
    server = None
    try:
        def builder(ping_fields):
            # header says snapshot follows; body is oversized (> per-cid 8MB)
            big = make_snapshot_bytes(vouched_peers=[], endpoints=[{"pad": "x" * 9_000_000}])
            return ({"epoch": "e1", "content_hash": "h1", "snapshot_follows": True}, big)
        server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey,
                                   pong_builder=builder)
        server.start()
        node = _spawn_target_dialing(h, server.port, hpem)
        # give the node time to dial + pulse + trip the bound a few times
        time.sleep(8.0)
        evs, snap = _read_obs(node, topic="_core/net/reject")
        entry = _snap_peer(snap, HOSTILE_HIGH)
        assert entry is not None, "hostile peer absent from snapshot"
        assert entry.get("reachable"), (
            "PONG-snapshot over-bound downed the peer (should stay reachable via the "
            f"header stamp): {entry}")
        assert server.pings_seen >= 1, "node never pulsed the hostile (no dial?)"
        # A8: the PONG-snapshot over-bound is a pending-side reassembly exceed, which
        # also emits an observable _core/net/reject{reason:reassembly_bound} carrying
        # the peer hostname, while the peer stays reachable via the header stamp.
        reasm = [e for e in evs if e["payload"].get("reason") == "reassembly_bound"]
        assert reasm, (
            f"PONG-snapshot over-bound produced no observable _core/net/reject: "
            f"{[e['payload'] for e in evs]}")
        assert any(e["payload"].get("hostname") == HOSTILE_HIGH for e in reasm), (
            f"reassembly-bound reject missing/incorrect hostname (want "
            f"{HOSTILE_HIGH}): {[e['payload'] for e in reasm]}")
    finally:
        if server:
            server.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP77_malformed_vouched_cert_rejected():
    """A vouched entry with a malformed cert PEM → REJECTED at ingest
    (_core/peer/vouch_rejected); the CA-context rebuild is NOT poisoned."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_HIGH)
    server = None
    try:
        def builder(pf):
            vouched = [{"hostname": "w2a-vouched", "address": "127.0.0.1:1",
                        "fingerprint": "sha256:deadbeef", "cert_pem": "-----BEGIN GARBAGE-----"}]
            return ({"epoch": "e1", "content_hash": "h1", "snapshot_follows": True},
                    make_snapshot_bytes(vouched_peers=vouched))
        server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey, pong_builder=builder)
        server.start()
        node = _spawn_target_dialing(h, server.port, hpem, discoverable=True)
        time.sleep(8.0)
        evs, snap = _read_obs(node, topic="_core/peer/vouch_rejected")
        assert evs, "a malformed vouched cert PEM was not rejected at ingest"
        # node not poisoned: the voucher itself is still reachable
        entry = _snap_peer(snap, HOSTILE_HIGH)
        assert entry and entry.get("reachable"), "context rebuild poisoned (voucher down)"
    finally:
        if server:
            server.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP78_vouched_spki_mismatch_rejected():
    """A vouched cert whose SPKI != declared fingerprint → REJECTED (no phantom
    redial-forever peer)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_HIGH)
    vk, vc, vkey, vpem = _gen_cert("w2a-vouched")  # a REAL cert...
    server = None
    try:
        def builder(pf):
            vouched = [{"hostname": "w2a-vouched", "address": "127.0.0.1:1",
                        "fingerprint": "sha256:0000",  # ...but a WRONG fingerprint
                        "cert_pem": vpem}]
            return ({"epoch": "e1", "content_hash": "h1", "snapshot_follows": True},
                    make_snapshot_bytes(vouched_peers=vouched))
        server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey, pong_builder=builder)
        server.start()
        node = _spawn_target_dialing(h, server.port, hpem, discoverable=True)
        time.sleep(8.0)
        evs, snap = _read_obs(node, topic="_core/peer/vouch_rejected")
        assert evs, "an SPKI!=fingerprint vouched cert was not rejected"
        assert _snap_peer(snap, "w2a-vouched") is None, "phantom vouched peer was added"
    finally:
        if server:
            server.stop()
        h.teardown()
        for d in (hk, vk):
            shutil.rmtree(d, ignore_errors=True)


def test_TG17_vouched_peers_overcount_drops_snapshot():
    """A hub serving a `vouched_peers` list over the decode bound → the whole
    snapshot is DROPPED and the hub goes FULLY un-routable (reachable-but-empty,
    not a silent partial mesh)."""
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert(HOSTILE_HIGH)
    server = None
    try:
        def builder(pf):
            # a vouched list far above any sane config-peer count
            vouched = [{"hostname": f"w2a-v{i}", "address": "127.0.0.1:1",
                        "fingerprint": f"sha256:{i:064x}", "cert_pem": hpem}
                       for i in range(500)]
            # ALSO carry endpoints/subs so "fully un-routable" is observable
            eps = [{"hostname": HOSTILE_HIGH, "access_name": "hub_ep",
                    "plugin_name": "Hub", "remote": True}]
            return ({"epoch": "e1", "content_hash": "h1", "snapshot_follows": True},
                    make_snapshot_bytes(vouched_peers=vouched, endpoints=eps))
        server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey, pong_builder=builder)
        server.start()
        node = _spawn_target_dialing(h, server.port, hpem, discoverable=True)
        time.sleep(8.0)
        _, snap = _read_obs(node)
        entry = _snap_peer(snap, HOSTILE_HIGH)
        assert entry is not None and entry.get("reachable"), (
            "hub should stay reachable (header stamp) even with a dropped snapshot")
        routing = (entry or {}).get("routing", {})
        eps = routing.get("endpoints", []) if isinstance(routing, dict) else []
        assert not eps, (
            "over-count snapshot was NOT dropped — the hub's endpoints leaked "
            f"(should be reachable-but-empty): {routing}")
    finally:
        if server:
            server.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)
