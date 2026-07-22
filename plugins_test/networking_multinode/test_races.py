"""Multinode RACE cells (batch 2, §E) — fault-injected against a real driver node.

Injectable-black-box races: the driver node (MultinodeDriver, lifecycle group) drives
the mutation (remove_peer / observes reachability) while this pytest runs the fault
injector that opens the race window:
  * TP-38 revoke-during-ping-await → a HostilePongServer with pong_delay (the
    pulse-await stays open across the revoke; the delayed PONG's resume-stamp must
    be roster-gated).
  * TP-46 remove-mid-dial → a StallListener (accepts TCP, never completes TLS →
    the node hangs in dial); remove during the dial → no ghost link.
  * TP-51 pulse survives one poisoned peer → a poison HostilePongServer (malformed
    reply to every PING) alongside a cooperative peer that must keep pulsing.
Plus the cooperative revoke/re-add/refused topology follow-ups (TP-37/41, TG-04).

TP-48 (removed-voucher in-flight snapshot) and TP-49 (flap-guard no-tear) are
WHITE-BOX (§F) — see BATCH2_FCASES.md; they have no injectable §A observable.

Direction: driver = "w2a-driver" (lex-lowest) → it dials every peer. Injector
hostnames are all lex-HIGHER so the driver dials them. Validates POST-combine.
Gated behind PLEXUS_PAIR_TEST.
"""
from __future__ import annotations

import json
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

from net_hostile.hostile_server import HostilePongServer  # noqa: E402
from net_hostile.hostile_client import StallListener  # noqa: E402
from _harness import (  # noqa: E402
    new_harness, wait_file, tail, peer_spec, free_port,
    CONFIG_DRIVER, CONFIG_PEER, CONFIG_PEER2, DRIVER_HOST, PEER_HOST, PEER2_HOST,
    RESULT_TIMEOUT,
)
from plexus.serialization import generate_keypair  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.environ.get("PLEXUS_PAIR_TEST"),
    reason="real-socket race integration; set PLEXUS_PAIR_TEST=1 to run",
)


@pytest.fixture(autouse=True)
def _socket_cooldown():
    yield
    time.sleep(5.0)


def _gen_cert(hostname):
    d = Path(tempfile.mkdtemp(prefix=f"w2r_{hostname}_"))
    cert, key, _fp, pem = generate_keypair(str(d), hostname)
    return d, str(cert), str(key), pem


def _tail_log(node):
    try:
        return tail(node.logfile.name)  # type: ignore[attr-defined]
    except Exception:
        return ""


def _assert_driver(node, label):
    res = wait_file(node.result_file, RESULT_TIMEOUT)
    assert res is not None, f"{label}: no driver result\n{_tail_log(node)}"
    bad = [c for c in res.get("cases", []) if c["status"] in ("fail", "error")]
    if bad:
        detail = "\n".join(f"  {c['id']} [{c['status']}]: {c.get('detail')}" for c in bad)
        pytest.fail(f"{label}: cell failed:\n{detail}\n{_tail_log(node)}")
    assert any(c["status"] == "pass" for c in res.get("cases", [])), (
        f"{label}: no cell passed (vacuous)")


def test_TP38_revoke_during_ping_await():
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert("w2d-delay")
    server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey, pong_delay=6.0)
    try:
        server.start()
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        h.spawn(drv, peers=[peer_spec("w2d-delay", server.port, hpem)],
                group="lifecycle", cell="TP-38", wants_result=True)
        assert h.wait_ready(drv), f"driver not ready\n{_tail_log(drv)}"
        _assert_driver(drv, "TP-38")
    finally:
        server.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP46_remove_mid_dial():
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert("w2s-stall")
    stall = StallListener("127.0.0.1", 0)  # accepts TCP, never completes TLS
    try:
        stall.start()
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        h.spawn(drv, peers=[peer_spec("w2s-stall", stall.port, hpem)],
                group="lifecycle", cell="TP-46", wants_result=True)
        assert h.wait_ready(drv), f"driver not ready\n{_tail_log(drv)}"
        _assert_driver(drv, "TP-46")
    finally:
        stall.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP51_pulse_survives_poison():
    h = new_harness()
    hk, hc, hkey, hpem = _gen_cert("w2p-poison")
    server = HostilePongServer("127.0.0.1", 0, cert_file=hc, key_file=hkey, poison=True)
    try:
        server.start()
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        coop = h.gen_node(PEER_HOST, CONFIG_PEER)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        # coop pins ONLY the driver; driver pins [coop, poison] (coop FIRST).
        h.spawn(coop, peers=[d])
        assert h.wait_ready(coop), f"coop not ready\n{_tail_log(coop)}"
        h.spawn(drv, peers=[peer_spec(PEER_HOST, coop.port, coop.cert_pem),
                            peer_spec("w2p-poison", server.port, hpem)],
                group="lifecycle", cell="TP-51", wants_result=True)
        assert h.wait_ready(drv), f"driver not ready\n{_tail_log(drv)}"
        _assert_driver(drv, "TP-51")
    finally:
        server.stop()
        h.teardown()
        shutil.rmtree(hk, ignore_errors=True)


def test_TP37_revoke_stays_gone():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        p1 = h.gen_node(PEER_HOST, CONFIG_PEER)
        p2 = h.gen_node(PEER2_HOST, CONFIG_PEER2)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        h.spawn(p1, peers=[d])
        h.spawn(p2, peers=[d])
        assert h.wait_ready(p1) and h.wait_ready(p2)
        # driver pins [p1 (removed), p2 (kept control)]
        h.spawn(drv, peers=[peer_spec(PEER_HOST, p1.port, p1.cert_pem),
                            peer_spec(PEER2_HOST, p2.port, p2.cert_pem)],
                group="lifecycle", cell="TP-37", wants_result=True)
        assert h.wait_ready(drv)
        _assert_driver(drv, "TP-37")
    finally:
        h.teardown()


def test_TP41_operator_readd():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        p1 = h.gen_node(PEER_HOST, CONFIG_PEER)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        h.spawn(p1, peers=[d])
        assert h.wait_ready(p1)
        p1_spec = peer_spec(PEER_HOST, p1.port, p1.cert_pem)
        readd = h.tmp / "readd_spec.json"
        readd.write_text(json.dumps(p1_spec), encoding="utf-8")
        h.spawn(drv, peers=[p1_spec], group="lifecycle", cell="TP-41",
                wants_result=True, extra_args=["--readd-spec", str(readd)])
        assert h.wait_ready(drv)
        _assert_driver(drv, "TP-41")
    finally:
        h.teardown()


def test_TG04_linkrefused_fast_path():
    h = new_harness()
    dk, dc, dkey, dpem = _gen_cert("w2x-dead")
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        steady = h.gen_node(PEER_HOST, CONFIG_PEER)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        h.spawn(steady, peers=[d])
        assert h.wait_ready(steady)
        dead_port = free_port()  # nothing ever listens here → connection REFUSED
        # driver pins [steady, dead]
        h.spawn(drv, peers=[peer_spec(PEER_HOST, steady.port, steady.cert_pem),
                            peer_spec("w2x-dead", dead_port, dpem)],
                group="lifecycle", cell="TG-04", wants_result=True)
        assert h.wait_ready(drv)
        _assert_driver(drv, "TG-04")
    finally:
        h.teardown()
        shutil.rmtree(dk, ignore_errors=True)
