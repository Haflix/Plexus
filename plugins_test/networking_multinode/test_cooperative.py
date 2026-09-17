"""Multinode COOPERATIVE socket cells (batch 1) — real multi-node acceptance net.

Boots real rewrite nodes (driver + 1-2 peers) via node.py, drives the
cooperative multinode cells through MultinodeDriver (which asserts the §A public surface
and writes a CaseRecorder result), and fails the pytest if any cell fails/errors.

Topology per group (see _harness): pair (2 mesh), trio_mesh (3 mesh), star
(driver pins only the hub), discovery (discoverable + hub vouches peer2). Lifecycle
cells are phase-coordinated: the driver signals a phase, this test kills/respawns/
supplies the peer, the driver continues.

Validates against the winning rewrite POST-COMBINE (no rewrite is deployed yet).
Gated behind PLEXUS_PAIR_TEST so a blanket `pytest plugins_test/` never boots real
nodes. Run explicitly:
    PLEXUS_PAIR_TEST=1 python -m pytest plugins_test/networking_multinode/
"""
from __future__ import annotations

import os
import time

import pytest

from _harness import (
    Harness, new_harness, wait_file, wait_phase, tail, peer_spec,
    CONFIG_DRIVER, CONFIG_PEER, CONFIG_PEER2, CONFIG_PEER_CHANGED,
    DRIVER_HOST, PEER_HOST, PEER2_HOST, RESULT_TIMEOUT, READY_TIMEOUT,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("PLEXUS_PAIR_TEST"),
    reason="real-socket multi-node integration; set PLEXUS_PAIR_TEST=1 to run",
)


@pytest.fixture(autouse=True)
def _socket_cooldown():
    yield
    time.sleep(5.0)


def _assert_driver_result(node, label: str):
    res = wait_file(node.result_file, RESULT_TIMEOUT)
    assert res is not None, (
        f"{label}: driver wrote no result within {RESULT_TIMEOUT}s\n"
        f"--- driver log ---\n{tail_log(node)}")
    bad = [c for c in res.get("cases", []) if c["status"] in ("fail", "error")]
    if bad:
        detail = "\n".join(
            f"  {c['id']} [{c['status']}]: {c.get('detail')}" for c in bad)
        pytest.fail(f"{label}: {len(bad)} cell(s) failed:\n{detail}\n"
                    f"--- driver log ---\n{tail_log(node)}")
    # Require at least one non-skipped pass so a boot that silently ran nothing
    # (all skips) does not green vacuously.
    passed = [c for c in res.get("cases", []) if c["status"] == "pass"]
    assert passed, f"{label}: no cell passed (all skipped?) — vacuous run"
    return res


def tail_log(node):
    try:
        return tail(node.logfile.name)  # type: ignore[attr-defined]
    except Exception:
        return ""


# ─────────────────────────── group boots ───────────────────────────
def test_pair_group():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)
        h.spawn(peer, peers=[peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)])
        h.spawn(drv, peers=[peer_spec(PEER_HOST, peer.port, peer.cert_pem)],
                group="pair", wants_result=True)
        assert h.wait_ready(peer), f"peer not ready\n{tail_log(peer)}"
        assert h.wait_ready(drv), f"driver not ready\n{tail_log(drv)}"
        _assert_driver_result(drv, "pair")
    finally:
        h.teardown()


def test_trio_mesh_group():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)
        peer2 = h.gen_node(PEER2_HOST, CONFIG_PEER2)
        specs = {
            DRIVER_HOST: peer_spec(DRIVER_HOST, drv.port, drv.cert_pem),
            PEER_HOST: peer_spec(PEER_HOST, peer.port, peer.cert_pem),
            PEER2_HOST: peer_spec(PEER2_HOST, peer2.port, peer2.cert_pem),
        }
        h.spawn(peer, peers=[specs[DRIVER_HOST], specs[PEER2_HOST]])
        h.spawn(peer2, peers=[specs[DRIVER_HOST], specs[PEER_HOST]])
        h.spawn(drv, peers=[specs[PEER_HOST], specs[PEER2_HOST]],
                group="trio_mesh", wants_result=True)
        for n in (peer, peer2, drv):
            assert h.wait_ready(n), f"{n.hostname} not ready\n{tail_log(n)}"
        _assert_driver_result(drv, "trio_mesh")
    finally:
        h.teardown()


def test_star_group():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)      # hub
        peer2 = h.gen_node(PEER2_HOST, CONFIG_PEER2)   # unpinned leaf
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        p = peer_spec(PEER_HOST, peer.port, peer.cert_pem)
        p2 = peer_spec(PEER2_HOST, peer2.port, peer2.cert_pem)
        h.spawn(peer, peers=[d, p2])       # hub pins both
        h.spawn(peer2, peers=[p])          # leaf pins only hub
        h.spawn(drv, peers=[p], group="star", wants_result=True)  # driver pins only hub
        for n in (peer, peer2, drv):
            assert h.wait_ready(n), f"{n.hostname} not ready\n{tail_log(n)}"
        _assert_driver_result(drv, "star")
    finally:
        h.teardown()


def test_discovery_group():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)      # hub, config-origin lists peer2
        peer2 = h.gen_node(PEER2_HOST, CONFIG_PEER2)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        p = peer_spec(PEER_HOST, peer.port, peer.cert_pem)
        p2 = peer_spec(PEER2_HOST, peer2.port, peer2.cert_pem)
        h.spawn(peer, peers=[d, p2], discoverable=True)   # hub vouches driver+peer2
        h.spawn(peer2, peers=[p], discoverable=True)
        # driver pins ONLY the hub + discoverable → learns peer2 via the hub's vouch
        h.spawn(drv, peers=[p], group="discovery", discoverable=True, wants_result=True)
        for n in (peer, peer2, drv):
            assert h.wait_ready(n), f"{n.hostname} not ready\n{tail_log(n)}"
        _assert_driver_result(drv, "discovery")
    finally:
        h.teardown()


# ─────────────────────────── lifecycle cells ───────────────────────────
def _run_lifecycle(h: Harness, cell: str, *, peer_up_first: bool,
                   phase_reactor, reload_config=None):
    drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
    peer = h.gen_node(PEER_HOST, CONFIG_PEER)
    d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
    p = peer_spec(PEER_HOST, peer.port, peer.cert_pem)
    if peer_up_first:
        h.spawn(peer, peers=[d])
        assert h.wait_ready(peer), f"peer not ready\n{tail_log(peer)}"
    h.spawn(drv, peers=[p], group="lifecycle", cell=cell, wants_result=True,
            wants_phase=True, reload_config=reload_config)
    assert h.wait_ready(drv), f"driver not ready\n{tail_log(drv)}"
    # React to phase signals until the driver writes its result.
    phase_reactor(h, drv, peer, d, p)
    return _assert_driver_result(drv, cell)


def test_TP08_offline_at_boot():
    h = new_harness()
    try:
        def reactor(h, drv, peer, d, p):
            # driver runs first with NO peer up; on "spawn-peer" boot the peer.
            if wait_phase(drv.phase_file, "spawn-peer", 60.0):
                h.spawn(peer, peers=[d])
                h.wait_ready(peer)
        _run_lifecycle(h, "TP-08", peer_up_first=False, phase_reactor=reactor)
    finally:
        h.teardown()


def test_TP09_drop_reconnect():
    h = new_harness()
    try:
        def reactor(h, drv, peer, d, p):
            if wait_phase(drv.phase_file, "kill-peer", 60.0):
                h.kill(peer)
                drv.phase_file.write_text("kill-peer-done", encoding="utf-8")
            if wait_phase(drv.phase_file, "respawn-peer", 60.0):
                # respawn same identity (same keys_dir + port)
                h.spawn(peer, peers=[d])
                h.wait_ready(peer)
        _run_lifecycle(h, "TP-09", peer_up_first=True, phase_reactor=reactor)
    finally:
        h.teardown()


def test_A5_silent_death():
    # A5 empirical tiebreaker: SUSPEND the peer (no TCP RST = true silent death) while a
    # cross-node request is in flight, and confirm the transport idle-read teardown
    # fast-fails it (~idle_read_deadline) instead of hanging. (Windows-only suspend.)
    import ctypes
    def _suspend(pid):
        PROCESS_SUSPEND_RESUME = 0x0800
        hp = ctypes.windll.kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
        assert hp, f"OpenProcess failed for pid {pid}"
        try:
            ctypes.windll.ntdll.NtSuspendProcess(hp)
        finally:
            ctypes.windll.kernel32.CloseHandle(hp)
    h = new_harness()
    try:
        def reactor(h, drv, peer, d, p):
            if wait_phase(drv.phase_file, "suspend-peer", 60.0):
                _suspend(peer.proc.pid)
        res = _run_lifecycle(h, "A5-silentdeath", peer_up_first=True, phase_reactor=reactor)
        for c in res.get("cases", []):
            print(f"\n[A5-RESULT] {c['id']} status={c['status']} marker={c.get('marker')}")
    finally:
        h.teardown()


def test_TP11_in_flight_during_down():
    h = new_harness()
    try:
        def reactor(h, drv, peer, d, p):
            if wait_phase(drv.phase_file, "kill-peer", 60.0):
                h.kill(peer)
        _run_lifecycle(h, "TP-11", peer_up_first=True, phase_reactor=reactor)
    finally:
        h.teardown()


def _reboot_reactor(changed: bool):
    def reactor(h, drv, peer, d, p):
        want = "reboot-changed" if changed else "reboot-same"
        if wait_phase(drv.phase_file, want, 60.0):
            h.kill(peer)
            time.sleep(1.0)
            # respawn SAME identity; changed → the extra-plugin config
            peer.config = CONFIG_PEER_CHANGED if changed else CONFIG_PEER
            h.spawn(peer, peers=[d])
            h.wait_ready(peer)
            drv.phase_file.write_text("reboot-done", encoding="utf-8")
    return reactor


def test_TP30_reboot_same_content():
    h = new_harness()
    try:
        _run_lifecycle(h, "TP-30", peer_up_first=True, phase_reactor=_reboot_reactor(False))
    finally:
        h.teardown()


def test_TP31_reboot_diff_content():
    h = new_harness()
    try:
        _run_lifecycle(h, "TP-31", peer_up_first=True, phase_reactor=_reboot_reactor(True))
    finally:
        h.teardown()


def test_TP14_hot_swap():
    h = new_harness()
    try:
        _run_lifecycle(h, "TP-14", peer_up_first=True, phase_reactor=_reboot_reactor(True))
    finally:
        h.teardown()


# ─────────────────── reload cells (self-reload, no phase) ───────────────────
def _write_reload_config(h: Harness, base_config, peer_spec_dict, keys_dir) -> "Path":
    """Write a self-contained reload config: the driver's plugin set + networking
    with the peer BAKED IN + a rebuild-trigger key (discoverable) flipped, so
    async_load_config_yaml re-processes networking. peers baked in so the reload
    does not hit the empty-peers hard error. `keys_dir` is baked in too: the live
    node was RUNTIME-injected a keys_dir via --keys-dir (which never lands in the
    reload file), so without this the rebuilt NM would default to `config_dir/keys`,
    generate a NEW identity, and the peer (pinning the old cert) would refuse it.
    `port` is deliberately NOT baked to the live value — the reload's `port` (0)
    vs the live free-port is the DIFF that TRIGGERS the rebuild."""
    import yaml  # PyYAML ships with the framework
    from pathlib import Path
    cfg = yaml.safe_load(Path(base_config).read_text(encoding="utf-8"))
    cfg.setdefault("networking", {})
    cfg["networking"]["enabled"] = True
    cfg["networking"]["discoverable"] = True  # rebuild-trigger flip
    cfg["networking"]["peers"] = [peer_spec_dict]
    cfg["networking"]["keys_dir"] = str(keys_dir)  # preserve the runtime-injected identity
    out = h.tmp / "reload_driver.yml"
    out.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return out


def test_TP39_revoke_durability():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        p = peer_spec(PEER_HOST, peer.port, peer.cert_pem)
        reload_cfg = _write_reload_config(h, CONFIG_DRIVER, p, drv.keys_dir)
        h.spawn(peer, peers=[d])
        assert h.wait_ready(peer)
        h.spawn(drv, peers=[p], group="lifecycle", cell="TP-39", wants_result=True,
                wants_phase=True, reload_config=reload_cfg)
        assert h.wait_ready(drv)
        _assert_driver_result(drv, "TP-39")
    finally:
        h.teardown()


def test_TG14_reconfigure_during_inflight():
    h = new_harness()
    try:
        drv = h.gen_node(DRIVER_HOST, CONFIG_DRIVER)
        peer = h.gen_node(PEER_HOST, CONFIG_PEER)
        d = peer_spec(DRIVER_HOST, drv.port, drv.cert_pem)
        p = peer_spec(PEER_HOST, peer.port, peer.cert_pem)
        reload_cfg = _write_reload_config(h, CONFIG_DRIVER, p, drv.keys_dir)
        h.spawn(peer, peers=[d])
        assert h.wait_ready(peer)
        h.spawn(drv, peers=[p], group="lifecycle", cell="TG-14", wants_result=True,
                wants_phase=True, reload_config=reload_cfg)
        assert h.wait_ready(drv)
        _assert_driver_result(drv, "TG-14")
    finally:
        h.teardown()


# ─────────────────────────── P-cells (boot behavior) ───────────────────────────
def test_TP15_own_keypair_mismatch_boot_abort():
    """own cert.pem ↔ key.pem mismatch → LOUD boot abort; control = matched boots."""
    from plexus.serialization import generate_keypair
    import tempfile, shutil, subprocess, sys
    from pathlib import Path
    from _harness import NODE_SCRIPT, CONFIG_PEER, REPO_ROOT, free_port
    tmp = Path(tempfile.mkdtemp(prefix="w2_tp15_"))
    keys = Path(tempfile.mkdtemp(prefix="w2_tp15_keys_"))
    other = Path(tempfile.mkdtemp(prefix="w2_tp15_other_"))
    try:
        generate_keypair(str(keys), "w2b-peer")
        generate_keypair(str(other), "w2b-peer")
        # Swap in a MISMATCHED key.pem (different keypair) → boot must abort loud.
        (keys / "key.pem").write_text((other / "key.pem").read_text(encoding="utf-8"),
                                      encoding="utf-8")
        ready = tmp / "ready.json"
        peers = tmp / "peers.json"
        peers.write_text("[]", encoding="utf-8")
        log = tmp / "boot.log"
        lf = open(log, "w", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(NODE_SCRIPT), "--config", str(CONFIG_PEER),
             "--port", str(free_port()), "--ready-file", str(ready),
             "--keys-dir", str(keys), "--peers-file", str(peers)],
            cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT)
        try:
            rc = proc.wait(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
        lf.close()
        assert not ready.exists() or ready.stat().st_size == 0, (
            "node with a mismatched own keypair became ready (should abort loud)")
        assert rc not in (0, None), (
            f"mismatched-keypair boot did not abort (exit={rc})\n{tail(log)}")
    finally:
        for d in (tmp, keys, other):
            shutil.rmtree(d, ignore_errors=True)


def test_TP58_config_key_migration():
    """`discoverable` replaces the 3 old knobs; removed keys warn-and-ignore; per-peer
    `cert` retained → the node still BOOTS CLEAN (presence-only per A6/A8)."""
    import tempfile, shutil, subprocess, sys, json
    from pathlib import Path
    from _harness import (NODE_SCRIPT, CONFIG_PEER, REPO_ROOT, free_port,
                                wait_file, READY_TIMEOUT)
    from plexus.serialization import generate_keypair
    tmp = Path(tempfile.mkdtemp(prefix="w2_tp58_"))
    keys = Path(tempfile.mkdtemp(prefix="w2_tp58_keys_"))
    try:
        generate_keypair(str(keys), "w2b-peer")
        ready = tmp / "ready.json"
        # legacy + removed keys merged via net-knobs → must warn-and-ignore, boot clean
        knobs = tmp / "knobs.json"
        knobs.write_text(json.dumps({
            "discover_nodes": True, "direct_discoverable": True, "auto_discoverable": True,
            "pool_size": 8, "max_outbound_connections": 4, "lookup_interval": 5,
            "resync_interval": 300, "inbound_idle_timeout": 30,
        }), encoding="utf-8")
        peers = tmp / "peers.json"
        peers.write_text("[]", encoding="utf-8")
        log = tmp / "boot.log"
        lf = open(log, "w", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(NODE_SCRIPT), "--config", str(CONFIG_PEER),
             "--port", str(free_port()), "--ready-file", str(ready),
             "--keys-dir", str(keys), "--peers-file", str(peers),
             "--net-knobs-file", str(knobs), "--discoverable"],
            cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT)
        try:
            info = wait_file(ready, READY_TIMEOUT)
            assert info is not None, f"node did not boot clean with legacy+removed keys\n{tail(log)}"
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            lf.close()
    finally:
        for d in (tmp, keys):
            shutil.rmtree(d, ignore_errors=True)
