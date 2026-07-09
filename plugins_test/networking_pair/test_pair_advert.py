"""B-082 regression guard — cross-node subscription adverts must propagate in a
same-machine 2-node pair.

Two REAL Plexus nodes are booted as a mutual mTLS-pinned pair on loopback,
CONCURRENTLY (both list the other as a configured peer), mirroring the actual
deployment topology (tui_smoke_pair.py) rather than TestRemoteSuite's
parent-up-first ordering. Node B (pair-b) subscribes pair/probe; node A (pair-a,
the lower hostname / tiebreak initiator) polls its own network._inbound_adverts
for the peer's subs and fires request_event("pair_probe"). PairProbe writes the
result; this test asserts on it.

B-082 (OPEN): the advert exchange never fires in this topology (a "deadlock of
politeness" — the initiator's update_single succeeds but never arms the
exchange; the peer Node is created hostname=None), so A's _inbound_adverts stays
empty forever and request_event raises "no subscriber matches".

PASS/FAIL CONTRACT
* XFAIL (strict=False) = bug present: A saw no adverts AND request_event failed.
* XPASS = B-082 fixed: A saw the peer's advert AND request_event succeeded ->
  the guard flips, and this is B-082's regression test.

This is a real-socket, two-subprocess integration test (~30-60s). It is kept out
of the boot-heavy in-process suite (which can starve Windows sockets); run it on
its own: ``python -m pytest plugins_test/networking_pair/``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from plexus.serialization import generate_keypair  # noqa: E402

PAIR_NODE = _HERE / "pair_node.py"
CONFIG_A = _HERE / "config.pair_a.yml"
CONFIG_B = _HERE / "config.pair_b.yml"

A_HOST, B_HOST = "pair-a", "pair-b"
A_PORT, B_PORT = 25100, 25101   # unusual ports, unlikely to clash with 2510

READY_TIMEOUT = 40.0            # per-node boot
RESULT_TIMEOUT = 45.0          # asker's _ASK_BUDGET (25s) + margin


def _spawn(config, port, peer_host, peer_port, keys_dir, peer_pem, ready, role,
           result, log):
    cmd = [
        sys.executable, str(PAIR_NODE),
        "--config", str(config),
        "--port", str(port),
        "--ready-file", str(ready),
        "--keys-dir", str(keys_dir),
        "--peer-cert-pem-file", str(peer_pem),
        "--peer-hostname", peer_host,
        "--peer-port", str(peer_port),
        "--peer-ip", "127.0.0.1",
        "--role", role,
    ]
    if result:
        cmd += ["--result-file", str(result)]
    lf = open(log, "w", encoding="utf-8")
    return subprocess.Popen(
        cmd, cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
        stdout=lf, stderr=subprocess.STDOUT,
    ), lf


def _wait_file(path: Path, timeout: float) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        time.sleep(0.25)
    return None


@pytest.mark.xfail(
    reason=(
        "B-082: cross-node subscription adverts never propagate in a "
        "same-machine 2-node pair booted concurrently as mutual mTLS-pinned "
        "peers. The advert exchange fires only from the outbound discovery "
        "cascade in update_single (guarded on node.hostname); the tiebreak "
        "initiator's update_single succeeds but never arms _spawn_initial_"
        "exchange, and the configured peer Node is created hostname=None, so "
        "the guard never passes. The asker's network._inbound_adverts stays "
        "empty and request_event raises 'no subscriber matches'. This test "
        "boots the REAL topology and asserts the asker saw no advert and the "
        "cross-node request_event failed. When B-082 is fixed the asker sees "
        "the peer's advert and the call succeeds -> this xfail flips to xpass."
    ),
    strict=False,
)
def test_B082_pair_cross_node_advert_propagation():
    tmp = Path(tempfile.mkdtemp(prefix="pair_b082_"))
    a_keys = Path(tempfile.mkdtemp(prefix="pair_a_keys_"))
    b_keys = Path(tempfile.mkdtemp(prefix="pair_b_keys_"))
    # Provision each node's mTLS identity; the peer consumes the OTHER's cert.
    _ac, _ak, _afp, a_pem = generate_keypair(str(a_keys), A_HOST)
    _bc, _bk, _bfp, b_pem = generate_keypair(str(b_keys), B_HOST)
    a_pem_f = tmp / "a_cert.pem"
    a_pem_f.write_text(a_pem, encoding="utf-8")
    b_pem_f = tmp / "b_cert.pem"
    b_pem_f.write_text(b_pem, encoding="utf-8")

    a_ready, b_ready = tmp / "a_ready.json", tmp / "b_ready.json"
    result_f = tmp / "ask_result.json"
    a_log, b_log = tmp / "a.log", tmp / "b.log"

    a_proc = b_proc = None
    a_lf = b_lf = None
    try:
        # Spawn BOTH concurrently (mutual peers): B (sub) then A (ask), back to
        # back, so they race through boot the way the real deployment does.
        b_proc, b_lf = _spawn(CONFIG_B, B_PORT, A_HOST, A_PORT, b_keys, a_pem_f,
                              b_ready, "sub", None, b_log)
        a_proc, a_lf = _spawn(CONFIG_A, A_PORT, B_HOST, B_PORT, a_keys, b_pem_f,
                              a_ready, "ask", result_f, a_log)

        a_info = _wait_file(a_ready, READY_TIMEOUT)
        b_info = _wait_file(b_ready, READY_TIMEOUT)

        # SETUP CHECK: both nodes must have booted, else this isn't the bug shape.
        if a_info is None or b_info is None:
            a_tail = a_log.read_text(encoding="utf-8")[-1500:] if a_log.exists() else ""
            b_tail = b_log.read_text(encoding="utf-8")[-1500:] if b_log.exists() else ""
            pytest.fail(
                "B-082 SETUP FAILED: a node did not become ready "
                f"(A={a_info is not None}, B={b_info is not None}). The pair "
                "never came up, so the advert result is meaningless.\n"
                f"--- A log tail ---\n{a_tail}\n--- B log tail ---\n{b_tail}"
            )

        result = _wait_file(result_f, RESULT_TIMEOUT)
        # SETUP CHECK: the asker's probe task must have run and reported.
        if result is None:
            a_tail = a_log.read_text(encoding="utf-8")[-1500:] if a_log.exists() else ""
            pytest.fail(
                "B-082 SETUP FAILED: the asker never wrote a result file within "
                f"{RESULT_TIMEOUT}s (PairProbe role=ask task did not report). "
                f"--- A log tail ---\n{a_tail}"
            )

        adverts_seen = bool(result.get("adverts_seen"))
        request_ok = bool(result.get("request_ok"))

        if adverts_seen and request_ok:
            # Adverts propagated AND the cross-node ask was answered by the peer
            # -> B-082 is fixed. Return cleanly so the strict=False xfail -> XPASS.
            return

        # CONFIRMED B-082: no advert reached the asker and/or the remote ask
        # failed in the concurrent mutual-peer topology.
        pytest.fail(
            "B-082 CONFIRMED (cross-node adverts do not propagate in a "
            "same-machine mutual-peer pair): after both nodes booted, the "
            f"asker (pair-a) reported adverts_seen={adverts_seen}, "
            f"request_ok={request_ok}, inbound_hosts={result.get('inbound_hosts')}, "
            f"error={result.get('error')!r}. The advert exchange never fired in "
            "the concurrent-boot mutual-mTLS-peer topology, so request_event "
            "found no remote subscriber. See B-082 for the root cause "
            "(update_single arms no exchange; peer Node created hostname=None)."
        )
    finally:
        for proc in (a_proc, b_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for lf in (a_lf, b_lf):
            try:
                if lf:
                    lf.close()
            except Exception:
                pass
