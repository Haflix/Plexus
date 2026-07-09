"""B-082 regression guard + connection failure-angle harness.

Boots two REAL Plexus nodes as a mutual mTLS-pinned pair on loopback,
CONCURRENTLY (each lists the other as a configured peer), mirroring the actual
deployment topology (tui_smoke_pair.py) rather than TestRemoteSuite's
parent-up-first ordering that dodges the race. One node subscribes pair/probe;
the other (the asker) polls its network for the peer's advert and fires
request_event. The PairProbe fixture writes the result; this test asserts on it.

B-082 (OPEN): the advert exchange never fires in this topology (a "deadlock of
politeness" — the tiebreak initiator's update_single succeeds but never arms the
exchange; the configured peer Node is created hostname=None), so the asker's
_inbound_adverts stays empty and request_event raises "no subscriber matches".

Angles covered (both are B-082, xfail):
  * asker = LOWER hostname (pair-a, the tiebreak INITIATOR)
  * asker = HIGHER hostname (pair-b, the RECIPROCATOR)
B-082 is initiator-vs-reciprocator asymmetric, so both directions are guarded; a
partial fix that flips only one would leave the other red.

FAITHFULNESS GATE: a true advert deadlock and an unrelated no-connection failure
(bad cert, wrong port, plugin didn't enable) both leave _inbound_adverts empty.
So the asker also records ``peer_connected`` — whether it learned the peer via
the AUTHENTICATED handshake/discovery layer (a Node with the peer hostname),
which is set in a true B-082 but NOT on a broken handshake. If the peer was never
connected, the result is a SETUP FAILURE, not a B-082 confirmation. The
``test_broken_cert_control`` case proves this gate by pinning a wrong cert and
asserting the harness reports no connection (not "B-082 confirmed").

PASS/FAIL (per B-082 angle):
  * XFAIL (strict=False) = bug present: peer connected, but no advert + the ask
    failed.
  * XPASS = B-082 fixed: peer connected, advert seen, ask answered. (strict=False
    so an xpass is silent; when it flips, convert B-082 to fixed and harden.)

Real-socket, multi-subprocess (~25-90s). GATED behind PLEXUS_PAIR_TEST so a
blanket ``pytest plugins_test/`` does NOT boot real nodes (avoids Windows socket
starvation). Run it explicitly:
    PLEXUS_PAIR_TEST=1 python -m pytest plugins_test/networking_pair/
"""

from __future__ import annotations

import json
import os
import shutil
import socket
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

READY_TIMEOUT = 40.0   # per-node boot
RESULT_TIMEOUT = 45.0  # asker's poll budget (~25s) + margin

# Real-socket integration; opt in explicitly so it isn't swept into a blanket
# `pytest plugins_test/` run (which would boot two real nodes each time).
pytestmark = pytest.mark.skipif(
    not os.environ.get("PLEXUS_PAIR_TEST"),
    reason="real-socket 2-node integration; set PLEXUS_PAIR_TEST=1 to run",
)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


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
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
            stdout=lf, stderr=subprocess.STDOUT,
        )
    except Exception:
        lf.close()
        raise
    return proc, lf


def _wait_file(path: Path, timeout: float) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass  # partial write; retry
        time.sleep(0.25)
    return None


def _tail(path: Path, n: int = 1500) -> str:
    try:
        return path.read_text(encoding="utf-8")[-n:]
    except OSError:
        return ""


def _run_pair(asker_is_lower: bool, break_cert: bool = False) -> dict:
    """Boot the mutual-peer pair once and return the asker's result + boot state.

    asker_is_lower: True  -> pair-a (lower hostname, tiebreak initiator) asks.
                    False -> pair-b (higher hostname, reciprocator) asks.
    break_cert: pin a WRONG cert for the asker's peer so the mTLS handshake
                fails (control: proves the peer-connection gate distinguishes a
                no-connection failure from a true B-082 deadlock).
    """
    tmp = Path(tempfile.mkdtemp(prefix="pair_"))
    a_keys = Path(tempfile.mkdtemp(prefix="pair_a_keys_"))
    b_keys = Path(tempfile.mkdtemp(prefix="pair_b_keys_"))
    a_proc = b_proc = a_lf = b_lf = None
    try:
        _ac, _ak, _afp, a_pem = generate_keypair(str(a_keys), A_HOST)
        _bc, _bk, _bfp, b_pem = generate_keypair(str(b_keys), B_HOST)
        a_pem_f = tmp / "a_cert.pem"
        a_pem_f.write_text(a_pem, encoding="utf-8")
        b_pem_f = tmp / "b_cert.pem"
        b_pem_f.write_text(b_pem, encoding="utf-8")

        a_port, b_port = _free_port(), _free_port()
        while b_port == a_port:
            b_port = _free_port()

        # Roles: the asker gets role=ask + a result-file; the peer subscribes.
        a_role = "ask" if asker_is_lower else "sub"
        b_role = "sub" if asker_is_lower else "ask"
        result_f = tmp / "ask_result.json"

        # Each node pins the OTHER's cert. For the control, corrupt the cert the
        # ASKER pins so its handshake to the peer fails.
        a_peer_pem, b_peer_pem = b_pem_f, a_pem_f  # A pins B's cert, B pins A's
        if break_cert:
            _wc, _wk, _wfp, wrong_pem = generate_keypair(
                str(tmp / "wrong_keys"), "wrong-host"
            )
            wrong_f = tmp / "wrong_cert.pem"
            wrong_f.write_text(wrong_pem, encoding="utf-8")
            if asker_is_lower:
                a_peer_pem = wrong_f  # A (asker) pins a wrong cert for B
            else:
                b_peer_pem = wrong_f  # B (asker) pins a wrong cert for A

        a_ready, b_ready = tmp / "a_ready.json", tmp / "b_ready.json"
        a_log, b_log = tmp / "a.log", tmp / "b.log"

        # Spawn BOTH concurrently (back-to-back) so they race through boot.
        b_proc, b_lf = _spawn(
            CONFIG_B, b_port, A_HOST, a_port, b_keys, b_peer_pem, b_ready,
            b_role, result_f if b_role == "ask" else None, b_log)
        a_proc, a_lf = _spawn(
            CONFIG_A, a_port, B_HOST, b_port, a_keys, a_peer_pem, a_ready,
            a_role, result_f if a_role == "ask" else None, a_log)

        a_info = _wait_file(a_ready, READY_TIMEOUT)
        b_info = _wait_file(b_ready, READY_TIMEOUT)
        result = _wait_file(result_f, RESULT_TIMEOUT) if (a_info and b_info) else None

        return {
            "a_ready": a_info is not None,
            "b_ready": b_info is not None,
            "result": result,
            "a_tail": _tail(a_log),
            "b_tail": _tail(b_log),
        }
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
        for d in (tmp, a_keys, b_keys):
            shutil.rmtree(d, ignore_errors=True)


def _assert_booted(run: dict):
    if not (run["a_ready"] and run["b_ready"]):
        pytest.fail(
            "PAIR SETUP FAILED: a node did not become ready "
            f"(A={run['a_ready']}, B={run['b_ready']}). The pair never came up.\n"
            f"--- A log tail ---\n{run['a_tail']}\n--- B log tail ---\n{run['b_tail']}"
        )
    if run["result"] is None:
        pytest.fail(
            "PAIR SETUP FAILED: the asker never wrote a result within "
            f"{RESULT_TIMEOUT}s (PairProbe role=ask task did not report).\n"
            f"--- asker log tail ---\n{run['a_tail']}{run['b_tail']}"
        )


@pytest.mark.parametrize(
    "asker_is_lower",
    [
        pytest.param(
            True, id="asker_lower_initiator",
            marks=pytest.mark.xfail(
                strict=False,
                reason="B-082: cross-node adverts don't propagate in a "
                "same-machine mutual-peer pair; asker=lower (tiebreak initiator).",
            ),
        ),
        pytest.param(
            False, id="asker_higher_reciprocator",
            marks=pytest.mark.xfail(
                strict=False,
                reason="B-082 reciprocal direction: asker=higher hostname. The "
                "bug is initiator/reciprocator asymmetric, so both are guarded.",
            ),
        ),
    ],
)
def test_B082_pair_cross_node_advert_propagation(asker_is_lower):
    run = _run_pair(asker_is_lower=asker_is_lower)
    _assert_booted(run)
    result = run["result"]

    # FAITHFULNESS GATE: an authenticated peer connection must have been
    # established, else "no adverts" is a connection/setup failure, NOT B-082.
    if not result.get("peer_connected"):
        pytest.fail(
            "PAIR SETUP FAILED: the asker never established an authenticated "
            "connection to the peer (peer_connected=False, "
            f"node_hosts={result.get('node_hosts')}). This is a connection/mTLS "
            "failure, not the B-082 advert deadlock — do not attribute it to "
            f"B-082.\n--- asker log tail ---\n{run['a_tail']}{run['b_tail']}"
        )

    if result.get("adverts_seen") and result.get("request_ok"):
        # Peer connected, advert propagated, cross-node ask answered -> B-082 is
        # fixed for this direction. Clean return -> strict=False xfail -> XPASS.
        return

    pytest.fail(
        "B-082 CONFIRMED (advert deadlock in a same-machine mutual-peer pair): "
        f"asker_is_lower={asker_is_lower}; the peer WAS connected "
        f"(peer_connected=True, node_hosts={result.get('node_hosts')}) but "
        f"adverts_seen={result.get('adverts_seen')}, "
        f"request_ok={result.get('request_ok')}, "
        f"inbound_hosts={result.get('inbound_hosts')}, "
        f"error={result.get('error')!r}. The advert exchange never fired despite "
        "an established connection — the B-082 deadlock. See B-082."
    )


def test_broken_cert_control():
    """Control: with a WRONG peer cert the mTLS handshake fails, so the asker
    never connects. Proves the peer_connected gate distinguishes a no-connection
    failure from a true B-082 deadlock — the main test would (correctly) SETUP
    FAIL on this, not report 'B-082 confirmed'. This is a normal passing test."""
    run = _run_pair(asker_is_lower=True, break_cert=True)
    # Both nodes still BOOT (peers are configured; the handshake fails later).
    if not (run["a_ready"] and run["b_ready"] and run["result"] is not None):
        pytest.fail(
            "control SETUP FAILED: nodes/result did not come up "
            f"(a_ready={run['a_ready']}, b_ready={run['b_ready']}, "
            f"result={run['result'] is not None}).\n{run['a_tail']}{run['b_tail']}"
        )
    result = run["result"]
    assert result.get("peer_connected") is False, (
        "control: expected NO authenticated connection with a wrong pinned cert, "
        f"but peer_connected={result.get('peer_connected')} "
        f"(node_hosts={result.get('node_hosts')}). If this is True the mTLS pin "
        "isn't actually being enforced, and the main test's peer_connected gate "
        "cannot distinguish a broken connection from a B-082 deadlock."
    )
    assert result.get("request_ok") is False, (
        "control: request_event should fail when the peer never connected "
        f"(request_ok={result.get('request_ok')})."
    )
