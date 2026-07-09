"""B-082 regression guard + connection failure-angle harness.

Boots two REAL Plexus nodes as a mutual mTLS-pinned pair on loopback,
CONCURRENTLY (each lists the other as a configured peer), mirroring the actual
deployment topology (tui_smoke_pair.py) rather than TestRemoteSuite's
parent-up-first ordering that dodges the race. One node subscribes pair/probe;
the other (the asker) polls its network for the peer's advert and fires
request_event(hosts="any"). The PairProbe fixture writes the result; this test
asserts on it.

B-082 (FIXED 2026-07-09, plexus __version__ 0.69.13): in this concurrent-boot
topology the tiebreak initiator (lower hostname) ran its initial advert exchange
BEFORE networking flipped is_ready. advertise_subs_remote silently no-op'd on the
is_ready guard (no send, no raise), but _perform_initial_exchange had already
claimed the _snapshot_sent slot and only rolled back on an exception — so the
slot was poisoned as "sent" with an empty wire. Every later trigger then
short-circuited on the poisoned slot; the reciprocator deferred forever; only the
300s periodic resync healed it. Fix: advertise_subs_remote now returns whether it
actually sent, and _perform_initial_exchange releases the slot when it didn't, so
the next post-is_ready discovery tick re-initiates and sends. Both tiebreak
directions are guarded because the bug was initiator/reciprocator asymmetric.

Angles covered (both must PASS):
  * asker = LOWER hostname (pair-a, the tiebreak INITIATOR)
  * asker = HIGHER hostname (pair-b, the RECIPROCATOR)

FAITHFULNESS GATE: a broken advert path and an unrelated no-connection failure
(bad cert, wrong port, plugin didn't enable) both leave _inbound_adverts empty.
So the asker also records ``peer_connected`` — whether it learned the peer via
the AUTHENTICATED handshake/discovery layer (a Node with the peer hostname),
which is set on a real advert-path failure but NOT on a broken handshake. If the
peer was never connected the result is a SETUP FAILURE, not a B-082 regression.
The ``test_broken_cert_control`` case proves this gate by pinning a wrong cert
and asserting the harness reports no connection.

NOTE on hosts="any": a request_event that omits ``hosts`` defaults to "local"
(docs/notifier.md), so it never routes to a remote peer. The asker must pass
hosts="any" — this is real cross-node API usage, not a harness workaround.

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


@pytest.fixture(autouse=True)
def _socket_cooldown():
    """Each test boots 2-3 real nodes; across the suite these accumulate
    TIME_WAIT sockets on Windows and can starve Winsock (WinError 10055),
    surfacing as a spurious advert-propagation failure in a LATER test. A short
    cooldown between the boot-heavy tests lets sockets drain. Even so, on a
    constrained box the full suite may need to run in smaller batches (see
    README); each test passes cleanly in isolation."""
    yield
    time.sleep(5.0)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _spawn(config, port, peer_host, peer_port, keys_dir, peer_pem, ready, role,
           result, log, extra_args=None):
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
    if extra_args:
        cmd += [str(a) for a in extra_args]
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


def _wait_phase(path: Path, want: str, timeout: float) -> bool:
    """Poll the recovery probe's phase file until its content equals `want`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if path.exists() and path.read_text(encoding="utf-8").strip() == want:
                return True
        except OSError:
            pass
        time.sleep(0.25)
    return False


# S4 timers (must match what pair_node.py sets on the live NM): fast heartbeat +
# low strikes so a kill is detected in seconds; resync LONG so recovery is
# proven to come from the real reconnect, not the 300s periodic sweep.
_S4_TIMER_ARGS = [
    "--heartbeat-interval", "1.0",
    "--heartbeat-strikes", "2",
    "--probe-timeout", "1.0",
    "--liveness-timeout", "4.0",
    "--resync-interval", "120.0",
]
_S4_PHASE1_TIMEOUT = 35.0   # advert established after concurrent boot
_S4_PHASE2_TIMEOUT = 25.0   # advert vanishes after the kill (strike-death)


def _run_drop_reconnect() -> dict:
    """S4: boot the pair, let the advert establish, KILL the subscriber, wait
    for the asker to see the advert vanish (strike-death), then RESPAWN the
    subscriber on the SAME identity/port (new session_id) and check the advert
    re-propagates + a cross-node request is answered again. Asker = pair-a
    (lower), killed/respawned sub = pair-b (higher)."""
    tmp = Path(tempfile.mkdtemp(prefix="pair_s4_"))
    a_keys = Path(tempfile.mkdtemp(prefix="pair_s4_a_keys_"))
    b_keys = Path(tempfile.mkdtemp(prefix="pair_s4_b_keys_"))
    a_proc = b_proc = b_proc2 = a_lf = b_lf = b_lf2 = None
    try:
        _ac, _ak, _afp, a_pem = generate_keypair(str(a_keys), A_HOST)
        _bc, _bk, _bfp, b_pem = generate_keypair(str(b_keys), B_HOST)
        a_pem_f = tmp / "a_cert.pem"
        a_pem_f.write_text(a_pem, encoding="utf-8")
        b_pem_f = tmp / "b_cert.pem"
        b_pem_f.write_text(b_pem, encoding="utf-8")
        a_peer_pem, b_peer_pem = b_pem_f, a_pem_f  # A pins B's cert, B pins A's

        a_port, b_port = _free_port(), _free_port()
        while b_port == a_port:
            b_port = _free_port()

        result_f = tmp / "ask_result.json"
        phase_f = tmp / "phase.txt"
        a_ready, b_ready, b_ready2 = (
            tmp / "a_ready.json", tmp / "b_ready.json", tmp / "b_ready2.json")
        a_log, b_log, b_log2 = tmp / "a.log", tmp / "b.log", tmp / "b2.log"

        # sub (pair-b) — killed + respawned.
        b_proc, b_lf = _spawn(
            CONFIG_B, b_port, A_HOST, a_port, b_keys, b_peer_pem, b_ready,
            "sub", None, b_log, extra_args=_S4_TIMER_ARGS)
        # asker (pair-a) — recovery probe.
        a_extra = _S4_TIMER_ARGS + ["--recover", "--phase-file", str(phase_f)]
        a_proc, a_lf = _spawn(
            CONFIG_A, a_port, B_HOST, b_port, a_keys, a_peer_pem, a_ready,
            "ask", result_f, a_log, extra_args=a_extra)

        a_info = _wait_file(a_ready, READY_TIMEOUT)
        b_info = _wait_file(b_ready, READY_TIMEOUT)

        established = killed = respawn_ready = False
        b_info2 = None
        if a_info and b_info:
            # Phase 1: wait until the asker records the advert established.
            established = _wait_phase(phase_f, "1", _S4_PHASE1_TIMEOUT)
            if established:
                # Kill the subscriber (hard) so the asker strikes it dead.
                if b_proc.poll() is None:
                    b_proc.kill()
                    try:
                        b_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                killed = True
                # Phase 2: wait for the asker to see the advert vanish, then
                # respawn (bounded — respawn even if it never vanishes so the
                # run completes and reports).
                _wait_phase(phase_f, "2", _S4_PHASE2_TIMEOUT)
                b_proc2, b_lf2 = _spawn(
                    CONFIG_B, b_port, A_HOST, a_port, b_keys, b_peer_pem,
                    b_ready2, "sub", None, b_log2, extra_args=_S4_TIMER_ARGS)
                b_info2 = _wait_file(b_ready2, READY_TIMEOUT)
                respawn_ready = b_info2 is not None

        result = _wait_file(result_f, RESULT_TIMEOUT) if (a_info and b_info) else None

        return {
            "a_ready": a_info is not None,
            "b_ready": b_info is not None,
            "established": established,
            "killed": killed,
            "respawn_ready": respawn_ready,
            "result": result,
            "a_tail": _tail(a_log),
            "b_tail": _tail(b_log) + "\n--- b respawn ---\n" + _tail(b_log2),
        }
    finally:
        for proc in (a_proc, b_proc, b_proc2):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for lf in (a_lf, b_lf, b_lf2):
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
        pytest.param(True, id="asker_lower_initiator"),
        pytest.param(False, id="asker_higher_reciprocator"),
    ],
)
def test_B082_pair_cross_node_advert_propagation(asker_is_lower):
    """B-082 REGRESSION GUARD (fixed 2026-07-09). In a same-machine mutual-peer
    pair booting concurrently, the tiebreak initiator (lower hostname) used to
    poison its own _snapshot_sent slot with a pre-is_ready advert that silently
    no-op'd, so adverts never propagated and the reciprocator deferred forever
    (healed only by the 300s resync). Fixed by making advertise_subs_remote
    report whether it actually sent and releasing the slot when it didn't
    (plexus/networking.py, __version__ 0.69.13). Both tiebreak directions are
    guarded because the bug was initiator/reciprocator asymmetric.
    """
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
            "failure, not the B-082 advert path — do not attribute it to "
            f"B-082.\n--- asker log tail ---\n{run['a_tail']}{run['b_tail']}"
        )

    ctx = (
        f"asker_is_lower={asker_is_lower}, node_hosts={result.get('node_hosts')}, "
        f"adverts_seen={result.get('adverts_seen')}, "
        f"inbound_advert_topics={result.get('inbound_advert_topics')}, "
        f"request_ok={result.get('request_ok')}, error={result.get('error')!r}"
    )
    # The peer's pair/probe sub must have propagated over the wire...
    assert result.get("adverts_seen"), (
        f"B-082 REGRESSION: peer connected but no advert propagated. {ctx}\n"
        f"--- asker log tail ---\n{run['a_tail']}{run['b_tail']}"
    )
    topics = result.get("inbound_advert_topics") or {}
    assert any("pair/probe" in v for v in topics.values()), (
        f"B-082 REGRESSION: an advert propagated but not the pair/probe sub. "
        f"{ctx}"
    )
    # ...and the cross-node request_event must route to it and be answered.
    assert result.get("request_ok"), (
        f"B-082 REGRESSION: advert propagated but the cross-node request_event "
        f"was not answered. {ctx}"
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


@pytest.mark.xfail(
    strict=False,
    reason="B-088 (HUNT-092/093 family): a strike-dead peer that RESTARTS is not "
    "recovered by this node. The asker never re-probes a peer it marked dead "
    "(discovery skips enabled=False), and the respawned peer's re-connect does "
    "not re-enable the asker's node, so the advert never re-propagates and the "
    "cross-node request stays unanswered. Flips to XPASS when recovery is fixed.",
)
def test_S4_drop_and_reconnect_recovers():
    """S4 (B-088 repro / M4 restart-recovery acceptance guard): boot the pair,
    establish the advert, KILL the subscriber (asker strikes it dead — advert
    vanishes), then RESPAWN it on the same identity/port (new session_id) and
    require the advert to RE-propagate + a cross-node request to be answered.

    SETUP GATE = advert_before AND advert_gone: the pair really established and
    the kill really landed (so a missing recovery is genuinely the recovery
    path, not a boot/kill artifact). ``resync_interval`` is pinned LONGER than
    the recovery budget so a pass would prove recovery came from the real
    reconnect, not the 300s periodic sweep.

    XFAIL (bug present) = recovery fails (advert_after/request_ok False after a
    clean establish+death). XPASS = recovery works -> B-088 fixed for this
    direction (asker=lower, killed peer=higher)."""
    run = _run_drop_reconnect()
    if not (run["a_ready"] and run["b_ready"]):
        pytest.fail(
            "S4 SETUP FAILED: a node did not boot "
            f"(a_ready={run['a_ready']}, b_ready={run['b_ready']}).\n"
            f"{run['a_tail']}{run['b_tail']}"
        )
    if not run["respawn_ready"]:
        pytest.fail(
            "S4 SETUP FAILED: the subscriber did not respawn on the same port "
            "(same-port re-bind failed — e.g. Windows TIME_WAIT / WinError "
            f"10048).\n{run['b_tail']}"
        )
    result = run["result"]
    if result is None:
        pytest.fail(
            "S4 SETUP FAILED: the asker never wrote a recovery result within "
            f"budget.\n{run['a_tail']}{run['b_tail']}"
        )

    # SETUP GATE: the pair established the advert AND the kill dropped it. If
    # either did not happen, this is a boot/kill artifact, not a recovery result.
    if not result.get("advert_before"):
        pytest.fail(
            "S4 SETUP FAILED: the advert never established before the kill "
            f"(advert_before=False, node_hosts={result.get('node_hosts')}). "
            f"Not a recovery result.\n{run['a_tail']}{run['b_tail']}"
        )
    if not result.get("advert_gone"):
        pytest.fail(
            "S4 SETUP FAILED: the advert did not vanish after the kill "
            "(advert_gone=False) — the strike-death did not drop the advert, so "
            "a later reappearance would be a stale positive, not recovery.\n"
            f"{run['a_tail']}{run['b_tail']}"
        )

    ctx = (
        f"peer_reconnected={result.get('peer_reconnected')}, "
        f"advert_after={result.get('advert_after')}, "
        f"request_ok={result.get('request_ok')}, "
        f"node_hosts={result.get('node_hosts')}, error={result.get('error')!r}"
    )
    if result.get("advert_after") and result.get("request_ok"):
        # Recovery worked -> B-088 fixed for this direction. Clean return so the
        # strict=False xfail flips to XPASS (then convert to a passing guard).
        return

    pytest.fail(
        "B-088 CONFIRMED (restart-recovery deadlock): the pair established the "
        "advert and the kill dropped it, but after the subscriber respawned on "
        "the same identity the advert did NOT re-propagate and the cross-node "
        f"request was not answered. {ctx}. The asker never re-probes a peer it "
        "marked dead and the respawn does not re-enable it. See B-088."
    )
