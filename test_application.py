"""Standalone runner for the AIO Assistant Core test framework.

Loads test_config.yml (only test-framework plugins enabled), drives
TestRunner.run_all, prints a compact summary, dumps full JSON to disk,
then shuts down. Exit code = 0 if no failed/errored cases AND no
unexpected_passes.

PR4 Stage K (B-066): pre-generates parent + subnode mTLS keypairs at
startup, patches the parent's networking config with the subnode peer
entry BEFORE NetworkManager is constructed, and forwards the subnode
keys + parent cert PEM path to TestRemoteSuite via environment
variables (consumed in TestRemoteSuite._spawn_subnode and passed as
flags to run_node.py).
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from plexus.core import Plexus
from plexus.serialization import generate_keypair


def _install_fast_loop():
    """Install a faster event-loop policy when available: winloop on
    Windows, uvloop on POSIX. Must run before asyncio.run(). Optional —
    `pip install plexus-core[fastloop]` activates it; a bare checkout falls
    back to the stock asyncio loop (no-op). Returns the module name or None.
    """
    try:
        if sys.platform == "win32":
            import winloop as _fast
        else:
            import uvloop as _fast
    except ImportError:
        return None
    _fast.install()
    return _fast.__name__


CONFIG_PATH = "test_config.yml"
DUMP_PATH = "test_outputs/test_report.json"
RUNNER_PLUGIN = "TestRunner"

SUBNODE_HOSTNAME = "test-subnode"
PARENT_HOSTNAME = "aio-test-parent"

# Live sockets this process may gain across a run before the run is reported as
# leaking. The census counts only sockets OWNED BY THIS PID, so a healthy run
# ends at roughly zero net: every socket the suite opens is closed by teardown,
# and sockets draining through TIME_WAIT are owned by no process and therefore
# not counted. A handful of slack absorbs sockets still closing at exit.
SOCKET_LEAK_THRESHOLD = 16


def _free_ports(n: int) -> List[int]:
    """Bind-probe `n` distinct free TCP ports, on 0.0.0.0 like the real listener.

    All probe sockets are held open simultaneously and released only once every
    port has been taken, so two probes cannot be handed the same port -- which
    would make the subnode fail to bind and silently turn every remote case
    into a skip.

    The parent and subnode listeners used to be hard-coded to 2510/2511, so a
    run failed to bind (WSAEADDRINUSE) whenever something still held the port:
    an orphaned subnode, or a prior connection on that port still in TIME_WAIT.
    Note this fixes the PORT collision only -- two concurrent runs still share
    test_outputs/subnode.log and test_outputs/test_report.json and would
    clobber each other there.
    """
    socks = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(n)]
    try:
        for s in socks:
            # Probe the same address the real listeners bind (Transport uses
            # 0.0.0.0), so a port free on loopback but taken on another
            # interface cannot pass the probe and then fail the real bind.
            s.bind(("0.0.0.0", 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


PARENT_PORT, SUBNODE_PORT = _free_ports(2)
assert PARENT_PORT != SUBNODE_PORT, "port probe handed out a duplicate port"


def _socket_census() -> Optional[Dict[str, Counter]]:
    """IPv4 TCP sockets, split into two counts that answer different questions.

    ``own`` -- sockets owned by THIS process, bucketed by connection state.
    This is the LEAK signal, and it is deliberately PID-scoped: a machine-wide
    count is unusable as an invariant because any other program opening
    connections during a multi-minute run moves it in both directions, so it
    can equally fail a clean run and mask a real leak.

    ``machine`` -- every socket on the box, same buckets. This exists because
    PID-scoping alone is BLIND to the failure it is supposed to police:
    Windows socket starvation is TIME_WAIT / ephemeral-port accumulation, and
    TIME_WAIT sockets are owned by no process (netstat reports PID 0), so they
    never appear in ``own``. The machine-wide TIME_WAIT total is the only
    starvation signal available here. It is REPORTED, never used to fail a
    run, since it is not attributable to this process.

    Deliberately locale-agnostic: state names differ per Windows UI language
    (TIME_WAIT prints as WARTEND on a German install), so the buckets are
    whatever netstat prints and only the DELTA between two censuses is read.

    Returns None when netstat could not be run OR produced output this parser
    recognised nothing in -- an unmeasured run must not be reportable as a
    clean one. Note ``-p tcp`` is IPv4-only on Windows; IPv6 sockets are not
    counted (netcore binds 0.0.0.0 and the selftests bind 127.0.0.1).
    """
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    pid = str(os.getpid())
    own, machine = Counter(), Counter()
    for line in proc.stdout.splitlines():
        parts = line.split()
        # Proto | Local Address | Foreign Address | State | PID
        if len(parts) >= 5 and parts[0].upper() == "TCP":
            machine[parts[3]] += 1
            if parts[4] == pid:
                own[parts[3]] += 1
    if not machine:
        return None  # netstat ran but nothing parsed; treat as unmeasured
    return {"own": own, "machine": machine}


def _print_summary(report: Dict[str, Any]) -> None:
    s = report.get("summary", {})
    print()
    print("=" * 72)
    print(
        f"Test framework {report.get('framework_version', '?')}  "
        f"({report.get('duration_ms', 0):.0f} ms)"
    )
    print("=" * 72)
    print(
        f"Suites: {s.get('suites_passed', 0)} passed, "
        f"{s.get('suites_failed', 0)} failed"
    )
    print(
        f"Cases:  {s.get('passed', 0)} passed | "
        f"{s.get('failed', 0)} failed | "
        f"{s.get('errored', 0)} errored | "
        f"{s.get('skipped', 0)} skipped | "
        f"{s.get('unexpected_passes', 0)} unexpected_pass | "
        f"{s.get('total', 0)} total"
    )
    print()

    for suite in report.get("suites", []):
        name = suite.get("suite", "?")
        ver = suite.get("version", "?")
        passed = suite.get("passed", 0)
        failed = suite.get("failed", 0)
        errored = suite.get("errored", 0)
        skipped = suite.get("skipped", 0)
        ups = suite.get("unexpected_passes", 0)
        total = suite.get("total", 0)
        dur = suite.get("duration_ms", 0)
        print(
            f"  [{name} v{ver}] "
            f"{passed}P / {failed}F / {errored}E / {skipped}S / {ups}U "
            f"of {total} ({dur:.0f} ms)"
        )

        # Print non-pass cases for visibility
        non_pass: List[Dict[str, Any]] = [
            c for c in suite.get("cases", []) if c.get("status") != "pass"
        ]
        for c in non_pass:
            cid = c.get("id", "?")
            status = c.get("status", "?")
            detail = c.get("detail", "")
            tag = ""
            if c.get("bug_ids"):
                tag = f" [{','.join(c['bug_ids'])}]"
            print(f"    {status:18} {cid}{tag}")
            if detail and status not in ("skip",):
                # Truncate long details
                d = detail if len(detail) <= 200 else detail[:197] + "..."
                print(f"      └ {d}")

    review = report.get("review_required", [])
    if review:
        print()
        print(f"REVIEW_REQUIRED ({len(review)} cases now passing — flip markers?):")
        for cid in review:
            print(f"  - {cid}")

    print()


def _exit_code(report: Dict[str, Any]) -> int:
    s = report.get("summary", {})
    if s.get("failed", 0) > 0 or s.get("errored", 0) > 0:
        return 1
    if s.get("unexpected_passes", 0) > 0:
        return 2  # bugs may be fixed; review needed
    return 0


def _provision_test_mtls_identities() -> Dict[str, str]:
    """Generate parent + subnode keypairs in temp dirs and return paths
    + cert PEM bodies. Called BEFORE Plexus loads so the parent's
    networking.peers can be patched with the subnode entry up-front.

    Returns a dict with keys:
        parent_keys_dir, parent_cert_path, parent_key_path,
        parent_fp, parent_cert_pem,
        sub_keys_dir, sub_cert_path, sub_key_path,
        sub_fp, sub_cert_pem,
        parent_cert_pem_file (path to a file holding parent_cert_pem,
            consumed by run_node.py via --parent-cert-pem-file flag)
    """
    parent_keys_dir = tempfile.mkdtemp(prefix="aio_test_parent_")
    sub_keys_dir = tempfile.mkdtemp(prefix="aio_test_sub_")
    p_cert, p_key, p_fp, p_pem = generate_keypair(parent_keys_dir, PARENT_HOSTNAME)
    s_cert, s_key, s_fp, s_pem = generate_keypair(sub_keys_dir, SUBNODE_HOSTNAME)

    parent_cert_pem_file = tempfile.NamedTemporaryFile(
        prefix="aio_test_parent_cert_", suffix=".pem", delete=False
    )
    try:
        parent_cert_pem_file.write(p_pem.encode("utf-8"))
    finally:
        parent_cert_pem_file.close()

    return {
        "parent_keys_dir": parent_keys_dir,
        "parent_cert_path": str(p_cert),
        "parent_key_path": str(p_key),
        "parent_fp": p_fp,
        "parent_cert_pem": p_pem,
        "sub_keys_dir": sub_keys_dir,
        "sub_cert_path": str(s_cert),
        "sub_key_path": str(s_key),
        "sub_fp": s_fp,
        "sub_cert_pem": s_pem,
        "parent_cert_pem_file": parent_cert_pem_file.name,
    }


def _patch_networking_for_mtls(pc: "Plexus", mtls: Dict[str, str]) -> None:
    """Inject mTLS keys_dir + peers into pc.yaml_config.networking BEFORE
    NetworkManager is constructed (NetworkManager reads peers + keys_dir
    once at __init__, so this must run before wait_until_ready).
    """
    nw_cfg = pc.yaml_config.setdefault("networking", {})
    nw_cfg["keys_dir"] = mtls["parent_keys_dir"]
    # Override test_config.yml's static port with this run's probed one.
    nw_cfg["port"] = PARENT_PORT
    nw_cfg["peers"] = [
        {
            "hostname": SUBNODE_HOSTNAME,
            "address": f"127.0.0.1:{SUBNODE_PORT}",
            "cert_pem": mtls["sub_cert_pem"],
            "system_caller": False,
        },
    ]
    nw_cfg.pop("node_ips", None)


def _set_subnode_env_for_test_remote_suite(mtls: Dict[str, str]) -> None:
    """Forward the subnode's keys + parent cert to TestRemoteSuite via
    env vars so its _spawn_subnode call passes them as flags to run_node.py.
    """
    os.environ["AIO_TEST_SUB_KEYS_DIR"] = mtls["sub_keys_dir"]
    os.environ["AIO_TEST_PARENT_CERT_PEM_FILE"] = mtls["parent_cert_pem_file"]
    os.environ["AIO_TEST_PARENT_HOSTNAME"] = PARENT_HOSTNAME
    os.environ["AIO_TEST_PARENT_PORT"] = str(PARENT_PORT)
    os.environ["AIO_TEST_SUBNODE_PORT"] = str(SUBNODE_PORT)


def _cleanup_test_mtls_identities(mtls: Dict[str, str]) -> None:
    for d in (mtls.get("parent_keys_dir"), mtls.get("sub_keys_dir")):
        if d:
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
    pem_file = mtls.get("parent_cert_pem_file")
    if pem_file:
        try:
            os.unlink(pem_file)
        except OSError:
            pass
    # Clear env vars so a second in-process
    # invocation of run_tests() (test rerun, REPL session, etc.) cannot
    # pick up stale paths pointing at the now-deleted temp dirs.
    for key in (
        "AIO_TEST_SUB_KEYS_DIR",
        "AIO_TEST_PARENT_CERT_PEM_FILE",
        "AIO_TEST_PARENT_HOSTNAME",
        "AIO_TEST_PARENT_PORT",
        "AIO_TEST_SUBNODE_PORT",
    ):
        os.environ.pop(key, None)


_socket_leak: Optional[int] = None


def _report_socket_census(
    before: Optional[Dict[str, Counter]], started_at: Optional[str]
) -> None:
    """Print the run's socket deltas and record them into the JSON report.

    Sets the module-level ``_socket_leak`` when THIS PROCESS's growth exceeds
    SOCKET_LEAK_THRESHOLD, which __main__ turns into a non-zero exit. The
    machine-wide delta is printed alongside but never fails a run: it is not
    attributable to this process. It is here because it is the only visibility
    into TIME_WAIT accumulation, which is the actual Windows socket-starvation
    mechanism and is invisible to the PID-scoped count.

    This exists so "the suite leaks sockets" is a measured claim rather than
    folklore: the starvation claim that gated 11 netcore cells was never
    reproduced, because nothing ever counted.
    """
    global _socket_leak
    after = _socket_census()
    if before is None or after is None:
        print("\nSocket census: UNMEASURED (netstat unavailable or unparsed)")
        return

    def _delta(a: Counter, b: Counter) -> Dict[str, int]:
        d = {k: b[k] - a[k] for k in set(a) | set(b)}
        return {k: v for k, v in sorted(d.items()) if v}

    own_delta = _delta(before["own"], after["own"])
    machine_delta = _delta(before["machine"], after["machine"])
    net = sum(after["own"].values()) - sum(before["own"].values())
    machine_net = sum(after["machine"].values()) - sum(before["machine"].values())

    print(f"\nSocket census: net {net:+d} held by this process "
          f"{own_delta or '(no change)'}")
    print(f"               net {machine_net:+d} machine-wide (informational) "
          f"{machine_delta or '(no change)'}")
    try:
        dump = Path(DUMP_PATH)
        report = json.loads(dump.read_text(encoding="utf-8"))
        # Only stamp the report this run actually produced. The census fires from
        # a finally block, so a run that died before TestRunner dumped would
        # otherwise decorate the PREVIOUS run's report and make it look current.
        if started_at is not None and report.get("started_at") == started_at:
            report["socket_census"] = {
                "own_before": sum(before["own"].values()),
                "own_after": sum(after["own"].values()),
                "own_net": net,
                "own_by_state": own_delta,
                "machine_net": machine_net,
                "machine_by_state": machine_delta,
                "threshold": SOCKET_LEAK_THRESHOLD,
            }
            dump.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"(could not record socket census in report: {e})", file=sys.stderr)

    if net > SOCKET_LEAK_THRESHOLD:
        _socket_leak = net
        print(
            f"ERROR: this process ended holding {net} more sockets than it "
            f"started with (threshold {SOCKET_LEAK_THRESHOLD}). Check for an "
            f"undrained peer link or a transport that was never stopped.",
            file=sys.stderr,
        )


async def run_tests() -> int:
    census_before = _socket_census()
    mtls = _provision_test_mtls_identities()
    try:
        _set_subnode_env_for_test_remote_suite(mtls)

        pc = Plexus(CONFIG_PATH)
        _patch_networking_for_mtls(pc, mtls)
        await pc.wait_until_ready()
    except Exception:
        # Ensure the temp dirs +
        # env vars are cleaned up even if Plexus startup raises.
        # The downstream try/finally only fires if pc was constructed
        # successfully.
        _cleanup_test_mtls_identities(mtls)
        raise

    run_started_at: Optional[str] = None
    try:
        report = await pc.execute(
            RUNNER_PLUGIN,
            "run_all",
            args={
                # Phases built so far; later phases extend this list.
                "suites": [
                    "TestExecuteSuite",
                    "TestStreamSuite",
                    "TestEventSuite",
                    "TestLifecycleSuite",
                    "TestRemoteSuite",
                    "TestPR2Suite",
                    "TestBugSuite",
                    "TestHotReloadNetworkingSuite",
                    "TestInternalEventBusSuite",
                    "TestRuntimeToggleSuite",
                    "TestIdentitySuite",
                    "TestCapabilitySuite",
                    "TestRateLimitSuite",
                    "TestCapabilityUnitSuite",
                    "TestIdentityUnitSuite",
                    "TestRateLimitConfigUnitSuite",
                    "TestRateLimiterUnitSuite",
                    "TestDepResolutionUnitSuite",
                    "TestDepResolutionSuite",
                    "TestAuditPortUnitSuite",
                    "TestNetPairUnitSuite",
                    "TestNetcoreUnitSuite",
                ],
                "category": None,        # both basic and edge
                # Don't filter by host — let matrix-expanded `.remote`
                # sub-cases auto-skip via remote_available=False so we keep
                # an accurate record of what's deferred.
                "host": None,
                "dump_path": DUMP_PATH,
                "skip_slow": False,
                "allow_destructive": True,
            },
        )

        if not isinstance(report, dict):
            print(
                f"ERROR: TestRunner returned non-dict: {type(report).__name__}",
                file=sys.stderr,
            )
            return 3

        run_started_at = report.get("started_at")
        _print_summary(report)
        print(f"Full report: {Path(DUMP_PATH).resolve()}")
        return _exit_code(report)
    finally:
        await pc.graceful_shutdown()
        _cleanup_test_mtls_identities(mtls)
        _report_socket_census(census_before, run_started_at)


if __name__ == "__main__":
    _loop_impl = _install_fast_loop()
    if _loop_impl:
        print(f"Using fast event loop: {_loop_impl}", file=sys.stderr)
    try:
        rc = asyncio.run(run_tests())
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        rc = 130
    except Exception as e:
        print(f"FATAL: {type(e).__name__}: {e}", file=sys.stderr)
        rc = 4
    if rc == 0 and _socket_leak is not None:
        rc = 5
    sys.exit(rc)
