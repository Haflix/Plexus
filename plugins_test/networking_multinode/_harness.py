"""Spawn / keypair / topology machinery for the multinode cooperative socket suite.

Real-socket, multi-subprocess: N nodes plus runtime peer/knob injection via JSON
files consumed by node.py.

Drives the netcore surface (snapshot(), the _core/* events, the networking config
keys). Netcore shipped in f71906b, so this runs against live code. Gated behind
PLEXUS_PAIR_TEST by the tests.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from plexus.serialization import generate_keypair  # noqa: E402

NODE_SCRIPT = _HERE / "node.py"
CONFIG_DRIVER = _HERE / "config.driver.yml"
CONFIG_PEER = _HERE / "config.peer.yml"
CONFIG_PEER2 = _HERE / "config.peer2.yml"
CONFIG_PEER_CHANGED = _HERE / "config.peer_changed.yml"

DRIVER_HOST = "w2a-driver"
PEER_HOST = "w2b-peer"
PEER2_HOST = "w2c-peer2"

READY_TIMEOUT = 45.0
RESULT_TIMEOUT = 180.0  # a group runs many cells; generous

# Fast networking knobs (rewrite key names, per SPEC §11). Unknown keys are
# warn-and-ignored by the rewrite (config migration), so a name mismatch just
# falls back to defaults (slower, still correct).
FAST_KNOBS = {
    "heartbeat_interval": 1.0,
    "probe_timeout": 0.5,
    "liveness_timeout": 3.0,
    "idle_read_deadline": 2.5,
    "reconnect_backoff_max": 2.0,
}


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def wait_file(path: Path, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        time.sleep(0.25)
    return None


def tail(path: Path, n: int = 2000) -> str:
    try:
        return path.read_text(encoding="utf-8")[-n:]
    except OSError:
        return ""


def wait_phase(path: Path, want: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if path.exists() and path.read_text(encoding="utf-8").strip() == want:
                return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


def peer_spec(hostname: str, port: int, cert_pem: str, *, ip: str = "127.0.0.1",
              system_caller: bool = False) -> dict:
    return {"hostname": hostname, "address": f"{ip}:{port}",
            "cert_pem": cert_pem, "system_caller": system_caller}


@dataclass
class Node:
    hostname: str
    config: Path
    port: int
    keys_dir: Path
    cert_pem: str
    proc: subprocess.Popen | None = None
    logfile: object = None
    ready_file: Path | None = None
    result_file: Path | None = None
    phase_file: Path | None = None
    obs_file: Path | None = None


@dataclass
class Harness:
    tmp: Path
    nodes: dict = field(default_factory=dict)

    def gen_node(self, hostname: str, config: Path) -> Node:
        keys = Path(tempfile.mkdtemp(prefix=f"w2_{hostname}_keys_"))
        _c, _k, _fp, pem = generate_keypair(str(keys), hostname)
        n = Node(hostname=hostname, config=config, port=free_port(), keys_dir=keys,
                 cert_pem=pem)
        self.nodes[hostname] = n
        return n

    def spawn(self, node: Node, *, peers: list[dict], group: str = "", cell: str = "",
              discoverable: bool = False, knobs: dict | None = None,
              reload_config: Path | None = None, wants_result: bool = False,
              wants_phase: bool = False, extra_args: list | None = None) -> None:
        peers_file = self.tmp / f"peers_{node.hostname}.json"
        peers_file.write_text(json.dumps(peers), encoding="utf-8")
        knobs_file = self.tmp / f"knobs_{node.hostname}.json"
        knobs_file.write_text(json.dumps(knobs or FAST_KNOBS), encoding="utf-8")
        node.ready_file = self.tmp / f"ready_{node.hostname}.json"
        obs_result = self.tmp / f"obs_{node.hostname}.json"
        node.obs_file = obs_result
        cmd = [sys.executable, str(NODE_SCRIPT),
               "--config", str(node.config), "--port", str(node.port),
               "--ready-file", str(node.ready_file), "--keys-dir", str(node.keys_dir),
               "--peers-file", str(peers_file), "--net-knobs-file", str(knobs_file),
               "--obs-result-file", str(obs_result)]
        if discoverable:
            cmd.append("--discoverable")
        if group:
            cmd += ["--group", group]
        if cell:
            cmd += ["--cell", cell]
        if wants_result:
            node.result_file = self.tmp / f"result_{node.hostname}.json"
            cmd += ["--result-file", str(node.result_file)]
        if wants_phase:
            node.phase_file = self.tmp / f"phase_{node.hostname}.txt"
            cmd += ["--phase-file", str(node.phase_file)]
        if reload_config is not None:
            cmd += ["--reload-config", str(reload_config)]
        if extra_args:
            cmd += [str(a) for a in extra_args]
        log = self.tmp / f"{node.hostname}.log"
        node.logfile = open(log, "w", encoding="utf-8")
        node.proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
                                     stdout=node.logfile, stderr=subprocess.STDOUT)

    def wait_ready(self, node: Node) -> bool:
        return wait_file(node.ready_file, READY_TIMEOUT) is not None

    def kill(self, node: Node) -> None:
        if node.proc and node.proc.poll() is None:
            node.proc.kill()
            try:
                node.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def teardown(self) -> None:
        for n in self.nodes.values():
            if n.proc and n.proc.poll() is None:
                n.proc.terminate()
                try:
                    n.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    n.proc.kill()
            try:
                if n.logfile:
                    n.logfile.close()
            except Exception:
                pass
            shutil.rmtree(n.keys_dir, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)


def new_harness() -> Harness:
    return Harness(tmp=Path(tempfile.mkdtemp(prefix="w2_")))
