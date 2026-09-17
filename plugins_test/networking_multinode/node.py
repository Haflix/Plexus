"""Generic multi-peer Plexus node runner for the multinode cooperative socket suite.

Extends the two-node pattern to N peers + the netcore config
surface. Boots a headless node from a per-role config (config.driver/peer/peer2),
injects port + keys_dir + a PEERS list (from a JSON file) + networking knobs (fast
heartbeat etc.), exports env the fixture plugins read (MultinodeDriver / NetObsProbe /
NetCtl), waits until ready, writes a ready-file, and runs until signalled.

Validates against the winning rewrite POST-combine: the rewrite exposes the
networking config keys used here (peers/discoverable/port/keys_dir + the §11 knob
names). Knob NAMES are rewrite-defined; passed through verbatim from --net-knobs so
the harness adapts to the landed branch without an edit here.

CLI (peer/knob flags layered on the shared runner parser):
    python plugins_test/networking_multinode/node.py \
        --config config.driver.yml --port 0 --ready-file <r> --keys-dir <d> \
        --peers-file <peers.json> --net-knobs-file <knobs.json> \
        --group pair --result-file <res> --phase-file <ph> --discoverable
"""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from plexus.core import Plexus  # noqa: E402
from plugins_test._runner_cli import build_runner_parser  # noqa: E402


async def main() -> None:
    ap = build_runner_parser(description="multinode cooperative socket node.")
    ap.add_argument("--peers-file", default="",
                    help="JSON list of peer dicts {hostname,address,cert_pem,"
                         "system_caller?,dial?} for the networking peers list")
    ap.add_argument("--net-knobs-file", default="",
                    help="JSON dict merged into the networking config (fast "
                         "heartbeat / liveness / reassembly-cap / per-voucher cap "
                         "overrides — rewrite key names, passed verbatim)")
    ap.add_argument("--discoverable", action="store_true")
    ap.add_argument("--group", default="", help="MultinodeDriver cell group / cell id")
    ap.add_argument("--cell", default="", help="single-cell id for lifecycle runs")
    ap.add_argument("--result-file", default="")
    ap.add_argument("--phase-file", default="")
    ap.add_argument("--obs-result-file", default="")
    ap.add_argument("--reload-config", default="",
                    help="a self-contained config the driver reloads for the "
                         "reconfigure/durability cells (peers baked in, a "
                         "rebuild-trigger key flipped)")
    ap.add_argument("--readd-spec", default="", help="peer spec JSON for TP-41 re-add")
    ap.add_argument("--addpeer-spec", default="", help="peer spec JSON for TP-36 add")
    ap.add_argument("--orphan-host", default="", help="orphan vouched host for TP-50")
    ap.add_argument("--vouch-cap", default="", help="per-voucher cap marker for TP-47")
    args = ap.parse_args()

    # Env the fixture plugins read in on_enable.
    if args.group:
        os.environ["MULTINODE_GROUP"] = args.group
    if args.cell:
        os.environ["MULTINODE_CELL"] = args.cell
    if args.result_file:
        os.environ["MULTINODE_RESULT_FILE"] = args.result_file
    if args.phase_file:
        os.environ["MULTINODE_PHASE_FILE"] = args.phase_file
    if args.obs_result_file:
        os.environ["NETOBS_RESULT_FILE"] = args.obs_result_file
    if args.reload_config:
        os.environ["MULTINODE_RELOAD_CONFIG"] = args.reload_config
    if args.readd_spec:
        os.environ["MULTINODE_READD_SPEC"] = args.readd_spec
    if args.addpeer_spec:
        os.environ["MULTINODE_ADDPEER_SPEC"] = args.addpeer_spec
    if args.orphan_host:
        os.environ["MULTINODE_ORPHAN_HOST"] = args.orphan_host
    if args.vouch_cap:
        os.environ["MULTINODE_VOUCH_CAP"] = args.vouch_cap
    os.environ["MULTINODE_CONFIG_PATH"] = args.config
    # Peer hostnames the driver may target (csv), derived from the peers file.
    peers = []
    if args.peers_file and Path(args.peers_file).exists():
        peers = json.loads(Path(args.peers_file).read_text(encoding="utf-8"))
    os.environ["MULTINODE_PEER_HOSTS"] = ",".join(
        p.get("hostname", "") for p in peers if p.get("hostname")
    )

    pc = Plexus(args.config)
    pc.networking_port = args.port
    nw = pc.yaml_config.setdefault("networking", {})
    nw["enabled"] = True
    nw["port"] = args.port
    if args.keys_dir is not None:
        nw["keys_dir"] = args.keys_dir
    if args.discoverable:
        nw["discoverable"] = True
    if peers:
        nw["peers"] = peers
        nw.pop("node_ips", None)
    if args.net_knobs_file and Path(args.net_knobs_file).exists():
        knobs = json.loads(Path(args.net_knobs_file).read_text(encoding="utf-8"))
        nw.update(knobs)

    await pc.wait_until_ready()

    Path(args.ready_file).write_text(
        json.dumps({"hostname": pc.hostname, "port": args.port,
                    "ip": "127.0.0.1", "pid": os.getpid()})
    )

    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown.set)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: shutdown.set())
    await shutdown.wait()
    await pc.graceful_shutdown()


if __name__ == "__main__":
    asyncio.run(main())
