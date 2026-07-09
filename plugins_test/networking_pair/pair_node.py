"""Headless Plexus node for the networking pair harness (test_pair_advert.py).

Mirrors plugins_test/_remote_node/run_node.py, but boots as one half of a
same-machine MUTUAL-peer pair (both nodes list the other as an mTLS-pinned peer
and boot concurrently), and carries a --role that the PairProbe plugin reads via
env to decide subscribe (sub) vs. probe+report (ask).

CLI (peer flags from the shared runner parser):
    python plugins_test/networking_pair/pair_node.py \
        --config <config.pair_a.yml> --port 2510 --ready-file <r> \
        --keys-dir <dir> --peer-cert-pem-file <pem> --peer-hostname pair-b \
        --peer-port 2511 --peer-ip 127.0.0.1 --role ask --result-file <res>
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
    ap = build_runner_parser(
        description="networking pair-harness node (B-082 guard).",
    )
    ap.add_argument("--role", choices=["ask", "sub"], required=True)
    ap.add_argument("--result-file", default="")
    args = ap.parse_args()

    # The PairProbe plugin reads these from the environment in on_enable.
    os.environ["PAIR_ROLE"] = args.role
    if args.result_file:
        os.environ["PAIR_RESULT_FILE"] = args.result_file

    pc = Plexus(args.config)

    # Port + keys + peer are injected into the yaml BEFORE wait_until_ready,
    # since NetworkManager is constructed there from yaml_config["networking"].
    pc.networking_port = args.port
    nw_cfg = pc.yaml_config.setdefault("networking", {})
    nw_cfg["port"] = args.port
    if args.keys_dir is not None:
        nw_cfg["keys_dir"] = args.keys_dir
    if args.peer_cert_pem_file is not None:
        peer_cert_pem = Path(args.peer_cert_pem_file).read_text(encoding="utf-8")
        nw_cfg["peers"] = [
            {
                "hostname": args.peer_hostname,
                "address": f"{args.peer_ip}:{args.peer_port}",
                "cert_pem": peer_cert_pem,
                "system_caller": False,
            },
        ]
        nw_cfg.pop("node_ips", None)

    await pc.wait_until_ready()

    Path(args.ready_file).write_text(
        json.dumps(
            {
                "hostname": pc.hostname,
                "port": args.port,
                "ip": "127.0.0.1",
                "pid": os.getpid(),
            }
        )
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
