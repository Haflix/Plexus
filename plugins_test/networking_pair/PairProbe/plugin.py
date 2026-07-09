"""PairProbe — networking pair-harness fixture (guards B-082).

Loaded on BOTH nodes of a same-machine mutual-peer pair; the role is chosen by
the ``PAIR_ROLE`` env var set by pair_node.py:

  * role=sub  — subscribe pair/probe at runtime (default hosts="any") so this
    node's subscription is advertised to the peer. Idle otherwise.
  * role=ask  — do NOT subscribe (so a local sub can't answer), then poll this
    node's ``network._inbound_adverts`` for the peer's subs and fire
    request_event("pair_probe", hosts="any"). Write {adverts_seen,
    inbound_advert_topics, request_ok, error, inbound_hosts} to
    ``PAIR_RESULT_FILE`` for the test to assert on.

B-082 (FIXED 2026-07-09): in a same-machine pair booting concurrently as mutual
mTLS-pinned peers, the tiebreak initiator poisoned its _snapshot_sent slot with a
pre-is_ready advert that silently no-op'd, so the exchange never fired and the
asker's _inbound_adverts stayed empty. Fixed in plexus/networking.py (0.69.13).
This fixture is the regression guard: the asker now sees the pair/probe advert
and the cross-node request_event(hosts="any") is answered.
"""

import asyncio
import json
import os

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


# How long the asker polls for the peer's advert / a working request before it
# gives up and records the (failing) result. Generous vs the ~5s a healthy
# exchange takes, so a False result means genuinely-absent, not just slow.
_ASK_BUDGET_S = 25.0
_POLL_INTERVAL_S = 0.5


class PairProbe(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._sub_ids: list[str] = []
        self._ask_task = None

    @async_log_errors
    async def on_enable(self):
        role = os.environ.get("PAIR_ROLE", "sub")
        if role == "sub":
            # Runtime subscribe (default hosts="any") so the sub advertises over
            # the wire, mirroring TestRemoteTarget's fixture idiom.
            sid = await self._plexus.subscribe_event(
                "pair/probe",
                self.plugin_name,
                self.plugin_uuid,
                target_access_name="pair_probe_handler",
            )
            self._sub_ids.append(sid)
        else:
            # role=ask: no local sub, so request_event can only be answered by
            # the remote peer. Run the probe in the background.
            self._ask_task = asyncio.create_task(self._run_ask())

    def _peer_connected(self, net) -> bool:
        """True once this node has learned the peer via an AUTHENTICATED
        exchange (a Node with the peer's hostname). This is set by the
        handshake/discovery layer (_handle_info), NOT the advert layer, so it
        stays True in a genuine B-082 (adverts starved but the peer IS known)
        and False on a broken handshake / no connection. Lets the test tell a
        true advert deadlock apart from an unrelated connection failure (FA1)."""
        peer = os.environ.get("PAIR_PEER_HOSTNAME", "")
        if not peer or net is None:
            return False
        for n in getattr(net, "nodes", ()) or ():
            if getattr(n, "hostname", None) == peer:
                return True
        return False

    async def _run_ask(self):
        result_file = os.environ.get("PAIR_RESULT_FILE", "")
        loop = asyncio.get_running_loop()
        net = getattr(self._plexus, "network", None)
        adverts_seen = False
        peer_connected = False
        request_ok = False
        error = ""

        # Poll for BOTH the peer connection (authenticated, handshake layer) and
        # the peer's advert (advert layer). In a healthy pair both appear; in a
        # true B-082 the connection appears but the advert never does; in a
        # no-connection failure neither appears (-> test treats as SETUP FAIL).
        deadline = loop.time() + _ASK_BUDGET_S
        while loop.time() < deadline:
            if not peer_connected and self._peer_connected(net):
                peer_connected = True
            inbound = getattr(net, "_inbound_adverts", {}) if net else {}
            if any(bool(v) for v in inbound.values()):
                adverts_seen = True
            if peer_connected and adverts_seen:
                break
            await asyncio.sleep(_POLL_INTERVAL_S)

        # Regardless of the polls, try the actual cross-node ask. hosts="any"
        # is REQUIRED: a request_event that omits hosts defaults to "local"
        # (docs/notifier.md — publisher default hosts="local"), so it would
        # only search local subs and never route to the remote peer. The asker
        # has no local pair/probe sub, so without hosts="any" this always
        # raises "no subscriber matches" regardless of advert propagation.
        try:
            await self.request_event(
                "pair_probe", payload={"value": 1}, hosts="any")
            request_ok = True
        except Exception as e:  # noqa: BLE001
            error = f"{type(e).__name__}: {e}"

        inbound = getattr(net, "_inbound_adverts", {}) if net else {}
        inbound_hosts = list(inbound.keys())
        # Diagnostic: the actual topic patterns advertised per peer, so the
        # test can tell "received the pair/probe advert" from "received only
        # some other (framework-internal) advert". adverts_seen alone is too
        # coarse to distinguish those.
        inbound_advert_topics = {
            host: [getattr(s, "topic_pattern", None) for s in (subs or {}).values()]
            for host, subs in inbound.items()
        }
        node_hosts = [
            getattr(n, "hostname", None) for n in (getattr(net, "nodes", ()) or ())
        ]
        if result_file:
            try:
                with open(result_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "peer_connected": peer_connected,
                            "adverts_seen": adverts_seen,
                            "request_ok": request_ok,
                            "error": error,
                            "inbound_hosts": inbound_hosts,
                            "inbound_advert_topics": inbound_advert_topics,
                            "node_hosts": node_hosts,
                        },
                        f,
                    )
            except OSError:
                self._logger.exception("PairProbe: failed to write result file")

    def pair_probe_handler(self, value=None, **kwargs):
        """Answer the pair/probe topic (on the sub node)."""
        return {"pong": True, "value": value}

    @async_log_errors
    async def on_disable(self):
        if self._ask_task is not None and not self._ask_task.done():
            self._ask_task.cancel()
            try:
                await self._ask_task
            except (asyncio.CancelledError, Exception):
                pass
        for sid in list(self._sub_ids):
            try:
                await self._plexus.unsubscribe_event(sid)
            except Exception:
                pass
        self._sub_ids = []
