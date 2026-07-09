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

# S4 (drop+reconnect) per-phase budgets. Death is bounded by
# heartbeat_strikes x heartbeat_interval + probe_timeout (turned down to
# seconds by pair_node.py), plus slack. Each phase fails fast on its own
# deadline rather than hanging the whole run.
_RECOVER_ESTABLISH_S = 25.0
_RECOVER_DEATH_S = 20.0
_RECOVER_REJOIN_S = 25.0


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
        elif os.environ.get("PAIR_RECOVER") == "1":
            # role=ask + S4: run the 4-phase drop+reconnect probe.
            self._ask_task = asyncio.create_task(self._run_recover_ask())
        else:
            # role=ask: no local sub, so request_event can only be answered by
            # the remote peer. Run the probe in the background.
            self._ask_task = asyncio.create_task(self._run_ask())

    def _peer_advert_present(self, net) -> bool:
        """True iff the peer's pair/probe subscription is currently in this
        node's _inbound_adverts (the advert layer, distinct from the handshake
        layer that _peer_connected reads). Used by the S4 recovery probe to
        watch the advert appear -> vanish (peer killed) -> reappear (peer
        respawned + reconnected)."""
        if net is None:
            return False
        inbound = getattr(net, "_inbound_adverts", {}) or {}
        for subs in inbound.values():
            for s in (subs or {}).values():
                if getattr(s, "topic_pattern", None) == "pair/probe":
                    return True
        return False

    def _write_phase(self, phase: str) -> None:
        """S4: signal the parent test how far the recovery probe has got, so it
        can time the kill (after phase 1) and the respawn (after phase 2)."""
        phase_file = os.environ.get("PAIR_PHASE_FILE", "")
        if not phase_file:
            return
        try:
            with open(phase_file, "w", encoding="utf-8") as f:
                f.write(phase)
        except OSError:
            self._logger.exception("PairProbe: failed to write phase file")

    async def _run_recover_ask(self):
        """S4 drop+reconnect probe. Four bounded phases, each writing a boolean:
          1. advert_before  — peer connected AND its pair/probe advert seen.
          2. advert_gone    — after the parent kills the sub, its advert vanishes
                              from _inbound_adverts (proves the kill + strike-
                              death landed, so a later reappearance is genuine
                              recovery, not a stale positive).
          3. advert_after   — after the parent respawns the sub (same identity,
                              new session), its advert RE-propagates.
          4. request_ok     — a cross-node request_event(hosts="any") is answered
                              again.
        Each phase has its own deadline so a stuck phase fails fast instead of
        hanging the run. The parent watches PAIR_PHASE_FILE to time the kill
        (after "1") and respawn (after "2")."""
        result_file = os.environ.get("PAIR_RESULT_FILE", "")
        loop = asyncio.get_running_loop()
        net = getattr(self._plexus, "network", None)
        advert_before = advert_gone = advert_after = request_ok = False
        error = ""

        async def _poll_until(pred, budget_s):
            deadline = loop.time() + budget_s
            while loop.time() < deadline:
                if pred():
                    return True
                await asyncio.sleep(_POLL_INTERVAL_S)
            return pred()

        # Phase 1: establish (peer connected + its advert seen).
        advert_before = await _poll_until(
            lambda: self._peer_connected(net) and self._peer_advert_present(net),
            _RECOVER_ESTABLISH_S,
        )
        if advert_before:
            self._write_phase("1")
            # Phase 2: the parent now kills the sub; wait for its advert to
            # vanish (strike-death -> _drop_peer_advert_state).
            advert_gone = await _poll_until(
                lambda: not self._peer_advert_present(net), _RECOVER_DEATH_S
            )
            if advert_gone:
                self._write_phase("2")
                # Phase 3: the parent now respawns the sub; wait for its advert
                # to re-propagate over the real reconnect.
                advert_after = await _poll_until(
                    lambda: self._peer_advert_present(net), _RECOVER_REJOIN_S
                )

        # Phase 4: the actual cross-node ask (hosts="any" to route remotely).
        try:
            await self.request_event(
                "pair_probe", payload={"value": 1}, hosts="any")
            request_ok = True
        except Exception as e:  # noqa: BLE001
            error = f"{type(e).__name__}: {e}"

        node_hosts = [
            getattr(n, "hostname", None) for n in (getattr(net, "nodes", ()) or ())
        ]
        # FAITHFULNESS GATE (mirrors _peer_connected for B-082): did the peer
        # genuinely RE-CONNECT after respawn (an ENABLED Node with its hostname)?
        # If it did but no advert came back, that is a real restart-recovery
        # advert bug; if it never reconnected, the missing advert is just a
        # connection failure and the test must treat it as SETUP FAIL, not a
        # confirmed recovery-advert bug.
        peer = os.environ.get("PAIR_PEER_HOSTNAME", "")
        peer_reconnected = any(
            getattr(n, "hostname", None) == peer and getattr(n, "enabled", False)
            for n in (getattr(net, "nodes", ()) or ())
        )
        if result_file:
            try:
                with open(result_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "advert_before": advert_before,
                            "advert_gone": advert_gone,
                            "advert_after": advert_after,
                            "request_ok": request_ok,
                            "peer_reconnected": peer_reconnected,
                            "error": error,
                            "node_hosts": node_hosts,
                        },
                        f,
                    )
            except OSError:
                self._logger.exception("PairProbe: failed to write result file")

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
