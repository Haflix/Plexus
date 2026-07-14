"""NetCtl — wave-2 runtime-membership control for the networking rewrite.

Thin adapter the socket cells call to drive runtime membership + subscriptions +
config reload from inside a node subprocess: runtime add_peer / remove_peer
(TP-36/37/39/41/50), snapshot read-back, sub add/remove (TP-04 fan-out count,
TP-34 enable/disable/toggle), and a config-reload trigger (TG-14 reconfigure-
during-in-flight; also the revoke-durability reload of TP-39).

The NM membership calls (``add_peer`` / ``remove_peer`` / ``snapshot``) are the
rewrite's public NM surface (SPEC §4.6 / §3). Forwarded via getattr with clear
{"ok": .., "error": ..} returns so a cell fails loudly (not silently) if a name
or arg shape differs on the landed branch — the exact PeerSpec arg shape binds at
the cell round against the NM API. ``ctl_reload_config`` forwards to the real core
``async_load_config_yaml`` (not rewrite-specific).
"""

from typing import Any

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class NetCtl(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._sub_ids: dict[str, str] = {}  # label -> sid (for readable removal)

    @async_log_errors
    async def on_enable(self):
        self._logger.debug("NetCtl.on_enable")

    @async_log_errors
    async def on_disable(self):
        for sid in list(self._sub_ids.values()):
            try:
                await self._plexus.unsubscribe_event(sid)
            except Exception:
                pass
        self._sub_ids = {}

    def _net(self):
        return getattr(self._plexus, "network", None)

    # ── Runtime membership ──────────────────────────────────────────────
    @async_log_errors
    async def ctl_add_peer(self, spec: Any = None) -> dict:
        """Forward a peer spec to NM.add_peer. ``spec`` is a dict the cell shapes
        to the rewrite's PeerSpec (hostname/address/cert_pem/fingerprint/
        system_caller?/dial?). Returns {ok, error}."""
        net = self._net()
        fn = getattr(net, "add_peer", None)
        if not callable(fn):
            return {"ok": False, "error": "NM has no add_peer"}
        # The cell shapes ``spec`` as the config-style peer dict (the
        # ``peer_spec`` harness helper). The rewrite's ``add_peer`` wants a real
        # PeerSpec, so run the dict through the SAME per-entry parse the config
        # path uses (derives the SPKI fingerprint from cert_pem, splits address).
        if isinstance(spec, dict):
            try:
                from plexus.netcore.manager import NetworkManager
                port_default = int(getattr(net, "port", 0) or 0)
                spec = NetworkManager._parse_one_peer_spec(
                    spec, port_default=port_default, seen_fp=set(), seen_addr=set())
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": f"peer spec parse: {type(e).__name__}: {e}"}
        try:
            res = fn(spec)
            if hasattr(res, "__await__"):
                res = await res
            return {"ok": True, "result": _safe(res)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    @async_log_errors
    async def ctl_remove_peer(self, hostname: str = "") -> dict:
        """Forward to NM.remove_peer(hostname) (revoke). Returns {ok, error}."""
        net = self._net()
        fn = getattr(net, "remove_peer", None)
        if not callable(fn):
            return {"ok": False, "error": "NM has no remove_peer"}
        try:
            res = fn(hostname)
            if hasattr(res, "__await__"):
                res = await res
            return {"ok": True, "result": _safe(res)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    @async_log_errors
    async def ctl_snapshot(self) -> Any:
        """NM.snapshot() verbatim (immediate read-back after a mutation)."""
        net = self._net()
        fn = getattr(net, "snapshot", None)
        if not callable(fn):
            return {"_ctl_error": "NM has no snapshot()"}
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            return {"_ctl_error": f"{type(e).__name__}: {e}"}

    # ── Runtime subscriptions ───────────────────────────────────────────
    @async_log_errors
    async def ctl_sub_add(
        self, label: str = "", topic: str = "", target_access_name: str = "",
        target_plugin: str = None, authors: Any = None, blocked_authors: Any = None,
        hosts: Any = "any", enabled: bool = True,
    ) -> dict:
        """Add a runtime subscription (fan-out count TP-04, sub toggle TP-34,
        author-filter TP-20). NetCtl is always the OWNER (its plugin_name/uuid);
        ``target_plugin`` routes the topic to ANOTHER plugin's endpoint. ``label``
        keys the sid for a later ctl_sub_remove. ``authors``/``blocked_authors``/
        ``hosts``/``enabled`` pass through so a cell can craft a filtered or
        disabled sub."""
        try:
            kwargs = {
                "target_access_name": target_access_name,
                "authors": authors,
                "blocked_authors": blocked_authors,
                "hosts": hosts,
                "enabled": enabled,
            }
            if target_plugin:
                kwargs["target_plugin"] = target_plugin
            sid = await self._plexus.subscribe_event(
                topic,
                self.plugin_name,
                self.plugin_uuid,
                **kwargs,
            )
            self._sub_ids[label or sid] = sid
            return {"ok": True, "sid": sid, "label": label or sid}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    @async_log_errors
    async def ctl_sub_remove(self, label: str = "") -> dict:
        """Remove a runtime subscription by its label (or raw sid)."""
        sid = self._sub_ids.pop(label, None) or label
        try:
            await self._plexus.unsubscribe_event(sid)
            return {"ok": True, "sid": sid}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ── Config reload (TG-14 / TP-39) ───────────────────────────────────
    @async_log_errors
    async def ctl_reload_config(self, config_path: str = "") -> dict:
        """Trigger a hot config reload (a rebuild-trigger key change drains +
        rebuilds networking; TG-14 asserts an in-flight cross-node call fails
        promptly, TP-39 asserts a revoked config peer is not re-added). Forwards
        to the real core async_load_config_yaml."""
        fn = getattr(self._plexus, "async_load_config_yaml", None)
        if not callable(fn):
            return {"ok": False, "error": "no async_load_config_yaml"}
        try:
            await fn(config_path)
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _safe(v: Any) -> Any:
    """Best-effort JSON-friendly reduction of an NM return (may be a PeerSpec)."""
    if v is None or isinstance(v, (bool, int, float, str, list, dict)):
        return v
    return repr(v)
