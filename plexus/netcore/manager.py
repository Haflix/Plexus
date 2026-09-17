"""netcore.manager — SPEC §3 root NetworkManager (PHASE 6 wiring).

The thin root that composes the four modules (Directory/Membership/Transport/
Dispatch), the lifecycle (start/stop/is_ready), the runtime mutators
(add_peer/remove_peer), `snapshot()` (§8.3 pinned shape), the `route_*`
passthrough seam, the five `*_remote` senders core consumes, and the NM-resident
`_hosts_match` predicate the core filter chain invokes. `__init__` creates
`_inflight_publishes` + `_adverts_struct_lock` as CORE-OWNED attrs on the NM
object (NM never uses them for adverts — §1.4/§4.5/§6).

Construction (phase-6 contracts): identity loaded/generated from `keys_dir`;
config peers parsed to PeerSpec (combined `address:"host:port"` split, learning 9);
`start()` runs `transport.start()` BEFORE `seed_config_peers` (else a supervisor
started pre-start exits and is never revived — learning 10); LOCAL dispatch stays
in the untouched core notifier (the injected `_RematchRegistry` delegates whole-
mode to `_fanout_sub`/`execute`/`execute_stream`; `_RateSeam` charges
nodes_in/framework_in via `core._rl_admit_inbound` — learning 12).

The tolerant `__init__(**_legacy)` sink absorbs any stray legacy kwarg so NO
protected-core construction edit is needed; `_apply_yaml`'s `nm.<knob> = x` sets
are tolerated via `__setattr__`. `_build_network_manager` passes only the
canonical `networking_config` dict + `config_dir`; the REMOVED `node_ips:` key,
if present in that dict, fails LOUD in `__init__` (migration guard) rather than
being silently ignored.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time as _time
import uuid as _uuid
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Tuple, Union

from .directory import Directory
from .dispatch import Dispatch, NoEndpointError
from .membership import Membership, VOUCHER_ACTIVE_CAP
from .transport import (
    Transport,
    NODE_WIDE_REASSEMBLY_CAP,
    PER_PEER_REASSEMBLY_CAP,
    PER_PEER_CID_CAP,
    STREAM_IDLE_DEADLINE,
    CONNECT_TIMEOUT,
)
from .wire import PER_CID_REASSEMBLY_CAP
from .types import (
    CallerCtx,
    EndpointEntry,
    ExecuteSelector,
    PeerSource,
    PeerSpec,
    RemoteSub,
    TopicSelector,
)

_logger = logging.getLogger("plexus.netcore.manager")


def _spki_from_pem(cert_pem: str) -> str:
    """`sha256:` + sha256(SubjectPublicKeyInfo DER) — the pin format Membership/
    Directory/the SPKI check use (SPEC §4.1)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as _ser
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    spki = cert.public_key().public_bytes(
        encoding=_ser.Encoding.DER, format=_ser.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(spki).hexdigest()


class NetworkManager:
    """The networking root core consumes (SPEC §3)."""

    def __init__(self, core: Any, logger: Optional[logging.Logger] = None,
                 networking_config: Optional[dict] = None,
                 config_dir: Optional[Union[str, Path]] = None,
                 **_legacy: Any) -> None:
        object.__setattr__(self, "_legacy_kwargs", _legacy)
        self._core = core
        self._logger = logger or _logger
        self._nw_cfg = dict(networking_config or {})
        # `node_ips:` is a REMOVED schema (replaced by `peers:`). It is not a netcore
        # knob, so without this guard it would be silently ignored -> a peerless,
        # non-functional node with no error. Restore the old fail-loud migration guard.
        if "node_ips" in self._nw_cfg:
            raise RuntimeError(
                "networking.node_ips: is a REMOVED schema, replaced by networking.peers:. "
                "Migrate each node to a peers: entry (hostname / address / "
                "cert_pem). See docs/networking.md and docs/configuration.md."
            )
        self._config_dir = Path(config_dir) if config_dir else Path(".")

        # CORE-OWNED attrs — created here, NEVER used by NM for adverts (§1.4/§4.5/§6).
        self._adverts_struct_lock: asyncio.Lock = asyncio.Lock()
        self._inflight_publishes: Dict[str, set] = {}

        self.is_ready: bool = False
        self.self_hostname: str = str(self._core.hostname)
        self.port: int = int(self._nw_cfg.get("port", 2510))
        self.liveness_timeout: float = float(self._nw_cfg.get("liveness_timeout", 30.0))

        # --- identity (§4.1): load or generate own long-lived self-signed cert ---
        self._keys_dir = self._resolve_keys_dir()
        self._cert_path, self._key_path, self._own_fingerprint, _own_pem = self._load_or_generate_identity()

        # --- config peers -> PeerSpec (empty is TOLERATED: the acceptor binds with an
        # empty-cadata listener whose sni_callback swaps to the live context on the first
        # add_peer; the SPKI post-check + roster-gate reject any unpinned inbound). ---
        self._config_specs: List[PeerSpec] = self._parse_config_peers()

        # --- timing knobs (SPEC §11 defaults + config overrides) ---
        hb = self._safe_float("heartbeat_interval", 10.0)
        probe = self._safe_float("probe_timeout", 2.0)
        idle_read = self._safe_float("idle_read_deadline", max(2.0 * hb, 20.0))
        if idle_read <= 0:  # a 0/negative idle-read deadline expires every read
            # immediately -> reader-teardown loop on every link (self-DoS). Guard it
            # like the caps below; the `inbound_idle_timeout` legacy alias can feed
            # this an unvalidated operator value.
            idle_read = max(2.0 * hb, 20.0)
        ping_floor = self._safe_float("ping_floor_interval", max(0.5, hb * 0.5))
        # §11 per-cid reassembly bound (DoS guard). Default 8 MB; a deployment that
        # genuinely needs larger single values can raise it in its own config.yml.
        per_cid_cap = self._safe_int("per_cid_reassembly_cap", PER_CID_REASSEMBLY_CAP)
        if per_cid_cap <= 0:  # a 0/negative cap makes every reassembly bound-exceed (self-DoS)
            per_cid_cap = PER_CID_REASSEMBLY_CAP
        # §11 node-wide reassembly cap (the aggregate DoS ceiling above the per-cid /
        # per-peer bounds). Default 128 MB; config-overridable so a deployment can size
        # it to its memory budget (and so tests can exercise the per-peer guaranteed-
        # minimum reservation under a realistically-low node ceiling).
        node_cap = self._safe_int("node_reassembly_cap", NODE_WIDE_REASSEMBLY_CAP)
        if node_cap <= 0:  # a 0/negative aggregate cap would reject every reassembly (self-DoS)
            node_cap = NODE_WIDE_REASSEMBLY_CAP
        # Theme 2 deployment knobs — already Transport/Membership ctor params; wired
        # here from config with the same `<=0 -> default` guard as the caps above.
        #   per_peer_reassembly_cap  un-traps per_cid (max single value = min(per_cid,
        #                            per_peer)); a memory-budget bound
        #   per_peer_cid_cap         max concurrent inbound CALLs from one peer
        #   stream_idle_deadline     slow-stream producer bound (§ per-chunk idle)
        #   connect_timeout          per-dial TCP+TLS budget
        #   vouch_active_cap         per-voucher §4.7 discovery fan-out cap
        per_peer_cap = self._safe_int("per_peer_reassembly_cap", PER_PEER_REASSEMBLY_CAP)
        if per_peer_cap <= 0:
            per_peer_cap = PER_PEER_REASSEMBLY_CAP
        per_peer_cid_cap = self._safe_int("per_peer_cid_cap", PER_PEER_CID_CAP)
        if per_peer_cid_cap <= 0:
            per_peer_cid_cap = PER_PEER_CID_CAP
        stream_idle = self._safe_float("stream_idle_deadline", STREAM_IDLE_DEADLINE)
        if stream_idle <= 0:
            stream_idle = STREAM_IDLE_DEADLINE
        connect_timeout = self._safe_float("connect_timeout", CONNECT_TIMEOUT)
        if connect_timeout <= 0:
            connect_timeout = CONNECT_TIMEOUT
        voucher_cap = self._safe_int("vouch_active_cap", VOUCHER_ACTIVE_CAP)
        if voucher_cap <= 0:
            voucher_cap = VOUCHER_ACTIVE_CAP

        # --- build + cross-wire the four modules (Directory -> Membership -> Transport -> Dispatch) ---
        tombstone_path = str(self._keys_dir / "revoked_peers.json")
        provider = self._RegistryProvider(self)
        self.directory = Directory(
            provider, None, self_hostname=self.self_hostname,
            observe=self._observe, ping_floor=ping_floor)
        self.membership = Membership(
            self_hostname=self.self_hostname, cert_file=str(self._cert_path),
            key_file=str(self._key_path), directory=self.directory, transport=None,
            observe=self._observe, tombstone_path=tombstone_path,
            lan_cidr=self._nw_cfg.get("lan_cidrs"), default_port=self.port,
            heartbeat_interval=hb, probe_timeout=probe,
            liveness_timeout=self.liveness_timeout, require_peers=False,
            discoverable=bool(self._nw_cfg.get("discoverable", False)),  # §4.7 opt-in gate
            voucher_cap=voucher_cap)
        self.directory._membership = self.membership   # mutual ref (chicken-and-egg patch)
        self.dispatch = Dispatch(
            transport=None, membership=self.membership,
            registry=self._RematchRegistry(self._core), rate=self._RateSeam(self._core),
            observe=self._observe)
        self.transport = Transport(
            self.membership, self.directory, self.dispatch,
            listen_host="0.0.0.0", listen_port=self.port, manager=self,
            liveness_timeout=self.liveness_timeout, idle_read_deadline=idle_read,
            per_cid_cap=per_cid_cap, node_cap=node_cap,
            per_peer_cap=per_peer_cap, per_peer_cid_cap=per_peer_cid_cap,
            stream_idle=stream_idle, connect_timeout=connect_timeout)
        self.membership.attach_transport(self.transport)
        self.dispatch.attach_transport(self.transport)

    # ----------------------------------------------------------------------
    # lifecycle — transport.start() BEFORE seed_config_peers (learning 10)
    # ----------------------------------------------------------------------

    async def start(self) -> None:
        await self.transport.start()                       # acceptor up + _running=True FIRST
        self.membership.seed_config_peers(self._config_specs)   # skips persisted-revoked (durability)
        await self.membership.start()                      # start the pulse
        self.is_ready = True

    async def stop(self) -> None:
        self.is_ready = False
        try:
            await self.membership.stop()
        except Exception:
            pass
        try:
            await self.transport.stop()
        except Exception:
            pass

    # ----------------------------------------------------------------------
    # runtime roster mutation (SPEC §3/§4.6)
    # ----------------------------------------------------------------------

    async def add_peer(self, spec: PeerSpec) -> bool:
        self.membership.add_peer(spec)   # explicit operator add (clears tombstone)
        return True

    async def remove_peer(self, hostname: str) -> None:
        self.membership.remove_peer(hostname)

    # ----------------------------------------------------------------------
    # observability snapshot (SPEC §8.3, PINNED shape)
    # ----------------------------------------------------------------------

    def snapshot(self) -> dict:
        now = _time.monotonic()
        peers: Dict[str, dict] = {}
        for hostname in sorted(self.membership.roster_snapshot()):
            spec = self.membership.spec_for(hostname)
            last_seen = self.membership._last_seen.get(hostname)
            age = None if last_seen is None or last_seen == float("-inf") else max(0.0, now - last_seen)
            # `epoch` = the peer's LIVE current boot identity, tracked in Membership off
            # every PONG header (the same source that fires `_core/peer/restarted`), so a
            # dashboard can tell a fresh reboot from a steady peer. NOT the epoch stamped
            # in the last-applied directory (`remote_snap.epoch`): that rides the
            # content-hash-gated apply path, so a same-config reboot (no re-apply, §10)
            # would freeze it stale while the peer has actually restarted.
            live_epoch = self.membership._last_epoch.get(hostname)
            remote_snap = self.directory._remote.get(hostname)
            routing = self.directory.routing_table(hostname)
            source = getattr(spec, "source", None) if spec else None
            # §8.3: a structured failure reason for a peer that is NOT reachable,
            # derived from the transport's per-peer dial state (TG-04). A reachable
            # peer carries no reason; a refused dial → "connection_refused"; otherwise
            # (liveness aged out / no link yet) → "unreachable".
            reachable = self.membership.reachable(hostname)
            if reachable:
                unreachable_reason = last_error = None
            elif getattr(self.transport, "_last_dial_refused", {}).get(hostname, False):
                unreachable_reason, last_error = "connection_refused", "dial refused (LinkRefused)"
            else:
                unreachable_reason, last_error = "unreachable", None
            peers[hostname] = {
                "hostname": hostname,
                "address": f"{getattr(spec, 'ip', '')}:{getattr(spec, 'port', '')}" if spec else None,
                "fingerprint": getattr(spec, "fingerprint", None) if spec else None,
                "reachable": reachable,
                "last_seen_age": age,
                "epoch": live_epoch,
                "content_hash": getattr(remote_snap, "content_hash", None),
                "last_error": last_error,
                "unreachable_reason": unreachable_reason,
                "source": source.name.lower() if isinstance(source, PeerSource) else source,
                "vouched_by": getattr(spec, "vouched_by", None) if spec else None,
                "routing": {"subs": routing.get("subs", []), "endpoints": routing.get("endpoints", [])},
            }
        return {"peers": peers, "self": self.self_hostname}

    # ----------------------------------------------------------------------
    # route_* passthrough seam (delegates to Directory) (SPEC §4.3)
    # ----------------------------------------------------------------------

    def route_request(self, topic: str) -> Iterator[Tuple[str, RemoteSub]]:
        return self.directory.route_request(topic)

    def route_execute(self, plugin: str, endpoint: str) -> Iterator[Tuple[str, EndpointEntry]]:
        return self.directory.route_execute(plugin, endpoint)

    def route_publish(self, topic: str) -> Iterator[Tuple[str, List[RemoteSub]]]:
        return self.directory.route_publish(topic)

    def route_tagged(self, tag: str) -> Iterator[Tuple[str, EndpointEntry]]:
        return self.directory.route_tagged(tag)

    def reachable(self, hostname: str) -> bool:
        return self.directory.reachable(hostname)

    # ----------------------------------------------------------------------
    # NM-resident host-filter predicate (the core filter chain invokes nm._hosts_match)
    # ----------------------------------------------------------------------

    def _hosts_match(self, hosts: Union[str, list, None], blocked_hosts: Union[str, list, None],
                     peer_hostname: str) -> bool:
        def _matches(val):
            if isinstance(val, str):
                return val in ("remote", "any") or val == peer_hostname
            if isinstance(val, list):
                return peer_hostname in val
            return False

        def _blocked(val):
            if val is None:
                return False
            if isinstance(val, str):
                return val in ("remote", "any") or val == peer_hostname
            if isinstance(val, list):
                return peer_hostname in val
            return False

        return _matches(hosts) and not _blocked(blocked_hosts)

    # ----------------------------------------------------------------------
    # the five *_remote senders core consumes (delegate to Dispatch) — PINNED.
    # events.py/core.py pass `selector` as a DICT; convert to a netcore selector obj.
    # ----------------------------------------------------------------------

    @staticmethod
    def _to_selector(selector: Any):
        if isinstance(selector, dict):
            if "topic" in selector:
                return TopicSelector(selector["topic"])
            return ExecuteSelector(selector.get("plugin"), selector.get("endpoint"),
                                   selector.get("plugin_uuid"))
        return selector

    async def execute_remote(self, hostname: str, selector: Any, payload: Any,
                             caller: CallerCtx, handler_timeout: Optional[float],
                             *, deadline: float) -> Any:
        return await self.dispatch.execute_remote(
            hostname, self._to_selector(selector), payload, caller, handler_timeout, deadline=deadline)

    async def request_event_remote(self, hostname: str, selector: Any, payload: Any,
                                   caller: CallerCtx, handler_timeout: Optional[float],
                                   *, deadline: float) -> Any:
        return await self.dispatch.request_event_remote(
            hostname, self._to_selector(selector), payload, caller, handler_timeout, deadline=deadline)

    async def request_event_stream_remote(self, hostname: str, selector: Any, payload: Any,
                                          caller: CallerCtx, handler_timeout: Optional[float] = None,
                                          *, deadline: float) -> AsyncIterator[Any]:
        # ASYNC GENERATOR (yield-through) so events.py gets an async iterator without await.
        async for item in self.dispatch.request_event_stream_remote(
                hostname, self._to_selector(selector), payload, caller, handler_timeout, deadline=deadline):
            yield item

    async def execute_remote_stream(self, hostname: str, selector: Any, payload: Any,
                                    caller: CallerCtx, handler_timeout: Optional[float] = None,
                                    *, deadline: float) -> AsyncIterator[Any]:
        async for item in self.dispatch.execute_remote_stream(
                hostname, self._to_selector(selector), payload, caller, handler_timeout, deadline=deadline):
            yield item

    async def publish_event_remote(self, hostname: str, topic: str, payload: Any,
                                   caller: CallerCtx) -> None:
        await self.dispatch.publish_event_remote(hostname, topic, payload, caller)

    # ----------------------------------------------------------------------
    # legacy config-knob tolerance (set by _apply_yaml; stored)
    # ----------------------------------------------------------------------

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)

    # ----------------------------------------------------------------------
    # identity + peer parsing + config helpers
    # ----------------------------------------------------------------------

    def _safe_float(self, key: str, default: float) -> float:
        try:
            v = self._nw_cfg.get(key)
            return float(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    def _safe_int(self, key: str, default: int) -> int:
        try:
            v = self._nw_cfg.get(key)
            return int(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    def _resolve_keys_dir(self) -> Path:
        kd = self._nw_cfg.get("keys_dir")
        if kd:
            p = Path(kd)
            return p if p.is_absolute() else (self._config_dir / p)
        return self._config_dir / "keys"

    def _load_or_generate_identity(self):
        """Load own cert.pem/key.pem from keys_dir, or generate a long-lived self-signed
        pair on first boot (§4.1). Returns (cert_path, key_path, fingerprint, cert_pem)."""
        from ..serialization import generate_keypair
        cert_path = self._keys_dir / "cert.pem"
        key_path = self._keys_dir / "key.pem"
        if cert_path.exists() and key_path.exists():
            cert_pem = cert_path.read_text(encoding="utf-8")
            return cert_path, key_path, _spki_from_pem(cert_pem), cert_pem
        cp, kp, fp, cert_pem = generate_keypair(str(self._keys_dir), self.self_hostname)
        return Path(cp), Path(kp), fp, cert_pem

    @staticmethod
    def _parse_one_peer_spec(entry: dict, *, port_default: int,
                             seen_fp: set, seen_addr: set) -> PeerSpec:
        """Parse ONE `peers:` entry -> PeerSpec: derive `fingerprint` from `cert_pem`
        (§4.6), reject a declared-vs-derived fingerprint mismatch, split the
        framework's COMBINED `address:"host:port"` (learning 9, the #1 connect
        blocker). RAISES ValueError on a malformed entry / fingerprint mismatch /
        duplicate fingerprint / duplicate (ip,port); mutates `seen_fp`/`seen_addr`
        on success. No sockets/SSL/disk — the SINGLE source of truth shared by the
        live parse and the hot-reload dry-run."""
        try:
            hostname = str(entry["hostname"])
            cert_pem = entry["cert_pem"]
            derived_fp = _spki_from_pem(cert_pem)
        except Exception as e:
            raise ValueError(f"malformed peer entry {entry!r}: {e!r}") from e
        declared = entry.get("fingerprint")
        if declared and declared != derived_fp:
            raise ValueError(
                f"peer {hostname} fingerprint mismatch (config {declared!r} != derived {derived_fp!r})")
        if derived_fp in seen_fp:
            raise ValueError(f"duplicate peer fingerprint {derived_fp} ({hostname})")
        _raw = str(entry.get("ip") or entry.get("address") or "")
        if entry.get("port") is not None:
            ip, port = _raw, int(entry["port"])
        elif ":" in _raw and _raw.rpartition(":")[2].isdigit():
            _h, _, _p = _raw.rpartition(":")
            ip, port = _h, int(_p)
        else:
            ip, port = _raw, int(port_default)
        if (ip, port) in seen_addr:
            raise ValueError(f"duplicate peer address {ip}:{port} ({hostname})")
        seen_fp.add(derived_fp)
        seen_addr.add((ip, port))
        return PeerSpec(
            hostname=hostname, ip=ip, port=port, cert_pem=cert_pem, fingerprint=derived_fp,
            system_caller=bool(entry.get("system_caller", False)),
            dial=entry.get("dial"), source=PeerSource.CONFIG, vouched_by=None)

    def _parse_config_peers(self) -> List[PeerSpec]:
        """Parse `peers:` -> PeerSpec (§4.6). LENIENT: a malformed/invalid entry is
        SKIPPED with a warning so one bad peer does not abort boot. (The hot-reload
        pre-validation gate uses the STRICT `_parse_peers_dryrun` instead.)"""
        out: List[PeerSpec] = []
        seen_fp: set = set()
        seen_addr: set = set()
        for entry in (self._nw_cfg.get("peers") or []):
            try:
                out.append(self._parse_one_peer_spec(
                    entry, port_default=self.port, seen_fp=seen_fp, seen_addr=seen_addr))
            except Exception as e:
                self._logger.warning("skipping invalid peer entry: %s", e)
        return out

    @staticmethod
    def _parse_peers_dryrun(logger: logging.Logger, peers: List[dict], *,
                            port_default: int, keys_dir: Any = None) -> None:
        """Side-effect-free STRICT pre-validation of a candidate `peers:` list for a
        hot-reload (SPEC §4.6). RAISES on the first malformed entry / fingerprint
        mismatch / duplicate fingerprint / duplicate address, so a networking reload
        aborts CLEANLY (keeping the live network) instead of tearing it down just to
        surface a config typo. `keys_dir` is accepted for call-site signature parity
        but unused (fingerprints derive from `cert_pem`). No sockets/SSL/disk writes.
        B-079: this static helper was dropped in the netcore port; core's reconfigure
        gate `_validate_networking_config` calls it, so its absence made every rebuild-
        triggering reload AttributeError-abort, hanging any in-flight cross-node call."""
        seen_fp: set = set()
        seen_addr: set = set()
        for entry in (peers or []):
            NetworkManager._parse_one_peer_spec(
                entry, port_default=int(port_default), seen_fp=seen_fp, seen_addr=seen_addr)

    def _observe(self, event: str, payload: dict) -> None:
        """Emit a `_core/*` observability event through the core notifier (best-effort)."""
        emit = getattr(self._core, "_internal_emit", None)
        if emit is not None:
            try:
                emit(event, **(payload or {}))
            except Exception:
                pass

    # ----------------------------------------------------------------------
    # registry_provider (Directory build_pong export) — derive from the LIVE core registry
    # ----------------------------------------------------------------------

    class _RegistryProvider:
        """The object Directory consumes (`.endpoints()` / `.subs()`) each build_pong,
        deriving the export material from the LIVE core registry (SPEC §4.3)."""

        def __init__(self, mgr: "NetworkManager") -> None:
            self._mgr = mgr

        def endpoints(self) -> List[dict]:
            return self._mgr._export_endpoints()

        def subs(self) -> List[dict]:
            return self._mgr._export_subs()

    def _export_endpoints(self) -> List[dict]:
        endpoints: List[dict] = []
        for plugin in list(getattr(self._core, "plugins", {}).values()):
            if not getattr(plugin, "enabled", False):
                continue
            plugin_remote = bool(getattr(plugin, "remote", False))
            for access_name, ep in getattr(plugin, "endpoints", {}).items():
                endpoints.append({
                    "access_name": access_name,
                    "plugin_name": getattr(plugin, "plugin_name", ""),
                    "plugin_uuid": getattr(plugin, "plugin_uuid", ""),
                    "plugin_version": str(getattr(plugin, "version", "unknown")),
                    "description": ep.get("description", ""),
                    "arguments": ep.get("arguments") or {},
                    "tags": ep.get("tags") or [],
                    "remote": plugin_remote and bool(ep.get("remote", False)),
                    "accessible_by_other_plugins": bool(ep.get("accessible_by_other_plugins", False)),
                    "enabled": True,
                    "owner_active": bool(getattr(plugin, "enabled", False)),
                })
        return endpoints

    def _export_subs(self) -> List[dict]:
        subs: List[dict] = []
        for sub in self._enumerate_local_subs():
            # A Subscription has NO `remote` field: remote-eligibility is DERIVED
            # (enabled AND hosts != "local"). `hosts`/`authors` are exported RAW so the
            # receiver core filter chain interprets them identically (learning 13).
            remote_eligible = bool(getattr(sub, "enabled", True)) and getattr(sub, "hosts", None) != "local"
            subs.append({
                "sub_uuid": getattr(sub, "sub_uuid", None),
                "topic_pattern": getattr(sub, "topic_pattern", ""),
                "authors": getattr(sub, "authors", None),
                "blocked_authors": getattr(sub, "blocked_authors", None),
                "hosts": getattr(sub, "hosts", None),
                "blocked_hosts": getattr(sub, "blocked_hosts", None),
                "plugin_name": getattr(sub, "plugin_name", ""),
                "remote": remote_eligible,
                "enabled": bool(getattr(sub, "enabled", True)),
                "owner_active": self._sub_owner_active(sub),
            })
        return subs

    def _enumerate_local_subs(self) -> list:
        """Every local subscription, sync (learning 13): `topic_registry.list_local_subs()`
        is ASYNC — but build_pong runs in ONE sync await-free pass, so read the underlying
        `_subs` store DIRECTLY as a GIL-atomic `list(...)` snapshot (`list(async_fn())`
        silently returns [] -> ZERO subs exported -> every inbound event NO_MATCH)."""
        tr = getattr(self._core, "topic_registry", None)
        if tr is None:
            return []
        store = getattr(tr, "_subs", None)
        if store is None:
            return []
        try:
            return list(store.values())
        except Exception:
            return []

    def _sub_owner_active(self, sub) -> bool:
        fn = getattr(self._core, "_sub_owner_active", None)
        if fn is not None:
            try:
                return bool(fn(sub))
            except Exception:
                return True
        return True

    # ----------------------------------------------------------------------
    # injected seams for Dispatch (re-match registry + rate) — adapt the core notifier
    # ----------------------------------------------------------------------

    class _RematchRegistry:
        """Dispatch re-match provider backed by the LIVE core notifier (B's Dispatch
        contract: execute/request_event/request_event_stream/execute_stream/publish_event).
        EXECUTE delegates to `core.execute(..., hosts="local")`; events delegate WHOLE-mode
        to `core._fanout_sub` (publisher=None + remote_publisher_* — the notifier applies the
        5-predicate chain + charges the IN-set + runs the handler; NOT per-sub, else FANOUT
        N×-delivers). The cross-node accepting-sub pre-filter is here (§4.5)."""

        def __init__(self, core: Any) -> None:
            self._core = core

        # -- EXECUTE ---------------------------------------------------------

        def _match_execute(self, selector):
            for p in list(getattr(self._core, "plugins", {}).values()):
                if not getattr(p, "enabled", False):
                    continue
                if getattr(p, "plugin_name", None) != selector.plugin:
                    continue
                ep = getattr(p, "endpoints", {}).get(selector.endpoint)
                if ep is None:
                    continue
                # uuid-exact (§F#14): a same-name-different-uuid instance must NOT answer.
                if selector.plugin_uuid and getattr(p, "plugin_uuid", "") != selector.plugin_uuid:
                    continue
                if not (bool(getattr(p, "remote", False)) and bool(ep.get("remote", False))):
                    continue
                if not bool(ep.get("accessible_by_other_plugins", False)):
                    continue
                return p
            return None

        async def execute(self, selector, payload, identity, caller):
            """UNARY execute -> core.execute local; NoEndpointError if no matching
            (name+uuid+remote+accessible) endpoint (-> NO_ENDPOINT -> fall through)."""
            if self._match_execute(selector) is None:
                raise NoEndpointError(f"{selector.plugin}.{selector.endpoint} uuid={selector.plugin_uuid}")
            return await self._core.execute(
                selector.plugin, selector.endpoint, args=payload,
                plugin_uuid=selector.plugin_uuid, hosts="local",
                author=caller.author, author_id=caller.author_id,
                author_host=identity.hostname)

        def execute_stream(self, selector, payload, identity, caller):
            """STREAM execute (async-gen). A GENERATOR endpoint drives `core.execute_stream`
            (NOT the unary handler -> 'method is a generator', learning 16)."""
            return self._exec_stream(selector, payload, identity, caller)

        async def _exec_stream(self, selector, payload, identity, caller):
            if self._match_execute(selector) is None:
                raise NoEndpointError(f"{selector.plugin}.{selector.endpoint} uuid={selector.plugin_uuid}")
            async for item in self._core.execute_stream(
                    selector.plugin, selector.endpoint, args=payload,
                    plugin_uuid=selector.plugin_uuid, hosts="local",
                    author=caller.author, author_id=caller.author_id,
                    author_host=identity.hostname):
                yield item

        # -- EVENTS (whole-mode delegate to the notifier _fanout_sub path) ---

        async def _accepting_subs(self, topic: str, identity, caller) -> list:
            core = self._core
            subs = await core.topic_registry.find_all(topic)   # literal topic -> matching sub patterns
            out = []
            for sub in subs:
                if not core._sub_owner_active(sub):
                    continue
                if not core._sub_accepts_remote_publisher(sub, identity.hostname, caller.author):
                    continue
                if not core._sub_accepts_author(sub, caller.author):
                    continue
                out.append(sub)
            return out

        def _fan(self, sub, topic, payload, identity, caller, kind, timeout):
            return self._core._fanout_sub(
                sub=sub, publisher=None, resolved_topic=topic, payload=payload,
                kind=kind, timestamp=_time.time(), timeout=timeout,
                remote_publisher_name=caller.author,
                remote_publisher_uuid=caller.author_id,
                remote_publisher_host=identity.hostname)

        async def request_event(self, topic, payload, identity, caller):
            """FIRST: the first accepting local sub answers; NoLocalSub if none."""
            from ..exceptions import NoLocalSubException, RequestException
            for sub in await self._accepting_subs(topic, identity, caller):
                req = await self._fan(sub, topic, payload, identity, caller, "request_event", None)
                if req is None:
                    continue
                result, error, _ = await req.wait_for_result_async()
                self._core.requests.pop(req.id, None)
                if error:
                    raise result if isinstance(result, BaseException) else RequestException(str(result))
                return result
            raise NoLocalSubException(f"no local subscriber matches {topic!r}")

        async def publish_event(self, topic, payload, identity, caller):
            """FANOUT: deliver to EVERY accepting local sub (one _fanout_sub each — correct
            fan-out, not N×); fire-and-forget, no reply."""
            for sub in await self._accepting_subs(topic, identity, caller):
                await self._fan(sub, topic, payload, identity, caller, "publish_event", None)

        def request_event_stream(self, topic, payload, identity, caller):
            """STREAM (async-gen): the first accepting sub routes the topic to its target
            endpoint; the stream = the core's LOCAL execute_stream. The FIRST item is
            Event-wrapped (LOCKED I, matching _process_request_event_stream), rest raw;
            NoLocalSub if none (learning 15)."""
            return self._req_stream(topic, payload, identity, caller)

        async def _req_stream(self, topic, payload, identity, caller):
            from ..exceptions import NoLocalSubException, RequestException
            from ..utils import Event
            subs = await self._accepting_subs(topic, identity, caller)
            if not subs:
                raise NoLocalSubException(f"no local subscriber matches {topic!r}")
            sub = subs[0]
            target_plugin = getattr(sub, "target_plugin", None) or getattr(sub, "plugin_name", None)
            target_method = getattr(sub, "target_access_name", None)
            sub_id = getattr(sub, "declared_id", None)
            if sub_id is None:
                sub_id = getattr(sub, "sub_uuid", None)

            # B-090: the ACCESS identity is the local sub OWNER, never the wire
            # author_id. Without this stamp, _process_request_stream falls back to
            # `request.requester_id or request.author_id` (core.py:6459) and hands
            # find_endpoint an attacker-controlled uuid: a pinned peer could name any
            # local plugin uuid to take the LOCAL branch (core.py:5187), skipping the
            # remote gate, and by naming the TARGET's own uuid also clear
            # accessible_by_other_plugins. This mirrors what _fanout_sub already does
            # for the unary topic paths (events.py:1216 "C18") and what the local
            # request_event_stream does (events.py:2033), so the stream variant grants
            # exactly what the non-stream variant grants -- no more, no less. The wire
            # author/author_id stay on the Request and on the Event below: they are
            # provenance, not authority. The hook runs before the producer is spawned
            # (core.py:4929-4936), so there is no race with the reader.
            def _stamp_requester(request):
                request.requester_id = sub.plugin_uuid

            # _create_gen_request_gated (not create_gen_request) keeps the capability
            # gate and the OUT rate admit. Hosts are passed pre-normalized, exactly as
            # execute_stream would after _validate_host_args.
            request = await self._core._create_gen_request_gated(
                target_plugin, target_method, payload,
                getattr(sub, "target_plugin_uuid", None),
                "local", None, caller.author, caller.author_id,
                None, identity.hostname, None,
                _post_construct_hook=_stamp_requester,
            )
            first = True
            try:
                async for item, error, _ in request.get_queue_stream():
                    if error:
                        # Preserve a RequestException SUBTYPE by re-raising the OBJECT.
                        raise item if isinstance(item, RequestException) else RequestException(item)
                    if first:
                        yield Event(topic=topic, payload=item, author=caller.author,
                                    author_id=caller.author_id, author_host=identity.hostname,
                                    subscription_id=sub_id, timestamp=_time.time())
                        first = False
                    else:
                        yield item
            finally:
                # Mandatory: without it an abandoned/cancelled remote stream leaks the
                # GeneratorRequest (same reason as execute_stream's finally).
                await request.set_collected()

    class _RateSeam:
        """Inbound rate charge (§8.2) — delegates to the core's canonical
        `_rl_admit_inbound(peer, include_framework)` (learning 12: nodes_in is a
        DYNAMIC-key bucket; a plain `get('nodes_in', host)` misses it). `charge_nodes_in`
        charges nodes_in ONLY (include_framework=False); `charge_framework_in` charges
        framework ONLY (peer=None). Fail-OPEN on a seam error."""

        def __init__(self, core: Any) -> None:
            self._core = core

        def charge_nodes_in(self, hostname: str) -> bool:
            fn = getattr(self._core, "_rl_admit_inbound", None)
            if fn is None:
                return True
            try:
                return fn(hostname, False) is None   # nodes_in only; None == admitted
            except Exception:
                return True                          # fail-open

        def charge_framework_in(self) -> bool:
            fn = getattr(self._core, "_rl_admit_inbound", None)
            if fn is None:
                return True
            try:
                return fn(None, True) is None        # framework only; None == admitted
            except Exception:
                return True
