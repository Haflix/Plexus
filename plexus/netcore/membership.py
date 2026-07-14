"""netcore.membership — §4.2/§4.6/§4.7 Membership + §4.1 mTLS context-provider.

Roster = config-set peers + runtime-added + vouched, minus removed/revoked
(tombstoned). THREE await-free SYNC mutators (``add_peer``, ``remove_peer``,
``ingest_vouched``); each is ONE await-free critical section, dedup-check +
insert/remove in the SAME tick (§F#1). The mTLS SSL contexts + the SPKI pin set
are rebuilt as NEW immutable objects on ANY roster change, never mutated in place
(§4.1/§F#11); the ACCEPTOR context refresh rides an ``sni_callback`` that swaps to
the live server context per inbound connection (so a runtime ADD's cert is trusted
at the TLS layer without re-binding the listener).

Liveness = ``last_seen`` (monotonic), ``reachable_set``, ``last_epoch``; writers =
the pulse-path (sweep + link-up one-shot) AND ``remove_peer``; all roster-gated
(§F#3) + rebind-not-mutate for the values Directory reads across awaits (§7).
Discovery ingest (§4.7) is source-voucher-gated + fully validated + budget-capped
+ LAN-CIDR-gated. ALL tombstones (config + vouched) are persisted (§F#15).

Collaborator seams (the two still-stub modules are INJECTED so this builds +
self-tests standalone):
  * Transport (DONE, used for real): ``start_link(spec)`` / ``stop_link(hostname)``
    / ``ping(hostname, have_hash, deadline) -> Pong`` / ``self.membership`` (Transport
    calls back the context-provider methods below). The flap-guard promotion/discard
    cycle LIVES in Transport (``_probation_promote`` + ``for_ping`` routing); the pulse
    DRIVES it by pinging (Transport routes the ping over the probationary link).
  * Directory (stub): ``have_hash(peer) -> str`` / ``replace(peer, snapshot)`` /
    ``drop_remote(hostname)`` (revoke cleanup) / ``build_pong`` (served by Transport's
    inbound-PING path, not called here).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import ssl
import time
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .types import (
    LinkDown,
    LinkRefused,
    PeerIdentity,
    PeerSource,
    PeerSpec,
    ProtocolError,
    Timeout,
    VouchedPeer,
)

_logger = logging.getLogger("plexus.netcore.membership")


# --- SPEC §11 defaults ------------------------------------------------------
HEARTBEAT_INTERVAL = 10.0
PROBE_TIMEOUT = 2.0
LIVENESS_TIMEOUT = 30.0
VOUCHER_ACTIVE_CAP = 64
DEFAULT_LAN_CIDR = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fd00::/8",
]


def _spki_fingerprint_from_pem(cert_pem: str) -> str:
    """Compute ``sha256:<hex>`` of a PEM cert's SubjectPublicKeyInfo DER (SPEC
    §4.1/§4.6) — mirrors ``serialization.generate_keypair`` / transport's SPKI."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


class Membership:
    """Roster/pin/tombstone + liveness + pulse + discovery + the §4.1 mTLS
    context-provider (SPEC §4.1/§4.2/§4.6/§4.7)."""

    def __init__(
        self,
        *,
        self_hostname: str,
        cert_file: Any,
        key_file: Any,
        directory: Any,
        transport: Any = None,
        observe: Any = None,
        tombstone_path: Optional[Any] = None,
        lan_cidr: Optional[List[str]] = None,
        default_port: int = 2510,
        voucher_cap: int = VOUCHER_ACTIVE_CAP,
        heartbeat_interval: float = HEARTBEAT_INTERVAL,
        probe_timeout: float = PROBE_TIMEOUT,
        liveness_timeout: float = LIVENESS_TIMEOUT,
        require_peers: bool = True,
        discoverable: bool = False,
    ):
        self.self_hostname = self_hostname
        self._cert_file = str(cert_file)
        self._key_file = str(key_file)
        self._directory = directory
        self._transport = transport
        self._observe_cb = observe
        self._default_port = default_port
        self._voucher_cap = voucher_cap
        self._heartbeat_interval = heartbeat_interval
        self._probe_timeout = probe_timeout
        self._liveness_timeout = liveness_timeout
        self._require_peers = require_peers
        # §4.7: discovery is OPT-IN (default OFF). An OFF node NEVER ingests a vouched
        # peer (never pins a learned peer -> refuses its handshake), so a star stays a
        # star; an edge forms only when BOTH ends are discoverable=on.
        self._discoverable = bool(discoverable)

        # The loop is captured lazily on-loop (start / on_link_up / pulse), NOT at
        # construction — the attach_transport late-bind means __init__ may run
        # off-loop (F#4e). Background tasks are stashed to defeat weak-ref GC (F#4f).
        self._bg_tasks: set = set()

        # LAN-CIDR gate for vouched addresses (§4.7).
        self._lan_networks = [
            ipaddress.ip_network(c) for c in (lan_cidr or DEFAULT_LAN_CIDR)
        ]

        # --- roster / pin / tombstone / voucher budget (rebind-not-mutate for
        #     the cross-await readers; §7). ------------------------------------
        self._roster: Dict[str, PeerSpec] = {}
        self._pin_by_fp: Dict[str, str] = {}            # fingerprint -> hostname
        self._per_voucher_active: Dict[str, int] = {}   # voucher hostname -> count

        # --- liveness --------------------------------------------------------
        self._last_seen: Dict[str, float] = {}          # monotonic
        self._reachable_set: FrozenSet[str] = frozenset()
        self._last_epoch: Dict[str, str] = {}

        # --- tombstone persistence (§F#15) -----------------------------------
        self._tombstone_path: Optional[Path] = (
            Path(tombstone_path) if tombstone_path else None
        )
        self._tombstone: FrozenSet[str] = self._load_tombstones()

        # --- mTLS contexts (§4.1). Own-keypair-mismatch fails LOUD here
        #     (load_cert_chain raises on a mismatched cert/key). --------------
        self._live_server_ctx: Optional[ssl.SSLContext] = None
        self._live_client_ctx: Optional[ssl.SSLContext] = None
        self._listener_ctx: Optional[ssl.SSLContext] = None
        self._rebuild_contexts(self._roster)  # validates own keypair (raises loud)

        self._running = False
        self._pulse_task: Optional[asyncio.Task] = None

    # ---------------------------------------------------------------------
    # Wiring + lifecycle
    # ---------------------------------------------------------------------
    def attach_transport(self, transport: Any) -> None:
        """Late-bind Transport (Transport's ctor needs Membership first)."""
        self._transport = transport

    def seed_config_peers(self, specs: List[PeerSpec]) -> None:
        """Boot/reload seeding = a batch of ``add_peer``, EXCEPT a hostname whose
        runtime-revoke is persisted is WARN+SKIPPED (revoke durability, §4.6/
        §F#15). An explicit operator ``add_peer`` is still the only tombstone
        clear."""
        for spec in specs:
            if spec.hostname in self._tombstone:
                _logger.warning(
                    "skip re-adding runtime-revoked peer %s (persisted tombstone)",
                    spec.hostname,
                )
                continue
            self.add_peer(spec)

    async def start(self) -> None:
        """Empty-``peers`` with networking enabled = hard error (§4.1). Start the
        single pulse task."""
        if self._require_peers and not self._roster:
            raise RuntimeError(
                "empty peers: with networking enabled is a hard boot error (§4.1)"
            )
        self._running = True
        self._pulse_task = asyncio.get_running_loop().create_task(self.pulse_all())

    async def stop(self) -> None:
        """Stop the pulse task (SPEC §3)."""
        self._running = False
        task = self._pulse_task
        self._pulse_task = None
        if task is not None:
            task.cancel()
            # gather(return_exceptions=True) captures the pulse task's OWN
            # CancelledError as a result (swallowed) while a CancelledError
            # targeting stop() ITSELF still propagates (F#4d).
            await asyncio.gather(task, return_exceptions=True)
        # F1 (panel robustness): the fire-and-forget pulse_one tasks spawned by
        # on_link_up via _spawn are also cancelled AND awaited here, else they
        # leak past shutdown (a task mid-`await pong.snapshot` would outlive stop).
        bg = list(self._bg_tasks)
        if bg:
            for t in bg:
                t.cancel()
            await asyncio.gather(*bg, return_exceptions=True)

    def _spawn(self, coro) -> "asyncio.Task":
        """Create + STASH a background task (defeats asyncio's weak-ref GC of
        fire-and-forget tasks, F#4f)."""
        task = asyncio.get_running_loop().create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    # ---------------------------------------------------------------------
    # §4.1 mTLS context-provider seam (Transport calls these)
    # ---------------------------------------------------------------------
    def _cadata_for(self, roster: Dict[str, PeerSpec]) -> str:
        """Concatenated PEMs of the currently-pinned peers = the CA-cadata trust
        store (SPEC §4.1 — each self-signed peer cert loaded as its own CA)."""
        return "\n".join(s.cert_pem for s in roster.values())

    def _new_context(self, protocol: int, cadata: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(protocol)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # reference-parity (§4.1)
        ctx.check_hostname = False                 # SPKI pin is the trust gate
        ctx.verify_mode = ssl.CERT_REQUIRED
        # NOTE: stdlib ``SSLContext.load_cert_chain`` takes file PATHS only (no
        # from-memory API), so a fresh context on a roster change re-reads the
        # own cert+key from disk — unavoidable + negligible at <=15-node scale.
        ctx.load_cert_chain(certfile=self._cert_file, keyfile=self._key_file)
        if cadata:
            ctx.load_verify_locations(cadata=cadata)
        return ctx

    def _rebuild_contexts(self, roster: Dict[str, PeerSpec]) -> None:
        """Rebuild the server + client contexts IMMUTABLY as NEW objects (§4.1/
        §F#11). The listener context (bound once by Transport.start) is stable;
        its ``sni_callback`` swaps to the fresh ``_live_server_ctx`` per inbound
        connection, so a runtime ADD's cert is trusted without re-binding."""
        cadata = self._cadata_for(roster)
        self._live_server_ctx = self._new_context(ssl.PROTOCOL_TLS_SERVER, cadata)
        self._live_client_ctx = self._new_context(ssl.PROTOCOL_TLS_CLIENT, cadata)

    def _sni_swap(self, sslobj, server_name, ssl_context):  # noqa: ANN001
        """sni_callback on the bound listener context: swap to the LIVE server
        context (fresh cadata) for THIS connection (acceptor context-refresh,
        the phase-2b carry-over). Runs before client-cert verification, so the
        new peer's cert is trusted at the TLS layer post-ADD."""
        live = self._live_server_ctx
        if live is not None:
            try:
                sslobj.context = live
            except Exception:  # noqa: BLE001 - never crash the handshake
                pass
        return None

    def server_ssl_context(self) -> ssl.SSLContext:
        """The STABLE listener context Transport binds once; its sni_callback
        redirects every inbound connection to the LIVE server context (SPEC
        §4.1 + carry-over). The swap TARGET (``_live_server_ctx``) is rebuilt
        immutably on every roster change, so the SNI path is always current.

        Residual (F#3): a NO-SNI ClientHello never fires the callback -> that one
        connection falls back to THIS bound context's boot-era CA store. It is
        (a) unreachable for our mesh — our dialer ALWAYS sends SNI and the TLS-1.3
        floor forces a fresh ClientHello — and (b) security-backstopped by the
        live SPKI post-check. Refreshing the bound-once listener would need
        add-only mutation of a live context (violates §F#11) or a listener re-bind
        (the close+reopen robustness bug), so it is intentionally left."""
        if self._listener_ctx is None:
            ctx = self._new_context(
                ssl.PROTOCOL_TLS_SERVER, self._cadata_for(self._roster)
            )
            ctx.sni_callback = self._sni_swap
            self._listener_ctx = ctx
        return self._listener_ctx

    def client_ssl_context(self) -> ssl.SSLContext:
        """The current client context (rebuilt on change; Transport fetches it
        fresh per dial attempt, so it is always live) (SPEC §4.1)."""
        return self._live_client_ctx

    def resolve_pin(self, fingerprint: str) -> Optional[str]:
        """Map a presented SPKI fingerprint to the pinned hostname, or None to
        FAIL CLOSED (SPEC §4.1). Dereferences the LIVE pin set at check time."""
        return self._pin_by_fp.get(fingerprint)

    def in_roster(self, hostname: str) -> bool:
        """Roster gate (SPEC §4.2/§4.6)."""
        return hostname in self._roster

    def identity_for(self, hostname: str) -> PeerIdentity:
        """Authenticated identity from the roster record (SPEC §8.1); a vouched
        peer has ``system_caller=False`` (discovery confers no escalation)."""
        spec = self._roster.get(hostname)
        return PeerIdentity(hostname, bool(spec.system_caller) if spec else False)

    # ---------------------------------------------------------------------
    # §4.6 the three await-free SYNC mutators
    # ---------------------------------------------------------------------
    def add_peer(self, spec: PeerSpec) -> None:
        """Insert/seed a peer (SPEC §4.6). CLEAR the tombstone (explicit add is
        the ONLY clear), then insert into roster + pin set + rebuild the CA
        context, start the generation-tagged supervisor. Idempotent. ONE
        await-free critical section — the NEW context is BUILT first (may raise on
        a bad PEM) and only then are roster/pin/context COMMITTED, so a failure
        leaves state consistent (§F#1: no await between check and insert)."""
        hostname = spec.hostname
        # idempotent: already pinned with the same fingerprint -> no-op.
        cur = self._roster.get(hostname)
        if cur is not None and cur.fingerprint == spec.fingerprint:
            return
        # build the NEW immutable context from a candidate roster FIRST (may raise
        # on a bad PEM) — BEFORE any state change, so a failure leaves state
        # consistent (§F#1). The tombstone clear is DEFERRED into the commit block
        # (F#1 fix): a bad-PEM add for a revoked hostname must NOT wipe the
        # persisted tombstone and then abort (revoke-durability hole).
        candidate = dict(self._roster)
        candidate[hostname] = spec
        cadata = self._cadata_for(candidate)
        new_server = self._new_context(ssl.PROTOCOL_TLS_SERVER, cadata)
        new_client = self._new_context(ssl.PROTOCOL_TLS_CLIENT, cadata)
        new_pin = dict(self._pin_by_fp)
        # a re-key (same hostname, different fp) drops the old fp mapping.
        if cur is not None:
            new_pin.pop(cur.fingerprint, None)
        new_pin[spec.fingerprint] = hostname
        # --- COMMIT (all rebinds, no await) ---
        # CLEAR the tombstone here (explicit add is the ONLY clear) — after the
        # context build succeeded, so a failed add never wipes a revoke.
        if hostname in self._tombstone:
            self._tombstone = frozenset(self._tombstone - {hostname})
            self._persist_tombstones()
        self._roster = candidate
        self._pin_by_fp = new_pin
        self._live_server_ctx = new_server
        self._live_client_ctx = new_client
        # start (or generation-bump) the supervisor.
        if self._transport is not None:
            self._transport.start_link(spec)

    def remove_peer(self, hostname: str) -> None:
        """Remove/revoke a peer (SPEC §4.6). Write the HOSTNAME-keyed persisted
        tombstone, remove from roster + pin + rebuild context, CLEAR last_seen /
        rebind reachable_set + drop the remote snapshot WITHOUT the peer,
        DECREMENT its voucher's active count, clear last_epoch, tear down the
        link. ONE await-free critical section, roster-gated."""
        cur = self._roster.get(hostname)
        # build the NEW contexts BEFORE any commit (symmetry with add_peer) — the
        # remaining peers' PEMs are pre-validated so this won't raise, but keeping
        # the all-or-nothing shape means a failure never half-applies a revoke.
        new_roster = new_pin = new_server = new_client = None
        if cur is not None:
            new_roster = dict(self._roster)
            del new_roster[hostname]
            new_pin = dict(self._pin_by_fp)
            new_pin.pop(cur.fingerprint, None)
            cadata = self._cadata_for(new_roster)
            new_server = self._new_context(ssl.PROTOCOL_TLS_SERVER, cadata)
            new_client = self._new_context(ssl.PROTOCOL_TLS_CLIENT, cadata)
        # --- COMMIT ---
        # durable tombstone (persisted) — a revoke stands even for a hostname not
        # currently rostered (pre-emptive revoke) (§F#15).
        self._tombstone = frozenset(self._tombstone | {hostname})
        self._persist_tombstones()
        if cur is None:
            return
        # decrement the voucher's active budget (§4.7 churn-safe).
        if cur.vouched_by:
            self._decrement_voucher(cur.vouched_by)
        self._roster = new_roster
        self._pin_by_fp = new_pin
        self._live_server_ctx = new_server
        self._live_client_ctx = new_client
        # clear liveness (revoke cleanup, rebind reachable_set).
        self._last_seen.pop(hostname, None)
        self._last_epoch.pop(hostname, None)
        self._reachable_set = frozenset(self._reachable_set - {hostname})
        # drop the remote directory snapshot (roster-gate also stops routing).
        try:
            self._directory.drop_remote(hostname)
        except Exception:  # noqa: BLE001 - directory is a seam
            pass
        # tear down the link.
        if self._transport is not None:
            self._transport.stop_link(hostname)
        self._observe("_core/peer/down", {"hostname": hostname, "reason": "revoked"})

    def ingest_vouched(
        self, voucher: str, vouched_list: List[VouchedPeer]
    ) -> None:
        """Discovery ingest (SPEC §4.7, await-free). If this node is NOT
        `discoverable` -> NO-OP (the opt-in gate: an OFF node stays as configured and
        never pins a learned peer, keeping a star a star). If the SOURCE voucher is
        tombstoned or not-in-roster at apply time -> NO-OP the WHOLE call (a
        removed voucher's in-flight snapshot must not seed adds)."""
        if not self._discoverable:
            return
        if voucher in self._tombstone or voucher not in self._roster:
            return
        for entry in vouched_list:
            self._ingest_one(voucher, entry)

    def _ingest_one(self, voucher: str, entry: VouchedPeer) -> None:
        hostname = entry.hostname
        if hostname == self.self_hostname:
            return  # skip self
        # tombstone check ordered BEFORE the conflict path (§4.6).
        if hostname in self._tombstone:
            return
        cur = self._roster.get(hostname)
        if cur is not None:
            # a CONFIG pin is never overwritten; a known-hostname re-vouch is
            # idempotent-skip (churn-safe, §F#21); fp-mismatch -> conflict.
            if cur.fingerprint != entry.fingerprint:
                self._observe(
                    "_core/peer/vouch_conflict",
                    {
                        "hostname": hostname,
                        "existing_fingerprint": cur.fingerprint,
                        "vouched_fingerprint": entry.fingerprint,
                        "voucher_hostname": voucher,
                    },
                )
            return
        # per-voucher ACTIVE budget cap (§4.7).
        if self._per_voucher_active.get(voucher, 0) >= self._voucher_cap:
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "budget", "voucher_hostname": voucher},
            )
            return
        # mirror ALL config-time validations (§4.6): cert parses, SPKI==declared
        # fingerprint, dup-fingerprint, well-formed host:port, LAN CIDR,
        # dup-(ip,port) — BEFORE the entry reaches roster/pin/CA-cadata.
        try:
            derived_fp = _spki_fingerprint_from_pem(entry.cert_pem)
        except Exception:  # noqa: BLE001 - malformed PEM would poison cadata
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "cert_parse", "voucher_hostname": voucher},
            )
            return
        if derived_fp != entry.fingerprint:
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "fingerprint_mismatch",
                 "voucher_hostname": voucher},
            )
            return
        if entry.fingerprint in self._pin_by_fp:
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "dup_fingerprint",
                 "voucher_hostname": voucher},
            )
            return
        ip, port = self._parse_address(entry.address)
        if ip is None:
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "bad_address", "voucher_hostname": voucher},
            )
            return
        if not self._in_lan_cidr(ip):
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "cidr", "address": entry.address,
                 "voucher_hostname": voucher},
            )
            return
        if any(s.ip == ip and s.port == port for s in self._roster.values()):
            self._observe(
                "_core/peer/vouch_rejected",
                {"hostname": hostname, "reason": "dup_address", "voucher_hostname": voucher},
            )
            return
        # accepted: a vouched peer gets system_caller=False + no dial override
        # (discovery MUST NOT confer system-caller rights, §8.1).
        spec = PeerSpec(
            hostname=hostname,
            ip=ip,
            port=port,
            cert_pem=entry.cert_pem,
            fingerprint=derived_fp,
            system_caller=False,
            dial=None,
            source=PeerSource.VOUCHED,
            vouched_by=voucher,
        )
        self.add_peer(spec)
        # increment the voucher's ACTIVE count AFTER the successful add.
        self._per_voucher_active[voucher] = (
            self._per_voucher_active.get(voucher, 0) + 1
        )
        self._observe(
            "_core/peer/vouched",
            {"hostname": hostname, "fingerprint": derived_fp, "voucher_hostname": voucher},
        )

    def _decrement_voucher(self, voucher: str) -> None:
        cnt = self._per_voucher_active.get(voucher, 0)
        if cnt > 0:
            self._per_voucher_active[voucher] = cnt - 1

    # ---------------------------------------------------------------------
    # §4.2 pulse + liveness
    # ---------------------------------------------------------------------
    async def pulse_all(self) -> None:
        """The single pulse task (SPEC §4.2): each heartbeat, gather ``pulse_one``
        over an IMMUTABLE roster snapshot (return_exceptions — MUST inspect for
        poison-peer isolation), derive ``reachable_set`` = roster INTERSECT
        fresh(``last_seen.get(p,-inf)``), sleep."""
        while self._running:
            roster_snap = self.roster_snapshot()
            if roster_snap:
                results = await asyncio.gather(
                    *(self.pulse_one(p) for p in roster_snap),
                    return_exceptions=True,
                )
                for peer, res in zip(roster_snap, results):
                    if isinstance(res, BaseException) and not isinstance(
                        res, asyncio.CancelledError
                    ):
                        # poison-peer isolation: log + keep the loop alive.
                        _logger.warning("pulse poison peer %s: %r", peer, res)
            # derive reachable_set + emit peer/down on any reachable->unreachable
            # transition (§F#10: .get(p,-inf), never a bare index).
            self._recompute_reachable()
            await asyncio.sleep(self._heartbeat_interval)

    def _recompute_reachable(self) -> None:
        """Recompute ``_reachable_set`` from ``last_seen`` age-out and emit
        ``_core/peer/down`` for every peer that transitioned reachable -> unreachable
        on this pass (silent death: liveness age-out / link-drop / hard-refuse).

        Edge-triggered: the event fires ONCE, on the transition (the peer leaves
        ``_reachable_set``), never every pulse. The revoke path (``remove_peer``)
        already pulls the peer from ``_reachable_set`` and emits its own
        ``_core/peer/down(reason="revoked")``, so it is never re-emitted here as
        "unreachable". Symmetric with the ``_core/peer/up`` emit in ``on_link_up``.
        """
        now = time.monotonic()
        new_reachable = frozenset(
            p
            for p in self._roster
            if (now - self._last_seen.get(p, float("-inf")))
            < self._liveness_timeout
        )
        for gone in (self._reachable_set - new_reachable):
            self._observe(
                "_core/peer/down", {"hostname": gone, "reason": "unreachable"}
            )
        self._reachable_set = new_reachable

    async def pulse_one(self, peer: str) -> None:
        """One peer's pulse (SPEC §4.2). Ping (returns on the PONG HEADER, routed
        by Transport over the PROBATIONARY link during a flap), ROSTER-GATED
        stamp of last_seen + last_epoch (revoke-during-await safe, §F#3), and if
        ``snapshot_follows`` reassemble AFTER the stamp then
        ``directory.replace`` + ``ingest_vouched`` (both gated)."""
        have = self._directory.have_hash(peer)
        # RELATIVE deadline (transport.ping arms it via call_later(max(0, deadline))).
        deadline = self._probe_timeout
        try:
            pong = await self._transport.ping(peer, have, deadline)
        except LinkRefused:
            # hard-down fast-path, ROSTER-GATED (§4.2/§F#3).
            if peer in self._roster:
                self._last_seen[peer] = float("-inf")
            return
        except (LinkDown, Timeout, ProtocolError):
            return  # transient: age out
        # success — ROSTER-GATED stamp in this arm too (§F#3).
        self._stamp_alive(peer, pong.epoch)
        if pong.snapshot_follows and pong.snapshot is not None:
            try:
                snap = await pong.snapshot  # reassembly AFTER the stamp
            except Exception:  # noqa: BLE001 - snapshot dropped -> peer stays reachable
                return
            # G7 companion: a dropped/over-bound/undecodable snapshot on a LIVE peer now
            # resolves to None (Transport carve-out) instead of raising — apply NO snapshot
            # in that case (peer already stamped reachable). Mirrors A's `if snap is not
            # None` guard; without it directory.replace(peer, None) would fault.
            if snap is not None and peer in self._roster:  # roster-gated replace (§4.3)
                try:
                    self._directory.replace(peer, snap)
                except Exception:  # noqa: BLE001 - directory seam
                    pass
                self.ingest_vouched(peer, getattr(snap, "vouched_peers", []) or [])

    def _stamp_alive(self, peer: str, epoch: Optional[str]) -> None:
        """ROSTER-GATED live stamp (§F#3): the success arm of a pulse. Also stores
        last_epoch + fires ``_core/peer/restarted`` on an epoch change (§4.2/§4.3,
        independent of the apply decision)."""
        if peer not in self._roster:
            return
        self._last_seen[peer] = time.monotonic()
        if epoch is not None:
            prev = self._last_epoch.get(peer)
            if prev is not None and epoch != prev:
                self._observe(
                    "_core/peer/restarted", {"hostname": peer, "epoch": epoch}
                )
            self._last_epoch[peer] = epoch

    def on_link_up(self, hostname: str) -> None:
        """Link-supervisor callback on connect-success (SPEC §4.2 routable-after-
        add SLA): ROSTER-GATED stamp of last_seen, add to reachable_set at once
        (routable within a heartbeat OF LINK-UP), THEN fire a one-shot pulse to
        fetch the directory snapshot. Sync + await-free."""
        if hostname not in self._roster:
            return
        self._last_seen[hostname] = time.monotonic()
        self._reachable_set = frozenset(self._reachable_set | {hostname})
        self._observe("_core/peer/up", {"hostname": hostname})
        self._spawn(self.pulse_one(hostname))

    def reachable(self, peer: str) -> bool:
        """``(monotonic() - last_seen.get(peer,-inf)) < liveness_timeout`` (SPEC
        §4.2)."""
        return (
            time.monotonic() - self._last_seen.get(peer, float("-inf"))
        ) < self._liveness_timeout

    @property
    def reachable_set(self) -> FrozenSet[str]:
        """The per-sweep reachable snapshot Directory reads for route_* (SPEC
        §4.3) — an immutable rebound frozenset (§7)."""
        return self._reachable_set

    def roster_snapshot(self) -> Tuple[str, ...]:
        """Immutable capture of the current roster hostnames (SPEC §4.2)."""
        return tuple(self._roster.keys())

    def spec_for(self, hostname: str) -> Optional[PeerSpec]:
        return self._roster.get(hostname)

    # ---------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------
    def _observe(self, event_id: str, payload: dict) -> None:
        if self._observe_cb is not None:
            try:
                self._observe_cb(event_id, payload)
            except Exception:  # noqa: BLE001
                pass
        else:
            _logger.debug("observe %s %r", event_id, payload)

    def _parse_address(self, address: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse ``"ip"`` / ``"ip:port"`` -> (ip, port); default port = the
        cluster listener port (§4.7). IPv6 is deferred (single-colon IPv4:port
        only). Returns (None, None) on a malformed address."""
        try:
            host = address
            port = self._default_port
            if address.count(":") == 1:
                host, port_s = address.rsplit(":", 1)
                port = int(port_s)
            ipaddress.ip_address(host)  # validate
            return host, port
        except Exception:  # noqa: BLE001
            return None, None

    def _in_lan_cidr(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._lan_networks)
        except Exception:  # noqa: BLE001
            return False

    # --- tombstone persistence (§F#15) -----------------------------------
    def _load_tombstones(self) -> FrozenSet[str]:
        if self._tombstone_path is None or not self._tombstone_path.exists():
            return frozenset()
        try:
            data = json.loads(self._tombstone_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return frozenset(str(h) for h in data)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("failed to load tombstones: %r", exc)
        return frozenset()

    def _persist_tombstones(self) -> None:
        if self._tombstone_path is None:
            return
        try:
            self._tombstone_path.parent.mkdir(parents=True, exist_ok=True)
            # G4 (panel robustness): atomic tmp-file + replace, NOT a bare
            # write_text — a crash mid-write would otherwise corrupt/truncate the
            # revoke list (a security-relevant durability hole). os.replace on
            # the same dir is atomic on both POSIX and Windows.
            tmp = self._tombstone_path.parent / (self._tombstone_path.name + ".tmp")
            tmp.write_text(json.dumps(sorted(self._tombstone)), encoding="utf-8")
            tmp.replace(self._tombstone_path)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("failed to persist tombstones: %r", exc)
