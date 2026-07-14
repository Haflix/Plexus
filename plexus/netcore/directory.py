"""netcore.directory — §4.3 Directory: content_hash + route_* seam.

``content_hash`` is the SOLE freshness token (SPEC §4.3). ``build_pong``
re-derives the hash + exported snapshot from the LIVE registry-provider (+ the
current roster for vouches) each serve, in ONE synchronous await-free pass. No
version, no monotone guard, no resync clause, no memo, no builtin ``hash()``.
The Directory holds NO liveness — it reads Membership's immutable
``reachable_set`` + roster when building ``route_*`` (§3/§4.3). Zero locks:
``replace`` is one synchronous roster-gated await-free critical section; readers
capture-once immutable rebound values (safe across core's awaits because writers
rebind, never mutate) (§7).

Registry-provider seam (core-owned, injected; faked in the self-test). It yields
the LIVE exported candidates — Directory OWNS the export filter (§F#17):
  * ``provider.endpoints() -> Iterable[dict]`` records:
      {access_name, plugin_name, plugin_uuid, plugin_version, description,
       arguments, tags, remote(bool), accessible_by_other_plugins(bool),
       enabled(bool), owner_active(bool)}
  * ``provider.subs() -> Iterable[dict]`` records:
      {sub_uuid, topic_pattern, authors, blocked_authors, hosts, blocked_hosts,
       plugin_name, remote(bool), enabled(bool), owner_active(bool)}

Membership seam (DONE, used for real): ``reachable_set`` (property, frozenset),
``in_roster(h)``, ``roster_snapshot()``, ``spec_for(h)`` (for config-origin
``vouched_peers``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import time
import unicodedata
import uuid
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .types import (
    DirectorySnapshot,
    EndpointEntry,
    PeerSource,
    Pong,
    RemoteSub,
    VouchedPeer,
)

_logger = logging.getLogger("plexus.netcore.directory")


# SPEC §11: PING floor-interval default 0.5 * heartbeat.
DEFAULT_PING_FLOOR = 5.0


# ---------------------------------------------------------------------------
# Canonicalization helpers (§4.3 recursive canonical hash; BAN builtin hash()).
# ---------------------------------------------------------------------------
def _nfc(s: Any) -> str:
    """NFC-normalize a string so an NFC/NFD variant hashes identically (§F#8)."""
    return unicodedata.normalize("NFC", s if isinstance(s, str) else str(s))


def _canon(obj: Any) -> Any:
    """Recursively canonicalize an arbitrary nested value (§4.3): NFC every
    string (incl. dict keys), preserve dict/list structure full-depth. Dict-key
    SORTING is done by ``json.dumps(sort_keys=True)`` at serialize time."""
    if isinstance(obj, str):
        return _nfc(obj)
    if isinstance(obj, dict):
        return {_nfc(k): _canon(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canon(x) for x in obj]
    return obj  # int / float / bool / None


def _canon_strlist(v: Any) -> List[str]:
    """Canonicalize an authors/hosts/tags value for the CONTENT-HASH only (§4.3).
    The value may be RAW: a keyword STRING ("any"/"local"/"remote"), a list, or
    None — a bare string is a SINGLE token (NOT `list("any")` -> ['a','n','y'],
    which would both corrupt the hash AND, if it leaked into the exported value,
    break the receiver's host/author filter — learning 2)."""
    if v is None:
        return []
    if isinstance(v, str):
        return [_nfc(v.strip())]
    return sorted(_nfc(str(x).strip()) for x in v)


class Directory:
    """Local snapshot (derived-at-serve) + remote snapshots + routing (SPEC
    §4.3)."""

    def __init__(
        self,
        registry_provider: Any,
        membership: Any,
        *,
        self_hostname: str,
        observe: Any = None,
        ping_floor: float = DEFAULT_PING_FLOOR,
    ):
        self._provider = registry_provider
        self._membership = membership
        self._self_hostname = self_hostname
        self._observe_cb = observe
        self._ping_floor = ping_floor

        # ``epoch`` = a >=128-bit CSPRNG/uuid4 boot nonce, IDENTITY only, OFF the
        # apply path (§4.3).
        self._epoch = uuid.uuid4().hex

        # remote snapshots: hostname -> DirectorySnapshot (rebound, never mutated).
        self._remote: Dict[str, DirectorySnapshot] = {}

        # per-peer PING floor last-served (monotonic), §8.2.
        self._ping_served: Dict[str, float] = {}

    # ---------------------------------------------------------------------
    # §4.3 local derivation + PONG build + §8.2 PING floor
    # ---------------------------------------------------------------------
    def build_pong(self, have_hash: str) -> Pong:
        """Re-derive the local ``content_hash`` + exported snapshot from the LIVE
        registry-provider (+ roster for vouches) in ONE await-free pass (SPEC
        §4.3). ``snapshot_follows = have_hash != content_hash``; when it follows,
        ``Pong.snapshot`` carries the ``DirectorySnapshot`` OBJECT the write-pump
        serializes as the trailing body (the shape transport's phase-2b
        inbound-PING path expects)."""
        snap = self._export_snapshot()
        follows = have_hash != snap.content_hash
        return Pong(
            epoch=snap.epoch,
            content_hash=snap.content_hash,
            snapshot_follows=follows,
            snapshot=snap if follows else None,
        )

    def serve_ping(self, peer: str, have_hash: str) -> Optional[Pong]:
        """The floor-gated inbound-serve wrapper (SPEC §8.2, phase-2b flag #7):
        AT MOST ONE PONG per ``ping_floor`` window per peer — a below-floor PING
        returns None (DROP), so a PING flood cannot flood PONGs / snapshot serves
        on the shared loop. An at-interval PING (>= floor apart) is always
        answered. Writer = the inbound serve path (Transport calls this)."""
        now = time.monotonic()
        last = self._ping_served.get(peer, float("-inf"))
        if (now - last) < self._ping_floor:
            return None  # below floor -> drop (the window already had its PONG)
        self._ping_served[peer] = now
        return self.build_pong(have_hash)

    def _export_snapshot(self) -> DirectorySnapshot:
        """Build the export-filtered ``DirectorySnapshot`` from the live provider
        (SPEC §4.3, §F#17). Endpoints/subs keep DECLARATION order in the snapshot;
        the ``content_hash`` sorts each list by its full canonical content (NOT by
        sub_uuid, which is excluded from the hash — TP-30)."""
        endpoints: List[EndpointEntry] = []
        for r in self._provider.endpoints():
            # export filter: remote AND enabled AND owner-active AND accessible.
            if not (
                r.get("remote")
                and r.get("enabled")
                and r.get("owner_active")
                and r.get("accessible_by_other_plugins")
            ):
                continue
            endpoints.append(
                EndpointEntry(
                    hostname=self._self_hostname,
                    access_name=r["access_name"],
                    plugin_name=r["plugin_name"],
                    plugin_uuid=r.get("plugin_uuid", ""),
                    plugin_version=r.get("plugin_version", ""),
                    description=r.get("description", ""),
                    arguments=r.get("arguments") or {},
                    tags=list(r.get("tags") or []),
                    remote=True,
                    accessible_by_other_plugins=True,
                )
            )

        subs: List[RemoteSub] = []
        for r in self._provider.subs():
            # export filter: remote AND enabled AND owner-active (a disabled /
            # owner-inactive sub is EXCLUDED, §F#17).
            if not (r.get("remote") and r.get("enabled") and r.get("owner_active")):
                continue
            subs.append(
                RemoteSub(
                    sub_uuid=r["sub_uuid"],
                    topic_pattern=r["topic_pattern"],
                    # RAW (str "any"/"local" / list / None) so the RECEIVER's core
                    # filter chain (_hosts_match / _sub_accepts_author) interprets
                    # them IDENTICALLY to a local sub. `list("any")` -> ['a','n','y']
                    # was the sub-routing blocker (learning 2); canonicalization for
                    # the content_hash happens ONLY in _canon_strlist.
                    authors=r.get("authors"),
                    blocked_authors=r.get("blocked_authors"),
                    hosts=r.get("hosts"),
                    blocked_hosts=r.get("blocked_hosts"),
                    plugin_name=r.get("plugin_name", ""),
                    enabled=True,  # always true post-export-filter
                )
            )

        # tagged: derived index (endpoint by tag, declaration order within a tag).
        tagged: Dict[str, List[EndpointEntry]] = {}
        for e in endpoints:
            for tag in e.tags:
                tagged.setdefault(tag, []).append(e)

        vouched = self._config_vouched_peers()
        content_hash = self._content_hash(endpoints, subs, vouched)
        return DirectorySnapshot(
            epoch=self._epoch,
            content_hash=content_hash,
            endpoints=endpoints,
            tagged=tagged,
            subs=subs,
            vouched_peers=vouched,
        )

    def _config_vouched_peers(self) -> List[VouchedPeer]:
        """``vouched_peers`` = the node's CONFIG-ORIGIN peers only (§4.7, single-
        hop, no relay), from Membership."""
        out: List[VouchedPeer] = []
        for hostname in self._membership.roster_snapshot():
            spec = self._membership.spec_for(hostname)
            if spec is None or getattr(spec, "source", None) != PeerSource.CONFIG:
                continue
            out.append(
                VouchedPeer(
                    hostname=spec.hostname,
                    address=f"{spec.ip}:{spec.port}",
                    fingerprint=spec.fingerprint,
                    cert_pem=spec.cert_pem,
                )
            )
        return out

    def _content_hash(
        self,
        endpoints: List[EndpointEntry],
        subs: List[RemoteSub],
        vouched: List[VouchedPeer],
    ) -> str:
        """The RECURSIVE canonical hash (SPEC §4.3/§F#8): each endpoint / sub /
        vouched_peer is canonicalized, then the lists are ordered by that canonical
        CONTENT (a stable total order), tags + authors/hosts normalized+sorted,
        ``arguments`` canonicalized full-depth, over a canonical JSON serialization
        via sha256.

        EXCLUDED from the hash (IDENTITY, not content — a same-content reboot must
        re-derive the SAME hash, §10): ``epoch`` AND the per-boot ``plugin_uuid`` /
        ``sub_uuid`` (both regenerated as ``uuid4()`` every boot, never persisted —
        utils.py / notifier.py). They stay in the EXPORTED wire shape (§4.3); only
        the hash omits them. TP-30: leaving them in re-hashed a same-config reboot
        and forced a needless directory re-apply. ``tagged`` is EXCLUDED (derived).
        BAN builtin ``hash()``.

        Ordering is by the canonical dict itself, NOT by ``plugin_uuid`` /
        ``sub_uuid``: those were per-boot random, so sorting by them flipped the
        list order (hence the hash) across reboots. Two entries whose canonical
        content is identical (they differ only by the excluded uuid) sort equal and
        serialize identically, so their order is immaterial."""
        def _key(d: dict) -> str:
            return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        canonical = {
            "endpoints": sorted((self._canon_endpoint(e) for e in endpoints), key=_key),
            "subs": sorted((self._canon_sub(s) for s in subs), key=_key),
            "vouched_peers": sorted((self._canon_vouched(v) for v in vouched), key=_key),
        }
        blob = json.dumps(
            canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @staticmethod
    def _canon_endpoint(e: EndpointEntry) -> dict:
        # NOTE: plugin_uuid is intentionally OMITTED — it is a per-boot uuid4
        # (identity, not content). It stays in the exported EndpointEntry / wire
        # shape (§4.3); only this hash canon drops it (§10 no-op reboot; TP-30).
        return {
            "hostname": _nfc(e.hostname),
            "access_name": _nfc(e.access_name),
            "plugin_name": _nfc(e.plugin_name),
            "plugin_version": _nfc(e.plugin_version),
            "description": _nfc(e.description),
            "arguments": _canon(e.arguments),
            "tags": _canon_strlist(e.tags),
            "remote": bool(e.remote),
            "accessible_by_other_plugins": bool(e.accessible_by_other_plugins),
        }

    @staticmethod
    def _canon_sub(s: RemoteSub) -> dict:
        # NOTE: sub_uuid is intentionally OMITTED — per-boot uuid4 (identity, not
        # content). Present in the exported wire shape (§4.3); off the hash (§10; TP-30).
        # Consequence (gap 6a, ACCEPTED — maintainer call 2026-07-13): because the
        # per-boot plugin_uuid/sub_uuid are off the hash, a peer's routing table keeps
        # the PREVIOUS boot's uuids across a same-content reboot (no refetch fires).
        # This is deliberate and low-blast: cross-node routing is by NAME/topic and the
        # receiver re-matches its own LOCAL subs, so delivery + rate-limiting are
        # unaffected; the sub_uuid here is identity/display only. The one narrow tooth
        # is a uuid-pinned cross-node `execute` (§F#14) to a plugin that just
        # same-content-rebooted — it would miss until the next config change refreshes
        # the hash. uuid-pinning a specific instance owns that staleness by nature (the
        # instance can unload/restart with a new uuid regardless).
        return {
            "topic_pattern": _nfc(s.topic_pattern),
            "authors": _canon_strlist(s.authors),
            "blocked_authors": _canon_strlist(s.blocked_authors),
            "hosts": _canon_strlist(s.hosts),
            "blocked_hosts": _canon_strlist(s.blocked_hosts),
            "plugin_name": _nfc(s.plugin_name),
            "enabled": bool(s.enabled),
        }

    @staticmethod
    def _canon_vouched(v: VouchedPeer) -> dict:
        return {
            "hostname": _nfc(v.hostname),
            "address": _nfc(v.address),
            "fingerprint": _nfc(v.fingerprint),
            "cert_pem": _nfc(v.cert_pem),
        }

    # ---------------------------------------------------------------------
    # §4.3 remote snapshot reconcile
    # ---------------------------------------------------------------------
    def replace(self, peer: str, snapshot: DirectorySnapshot) -> None:
        """Reconcile a fetched remote snapshot (SPEC §4.3), ONE synchronous
        await-free critical section: (1) roster gate; (2) apply iff ``cur is None
        OR content_hash differs``; (3) atomic rebind of ``remote`` + fire-and-
        forget ``_core/directory/replaced``."""
        if not self._membership.in_roster(peer):
            return  # roster gate
        cur = self._remote.get(peer)
        if cur is not None and cur.content_hash == snapshot.content_hash:
            return  # NOOP on same content
        self._remote = {**self._remote, peer: snapshot}  # atomic rebind
        self._observe(
            "_core/directory/replaced",
            {"hostname": peer, "content_hash": snapshot.content_hash},
        )

    def have_hash(self, peer: str) -> str:
        """The ``content_hash`` currently cached for ``peer`` (the PING's
        ``have_hash``), or "" if none (sentinel — forces snapshot_follows on the
        responder) (SPEC §4.2/§4.3)."""
        cur = self._remote.get(peer)
        return cur.content_hash if cur is not None else ""

    def drop_remote(self, hostname: str) -> None:
        """Drop a peer's cached remote snapshot on revoke/removal (called by
        Membership.remove_peer) — rebind ``remote`` WITHOUT the peer (SPEC §4.6)."""
        if hostname in self._remote:
            new = dict(self._remote)
            del new[hostname]
            self._remote = new
        # prune the PING-floor serve-map on revoke (§8.2) so a re-add starts fresh.
        self._ping_served.pop(hostname, None)

    # ---------------------------------------------------------------------
    # §4.3 routing seam — lock-free capture-once (reads Membership live state)
    # ---------------------------------------------------------------------
    def _routable_peers(self) -> Tuple[Dict[str, DirectorySnapshot], List[str]]:
        """Capture-once (§4.3): the current ``remote`` dict + the reachable-in-
        roster peer hostnames in hostname-lex order. ``remote`` + ``reachable_set``
        are immutable-rebind, so the captured refs are a consistent snapshot safe
        to iterate lazily across core's awaits."""
        remote = self._remote
        reach = self._membership.reachable_set
        in_roster = self._membership.in_roster
        peers = sorted(h for h in remote if h in reach and in_roster(h))
        return remote, peers

    def route_request(self, topic: str) -> Iterator[Tuple[str, RemoteSub]]:
        """Reachable+in-roster remote peers whose cached subs topic-match, in
        hostname-lex then DECLARATION order, UNFILTERED beyond topic-match +
        reachability (no author/host filter — core applies those) (SPEC §4.3)."""
        remote, peers = self._routable_peers()

        def _gen():
            for h in peers:
                for sub in remote[h].subs:  # declaration order
                    if _topic_match(sub.topic_pattern, topic):
                        yield (h, sub)

        return _gen()

    def route_execute(
        self, plugin: str, endpoint: str
    ) -> Iterator[Tuple[str, EndpointEntry]]:
        """Reachable+in-roster remote peers exporting ``(plugin, endpoint)``, in
        hostname-lex order, yielding ``(hostname, endpoint_entry)`` (NOT filtered
        by uuid — the callee NO_ENDPOINT rule is the uuid backstop, §4.5) (SPEC
        §4.3)."""
        remote, peers = self._routable_peers()

        def _gen():
            for h in peers:
                for e in remote[h].endpoints:
                    if e.access_name == endpoint and e.plugin_name == plugin:
                        yield (h, e)

        return _gen()

    def route_publish(
        self, topic: str
    ) -> Iterator[Tuple[str, List[RemoteSub]]]:
        """Grouped per peer: ``(hostname, list[RemoteSub])`` for reachable+in-
        roster peers with >=1 topic-matching sub; core applies its predicates per
        sub, sums the scheduled count, sends one FANOUT frame per peer (SPEC
        §4.3)."""
        remote, peers = self._routable_peers()

        def _gen():
            for h in peers:
                matches = [
                    sub for sub in remote[h].subs if _topic_match(sub.topic_pattern, topic)
                ]
                if matches:
                    yield (h, matches)

        return _gen()

    def route_tagged(self, tag: str) -> Iterator[Tuple[str, EndpointEntry]]:
        """COLLECT from cached ``tagged``, reachable+in-roster, REMOTE only; core
        adds local + reshapes to the public ``find_endpoints_by_tag`` return,
        normalizing self-host to 'local' (SPEC §4.3)."""
        remote, peers = self._routable_peers()

        def _gen():
            for h in peers:
                for e in remote[h].tagged.get(tag, []):
                    yield (h, e)

        return _gen()

    def reachable(self, hostname: str) -> bool:
        """Whether ``hostname`` is a reachable+in-roster routing target (SPEC
        §4.3) — Membership's ``reachable_set`` INTERSECT roster."""
        return (
            hostname in self._membership.reachable_set
            and self._membership.in_roster(hostname)
        )

    # ---------------------------------------------------------------------
    # §8.3 routing contribution to snapshot() (manager assembles the rest)
    # ---------------------------------------------------------------------
    def routing_table(self, hostname: str) -> dict:
        """The ``routing`` block for a peer in the phase-6 ``snapshot()`` (SPEC
        §8.3): ``{subs: [RemoteSub dicts], endpoints: [endpoint_entry dicts]}``.
        Directory owns ``routing`` + ``content_hash``; the manager assembles the
        §8.3 scalars around it."""
        snap = self._remote.get(hostname)
        if snap is None:
            return {"subs": [], "endpoints": []}
        return {
            "subs": [dataclasses.asdict(s) for s in snap.subs],
            "endpoints": [dataclasses.asdict(e) for e in snap.endpoints],
        }

    def content_hash_for(self, hostname: str) -> Optional[str]:
        """The cached ``content_hash`` for a peer (for the §8.3 snapshot scalar)."""
        snap = self._remote.get(hostname)
        return snap.content_hash if snap is not None else None

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


def _topic_match(pattern: str, topic: str) -> bool:
    """Topic match (SPEC §4.3): ``/``-separated, ``*`` matches EXACTLY ONE
    segment. Same segment count required."""
    ps = pattern.split("/")
    ts = topic.split("/")
    if len(ps) != len(ts):
        return False
    return all(p == "*" or p == t for p, t in zip(ps, ts))
