"""netcore.types — the SPEC §6 data structures, made real.

This module carries the concrete data shapes the rest of ``netcore`` passes
across module seams: the frame-kind byte table (§4.4/§5), the ERROR.kind set
and the CALL ``mode`` set (§4.4), plus the dataclasses named in SPEC §6:
``DirectorySnapshot``, ``PeerSpec``, ``PeerIdentity``, ``Pending`` (with its
PING variant), the endpoint-entry + ``RemoteSub`` export shapes (§4.3), the
``CallerCtx`` wire caller (§4.5/§5), the ``VouchedPeer`` discovery entry (§4.7),
and the transport-level link exceptions (§4.2/§4.4).

The behavioural modules (wire/transport/membership/directory/dispatch/manager)
are all fully implemented; this module holds the shared data shapes they pass
across seams.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional, Union


# ---------------------------------------------------------------------------
# Frame kinds — the LOCKED 1-byte kind table (SPEC §4.4 "Kind byte table" / §5).
# PING=1, CALL=2, CANCEL=3, PONG=4, CHUNK=5, END=6, ERROR=7.
# ---------------------------------------------------------------------------
class Kind(IntEnum):
    """The seven wire frame kinds, four roles (SPEC §4.4/§5).

    Control (small, priority write-slot): PING, PONG, CANCEL.
    App opener (non-priority): CALL.
    Data (bidirectional): CHUNK.
    Terminators (bidirectional, value-less): END, ERROR.
    """

    PING = 1
    CALL = 2
    CANCEL = 3
    PONG = 4
    CHUNK = 5
    END = 6
    ERROR = 7


# ---------------------------------------------------------------------------
# ERROR.kind set (SPEC §4.4/§4.5/§5) — a small int on the wire, decoded
# INDEPENDENTLY of the exc payload; maps to a legacy exception TYPE in Dispatch.
# ---------------------------------------------------------------------------
class ErrorKind(IntEnum):
    """The ERROR frame's ``kind`` field (SPEC §4.4/§4.5).

    Dispatch maps each to the legacy exception TYPE (§4.5):
      NO_MATCH        -> NoLocalSubException      (fall through)
      HANDLER_RAISED  -> re-raise the deserialized exc (nested-Network wrap)
      NETWORK         -> NetworkRequestException   (fall through)
      RATE_LIMIT      -> RateLimitException        (propagate)
      CAPABILITY      -> CapabilityException       (propagate)
      NO_ENDPOINT     -> NetworkRequestException   (fall through)
    """

    NO_MATCH = 1
    HANDLER_RAISED = 2
    NETWORK = 3
    RATE_LIMIT = 4
    CAPABILITY = 5
    NO_ENDPOINT = 6


# ---------------------------------------------------------------------------
# CALL mode set (SPEC §4.4/§5) — a small int on the wire.
# UNARY/FIRST/STREAM/FANOUT are the public modes; PING is an internal-only
# mode for the bespoke PING/PONG cid entry (§4.4 "a distinct internal PING mode").
# ---------------------------------------------------------------------------
class Mode(IntEnum):
    """CALL ``mode`` (SPEC §4.4/§5). STREAM is shared by request_event_stream
    (topic selector) + execute_remote_stream (plugin/endpoint/uuid selector);
    the callee disambiguates by selector SHAPE. ``PING`` never rides a CALL —
    it is the internal ``Pending`` mode for the PING/PONG cid (§4.4)."""

    UNARY = 1
    FIRST = 2
    STREAM = 3
    FANOUT = 4
    PING = 5  # internal only; never encoded on a CALL frame


# ---------------------------------------------------------------------------
# Peer source provenance (SPEC §4.7 / §6): config-origin vs vouched (learned).
# ---------------------------------------------------------------------------
class PeerSource(IntEnum):
    """Where a roster peer came from (SPEC §4.7 audit / §8.3 snapshot)."""

    CONFIG = 1
    VOUCHED = 2


# ---------------------------------------------------------------------------
# Transport-level link exceptions (SPEC §4.2/§4.4). Raised by Transport;
# Membership's pulse arms + Dispatch's senders catch them (§4.2 pseudocode,
# §4.5 "RAISES only on link-level LinkDown/Timeout").
# ---------------------------------------------------------------------------
class LinkError(Exception):
    """Base for transport link-level failures (SPEC §4.2)."""


class LinkDown(LinkError):
    """No live link to the peer / it dropped mid-flight (SPEC §4.2). Transient:
    the pulse ages it out; a sender falls through. Windows: WSAETIMEDOUT /
    no-route map here."""


class LinkRefused(LinkError):
    """The most recent dial was actively refused (SPEC §4.2 fast-path,
    WSAECONNREFUSED/10061). The pulse hard-downs `last_seen=-inf` (roster-gated)."""


class Timeout(LinkError):
    """A per-call deadline elapsed at the transport layer (SPEC §4.2/§4.4)."""


class ProtocolError(LinkError):
    """A malformed FRAME / codec violation (SPEC §4.4). This is the ONLY
    condition that TEARS the link (contrast a reassembly-bound exceed, which
    CANCELs + keeps the link)."""


# ---------------------------------------------------------------------------
# Caller context — the wire ``caller`` (SPEC §4.5/§5/§8.1).
# NOTE: NO ``system_caller`` field — the callee derives it from its OWN
# authenticated record, never the wire.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CallerCtx:
    """The CALL ``caller`` envelope (SPEC §5): ``{author, author_id,
    author_host, request_uuid}`` — carries NO ``system_caller`` (§8.1: the
    callee grants ``author="system"`` only from its authenticated record)."""

    author: Optional[str]
    author_id: Optional[str]
    author_host: Optional[str]
    request_uuid: Optional[str]


# ---------------------------------------------------------------------------
# CALL selectors (SPEC §4.4/§5). Execute carries an optional plugin_uuid
# (D2 uuid-targeting survives cross-node); events carry a topic.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExecuteSelector:
    """Execute/execute-stream selector (SPEC §5): ``{plugin, endpoint,
    plugin_uuid?}``. A uuid-targeted CALL a peer can't satisfy -> NO_ENDPOINT
    (§4.5 D2)."""

    plugin: str
    endpoint: str
    plugin_uuid: Optional[str] = None


@dataclass(frozen=True)
class TopicSelector:
    """Event selector (SPEC §5): ``{topic}`` for request_event /
    request_event_stream / publish_event."""

    topic: str


Selector = Union[ExecuteSelector, TopicSelector]


# ---------------------------------------------------------------------------
# Peer identity — built from the AUTHENTICATED roster record (SPEC §4.4/§8.1),
# NOT the wire.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PeerIdentity:
    """The authenticated peer identity (SPEC §8.1): ``{hostname,
    system_caller}`` keyed by the SPKI-pinned hostname. The callee builds this
    from its own record and IGNORES any wire-asserted system-caller."""

    hostname: str
    system_caller: bool


# ---------------------------------------------------------------------------
# PeerSpec — a pinned peer (SPEC §6). ``cert_pem`` present (D1). ``fingerprint``
# is DERIVED from ``cert_pem`` (= SPKI(cert_pem)) so a mismatch is
# unrepresentable (§4.6). ``vouched_by`` null for config-origin peers.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PeerSpec:
    """A pinned peer entry (SPEC §6). Feeds BOTH the CA-cadata context and the
    SPKI pin set (§4.1). ``dial`` is the per-edge FALLBACK dialer override
    (§4.4, NAT edge). ``source``/``vouched_by`` carry discovery provenance
    (§4.7)."""

    hostname: str
    ip: str
    port: int
    cert_pem: str
    fingerprint: str  # DERIVED = SPKI(cert_pem); mismatch unrepresentable (§4.6)
    system_caller: bool = False
    dial: Optional[str] = None  # per-edge fallback dial override (§4.4)
    source: PeerSource = PeerSource.CONFIG
    vouched_by: Optional[str] = None  # null for config; voucher hostname if vouched


# ---------------------------------------------------------------------------
# VouchedPeer — a discovery entry riding ``vouched_peers`` on the snapshot
# (SPEC §4.3/§4.7). ``cert_pem`` present (D1). ``fingerprint`` DERIVED (§4.6).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VouchedPeer:
    """One ``vouched_peers`` list entry (SPEC §4.7): ``{hostname, address,
    fingerprint, cert_pem}``, config-origin-only at the voucher (single-hop,
    no relay). A ``content_hash`` input (§4.3)."""

    hostname: str
    address: str  # "ip[:port]"
    fingerprint: str
    cert_pem: str


# ---------------------------------------------------------------------------
# Endpoint export entry (SPEC §4.3 "Endpoint entry shape (DECIDED)").
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EndpointEntry:
    """A directory endpoint entry (SPEC §4.3). Carries ``hostname`` so the
    tag/execute consumers can key by host, plus the metadata orchestrators
    need for ``ai_tool`` schemas."""

    hostname: str
    access_name: str
    plugin_name: str
    plugin_uuid: str
    plugin_version: str
    description: str
    arguments: Any  # the plugin's arguments dict/list (canonicalized in the hash)
    tags: list
    remote: bool
    accessible_by_other_plugins: bool


# ---------------------------------------------------------------------------
# RemoteSub — an exported subscription (SPEC §4.3). ``enabled`` is always true
# post-export-filter; present for callee re-match.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RemoteSub:
    """An exported subscription (SPEC §4.3): ``{sub_uuid, topic_pattern,
    authors, blocked_authors, hosts, blocked_hosts, plugin_name, enabled?}``.
    Ordered by declaration in the snapshot's ``subs`` list. ``sub_uuid`` is
    EXCLUDED from the content hash (per-boot uuid4 = identity, not content; TP-30);
    it rides the wire shape but never the freshness hash (§4.3)."""

    sub_uuid: str
    topic_pattern: str
    authors: list
    blocked_authors: list
    hosts: list
    blocked_hosts: list
    plugin_name: str
    enabled: bool = True


# ---------------------------------------------------------------------------
# DirectorySnapshot — the immutable per-node directory (SPEC §4.3/§6).
# ``remote:true`` + ``enabled`` + owner-active-filtered, live-derived; the hash
# covers vouches recursively.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DirectorySnapshot:
    """The immutable directory snapshot (SPEC §4.3/§6): ``{epoch, content_hash,
    endpoints, tagged, subs, vouched_peers}``.

    ``epoch`` = a >=128-bit CSPRNG/uuid4 boot nonce, IDENTITY only, OFF the
    apply path (§4.3). ``content_hash`` = the sole freshness token, a RECURSIVE
    canonical hash (§4.3). ``replace`` applies iff hash differs."""

    epoch: str
    content_hash: str
    endpoints: list  # list[EndpointEntry]
    tagged: dict  # tag -> list[EndpointEntry]
    subs: list  # list[RemoteSub], declaration-ordered
    vouched_peers: list  # list[VouchedPeer]


# ---------------------------------------------------------------------------
# Pong — the PING reply header (SPEC §4.4/§3). ``snapshot`` is an awaitable the
# reader reassembles + settles on ``END{cid}`` when ``snapshot_follows``.
# ---------------------------------------------------------------------------
@dataclass
class Pong:
    """A PONG reply (SPEC §3/§4.4). ``ping()`` RETURNS on this HEADER.
    ``.snapshot`` is DUAL-ROLE by side: on the REQUESTER side (ping caller) it is
    an awaitable Future yielding the reassembled ``DirectorySnapshot`` (settled on
    ``END{cid}``); on the RESPONDER side (``build_pong``) it holds the
    ``DirectorySnapshot`` OBJECT to serialize as the trailing body.
    Header-terminal when ``snapshot_follows=false``."""

    epoch: str
    content_hash: str
    snapshot_follows: bool
    # requester side: awaitable[DirectorySnapshot]; responder side: DirectorySnapshot
    snapshot: Optional[Any] = None


# ---------------------------------------------------------------------------
# Pending — a per-cid outbound correlation entry (SPEC §4.4/§6). The PING
# variant is a bespoke internal entry (Mode.PING).
# ---------------------------------------------------------------------------
@dataclass
class Pending:
    """A per-cid outbound correlation entry (SPEC §4.4/§6): ``{cid, deadline,
    mode, fut_or_queue, reassembly_buf, reassembly_bytes}``.

    - UNARY/FIRST: ``fut_or_queue`` is a Future settled on END; peeks on CHUNK.
    - STREAM: ``fut_or_queue`` is a StreamQueue; one item per CHUNK{last}.
    - PING (Mode.PING variant): the PONG header settles ``fut_or_queue``
      immediately; header-terminal unless ``snapshot_follows`` (then the
      snapshot reassembles on the SAME cid, settling on END).

    ``reassembly_bytes`` is the recorded per-cid byte count; every exit path
    decrements the per-peer + node-wide counters by EXACTLY this, once, by the
    pop-winner (§4.4/§7)."""

    cid: int
    deadline: float
    mode: Mode
    fut_or_queue: Any
    reassembly_buf: list = field(default_factory=list)  # accumulated CHUNK.data bytes
    reassembly_bytes: int = 0
    snapshot_follows: bool = False  # PING variant: whether a snapshot body trails
    # F4 (panel clarity): these transport-managed timer/snapshot handles were formerly
    # monkey-patched onto the entry with `# type: ignore` (a "where is this set?" hazard
    # in the busiest module). Declared here (default None) so every field has ONE
    # visible home. `_timer` = the request/ping deadline; `_snapshot_future` = the PING
    # snapshot awaitable; `_abs_timer`/`_idle_timer` = the per-reassembly deadlines.
    _timer: Any = None
    _snapshot_future: Any = None
    _abs_timer: Any = None
    _idle_timer: Any = None
