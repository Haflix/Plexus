"""netcore.wire — §4.4 framing + codec, chunk/reassembly primitives.

Framing (SPEC §4.4/§5, LOCKED): ``[4B length][1B kind][cid + fields]``, big-
endian length EXCLUDING the 4 length bytes, counting ``[kind][cid+fields]``.
Kind byte table PING=1/CALL=2/CANCEL=3/PONG=4/CHUNK=5/END=6/ERROR=7.

On-wire body layout (branch-internal — no mixed-version interop, Locked
decision 1):
  * every kind: ``[1B kind][8B big-endian cid][ ...fields ]``
  * CHUNK fields = ``[1B last][opaque data bytes to end-of-frame]`` (NO msgpack
    wrap — ``data`` is opaque bytes sliced at byte offsets, §4.4)
  * every OTHER kind's fields = ONE msgpack blob (a dict), possibly empty for
    CANCEL/END.

Codec split (SPEC §4.4/§5, LOCKED): control fields (all openers/terminators,
PONG, the DirectorySnapshot, ``vouched_peers``) = **msgpack**. ``CHUNK.data`` =
opaque bytes; a logical VALUE (CALL args / a unary/FIRST result / a stream item /
a snapshot body) is serialized with ``pickle`` and deserialized by the restricted
**SafeUnpickler allowlist** (``safe_loads`` — NOT raw ``pickle.loads``) AFTER full
reassembly, never per-chunk. ``ERROR.exc`` is such a VALUE (a pickled exception
carried as opaque bytes inside the msgpack ERROR envelope), so ``kind`` decodes
INDEPENDENTLY of ``exc`` (§5).

Every logical value rides one or more ``CHUNK{cid, data, last}``; a value <=
``CHUNK_SIZE`` (64 KB) is a single ``CHUNK{last=true}``, larger splits with
``last=true`` on its final fragment.
"""

from __future__ import annotations

import asyncio
import dataclasses
import pickle
from typing import Any, Iterator, Optional, Tuple

import msgpack

from ..serialization import safe_loads
from .types import (
    CallerCtx,
    DirectorySnapshot,
    EndpointEntry,
    ErrorKind,
    ExecuteSelector,
    Kind,
    LinkDown,
    Mode,
    ProtocolError,
    RemoteSub,
    Selector,
    TopicSelector,
    VouchedPeer,
)


# SPEC §11: CHUNK_SIZE default 64 KB. The per-FRAME cap = the chunk unit; there
# is NO per-message cap (reassembly-byte bounds replace it).
CHUNK_SIZE = 64 * 1024

# SPEC §4.4: the 4-byte big-endian length prefix.
LENGTH_PREFIX_BYTES = 4

# The cid is a per-link 63-bit counter with the high bit = dial role (§4.4), so
# it fits in 8 bytes big-endian unsigned.
CID_BYTES = 8

# SPEC §4.4 reassembly bounds: per-cid 8 MB (the wire-owned bound; Transport
# drives the per-peer 16 MB / node-wide 128 MB budgets on top of this).
PER_CID_REASSEMBLY_CAP = 8 * 1024 * 1024

# Framing DoS guard: a single frame's declared length is bounded so a hostile
# peer cannot make ``readexactly`` allocate arbitrarily. A data CHUNK is <=
# CHUNK_SIZE; control frames are tiny; ERROR.exc (a pickled exception) is small.
# Headroom for the 9-byte header + msgpack envelope + an oversized exc. An
# over-bound frame length is a MALFORMED FRAME -> ProtocolError -> tear link.
MAX_FRAME_BYTES = CHUNK_SIZE + (1 << 20)


class ReassemblyBoundExceeded(Exception):
    """A per-cid reassembly-byte bound was exceeded (SPEC §4.4). Deliberately
    NOT a ``ProtocolError``: the caller (Transport) FAILS CLOSED by dropping the
    cid + sending CANCEL, but KEEPS THE LINK (tear-link is reserved for a
    malformed FRAME only, §4.4)."""


@dataclasses.dataclass
class Frame:
    """A decoded wire frame (SPEC §4.4/§5). ``kind`` selects which optional
    fields are populated."""

    kind: Kind
    cid: int
    # PING / PONG
    have_hash: Optional[str] = None
    epoch: Optional[str] = None
    content_hash: Optional[str] = None
    snapshot_follows: Optional[bool] = None
    # CALL
    selector: Optional[Selector] = None
    mode: Optional[Mode] = None
    caller: Optional[CallerCtx] = None
    handler_timeout: Optional[float] = None
    # CHUNK
    data: Optional[bytes] = None
    last: Optional[bool] = None
    # ERROR
    error_kind: Optional[ErrorKind] = None
    exc: Optional[bytes] = None  # pickled exception payload (opaque; safe_loads)


# ---------------------------------------------------------------------------
# Control-field codec (msgpack) + value codec (pickle out / safe_loads in).
# ---------------------------------------------------------------------------
def pack_control(obj: Any) -> bytes:
    """msgpack-encode a control field / DirectorySnapshot / ``vouched_peers``
    (SPEC §4.4/§5 codec split). ``use_bin_type`` keeps ``bytes`` distinct from
    ``str`` (ERROR.exc rides as bin)."""
    return msgpack.packb(obj, use_bin_type=True)


def unpack_control(raw: bytes) -> Any:
    """msgpack-decode a control field. ``raw=False`` -> ``str`` for text;
    ``strict_map_key=False`` allows int keys. Raises ``ProtocolError`` on a
    malformed blob (SPEC §4.4 — a malformed frame tears the link)."""
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except Exception as exc:  # noqa: BLE001 - any msgpack failure = malformed frame
        raise ProtocolError(f"malformed control payload: {exc!r}") from exc


def serialize_value(value: Any) -> bytes:
    """Serialize a logical VALUE (CALL args / result / stream item / an
    exception) to the opaque bytes that ``chunk_value`` slices (SPEC §4.4). Uses
    ``pickle`` on the SEND side (the receive side is hardened by
    ``deserialize_value``)."""
    return pickle.dumps(value)


def deserialize_value(raw: bytes) -> Any:
    """Deserialize a fully-reassembled CHUNK payload via the restricted
    SafeUnpickler allowlist (``safe_loads`` from ``plexus.serialization`` — NOT
    raw ``pickle.loads``), AFTER full reassembly (SPEC §4.4/§5/§8.1)."""
    return safe_loads(raw)


# ---------------------------------------------------------------------------
# Directory snapshot codec — MSGPACK, NOT pickle (SPEC §4.4/§5 LOCKED: "the
# DirectorySnapshot = msgpack"). The snapshot body rides the PING/PONG cid as
# CHUNK frames, but it is a CONTROL structure encoded as inert msgpack data — it
# is NEVER routed through SafeUnpickler, so a possibly-compromised vouched peer's
# snapshot cannot reach the pickle allowlist via the discovery/PONG path (§8.1).
# Decode-COUNT bounds (§4.4/§4.7) drop an over-count snapshot (TG-17): the whole
# snapshot is dropped -> that peer goes fully un-routable, not a silent partial.
# ---------------------------------------------------------------------------
MAX_SNAPSHOT_ENDPOINTS = 10000
MAX_SNAPSHOT_SUBS = 10000
MAX_VOUCHED_PEERS = 256  # GENEROUS headroom above the max config-peer count
_MSGPACK_SNAPSHOT_CEIL = 100000  # a hard array/map element ceiling (bomb guard)


def encode_snapshot(snapshot: DirectorySnapshot) -> bytes:
    """msgpack-encode a ``DirectorySnapshot`` as the PONG trailing body (SPEC
    §4.4/§5). ``tagged`` is OMITTED (derived from endpoints+tags on decode)."""
    obj = {
        "epoch": snapshot.epoch,
        "content_hash": snapshot.content_hash,
        "endpoints": [dataclasses.asdict(e) for e in snapshot.endpoints],
        "subs": [dataclasses.asdict(s) for s in snapshot.subs],
        "vouched_peers": [dataclasses.asdict(v) for v in snapshot.vouched_peers],
    }
    return pack_control(obj)


def decode_snapshot(raw: bytes) -> DirectorySnapshot:
    """msgpack-decode + reconstruct a ``DirectorySnapshot`` from the reassembled
    PONG body (SPEC §4.4/§5). Enforces the decode-COUNT bounds (§4.4/§4.7) and
    re-derives ``tagged``. Raises ``ProtocolError`` on a malformed / over-count
    snapshot (the pinger drops it; the peer stays reachable via the header
    stamp, §4.4)."""
    try:
        obj = msgpack.unpackb(
            raw,
            raw=False,
            strict_map_key=False,
            max_array_len=_MSGPACK_SNAPSHOT_CEIL,
            max_map_len=_MSGPACK_SNAPSHOT_CEIL,
        )
    except Exception as exc:  # noqa: BLE001 - any msgpack failure = malformed
        raise ProtocolError(f"malformed snapshot: {exc!r}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("snapshot body is not a map")
    eps = obj.get("endpoints") or []
    subs = obj.get("subs") or []
    vps = obj.get("vouched_peers") or []
    if (
        len(eps) > MAX_SNAPSHOT_ENDPOINTS
        or len(subs) > MAX_SNAPSHOT_SUBS
        or len(vps) > MAX_VOUCHED_PEERS
    ):
        raise ProtocolError(
            f"snapshot decode-count bound exceeded "
            f"(endpoints={len(eps)}, subs={len(subs)}, vouched={len(vps)})"
        )
    try:
        endpoints = [EndpointEntry(**e) for e in eps]
        remote_subs = [RemoteSub(**s) for s in subs]
        vouched = [VouchedPeer(**v) for v in vps]
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"malformed snapshot entry: {exc!r}") from exc
    tagged: dict = {}
    for e in endpoints:
        for tag in e.tags:
            tagged.setdefault(tag, []).append(e)
    return DirectorySnapshot(
        epoch=obj.get("epoch", ""),
        content_hash=obj.get("content_hash", ""),
        endpoints=endpoints,
        tagged=tagged,
        subs=remote_subs,
        vouched_peers=vouched,
    )


# ---------------------------------------------------------------------------
# selector <-> dict (msgpack-safe) helpers (SPEC §5).
# ---------------------------------------------------------------------------
def _selector_to_dict(selector: Selector) -> dict:
    if isinstance(selector, TopicSelector):
        return {"topic": selector.topic}
    if isinstance(selector, ExecuteSelector):
        d = {"plugin": selector.plugin, "endpoint": selector.endpoint}
        if selector.plugin_uuid is not None:
            d["plugin_uuid"] = selector.plugin_uuid
        return d
    raise ProtocolError(f"unknown selector type: {type(selector)!r}")


def _dict_to_selector(d: dict) -> Selector:
    # The callee disambiguates by selector SHAPE (SPEC §4.4): a topic selector
    # for events, a plugin/endpoint(/uuid) selector for execute.
    if "topic" in d:
        return TopicSelector(topic=d["topic"])
    if "plugin" in d:
        return ExecuteSelector(
            plugin=d["plugin"],
            endpoint=d["endpoint"],
            plugin_uuid=d.get("plugin_uuid"),
        )
    raise ProtocolError(f"unrecognized selector shape: {sorted(d)!r}")


def _caller_to_dict(caller: CallerCtx) -> dict:
    return {
        "author": caller.author,
        "author_id": caller.author_id,
        "author_host": caller.author_host,
        "request_uuid": caller.request_uuid,
    }


def _dict_to_caller(d: dict) -> CallerCtx:
    return CallerCtx(
        author=d.get("author"),
        author_id=d.get("author_id"),
        author_host=d.get("author_host"),
        request_uuid=d.get("request_uuid"),
    )


# ---------------------------------------------------------------------------
# Low-level frame assembly.
# ---------------------------------------------------------------------------
def _frame(kind: int, cid: int, fields_bytes: bytes) -> bytes:
    body = bytes((int(kind),)) + int(cid).to_bytes(CID_BYTES, "big") + fields_bytes
    return len(body).to_bytes(LENGTH_PREFIX_BYTES, "big") + body


# ---------------------------------------------------------------------------
# Encoders — one per kind (SPEC §4.4/§5).
# ---------------------------------------------------------------------------
def encode_ping(cid: int, have_hash: str) -> bytes:
    """Encode ``PING{cid, have_hash}`` (control/priority)."""
    return _frame(Kind.PING, cid, pack_control({"have_hash": have_hash}))


def encode_pong(
    cid: int, epoch: str, content_hash: str, snapshot_follows: bool
) -> bytes:
    """Encode ``PONG{cid, epoch, content_hash, snapshot_follows}`` (control/
    priority). No inline snapshot — the body trails as CHUNKs on the same cid."""
    return _frame(
        Kind.PONG,
        cid,
        pack_control(
            {
                "epoch": epoch,
                "content_hash": content_hash,
                "snapshot_follows": bool(snapshot_follows),
            }
        ),
    )


def encode_cancel(cid: int) -> bytes:
    """Encode ``CANCEL{cid}`` (control/priority, handled inline)."""
    return _frame(Kind.CANCEL, cid, pack_control({}))


def encode_call(
    cid: int,
    selector: Selector,
    mode: Mode,
    caller: CallerCtx,
    handler_timeout: Optional[float],
) -> bytes:
    """Encode ``CALL{cid, selector, mode, caller, handler_timeout}`` (app
    opener, non-priority). No inline args — args trail as CHUNKs.
    ``handler_timeout`` is omitted (absent on the wire) for FANOUT / None
    (STREAM) (SPEC §4.4)."""
    fields = {
        "selector": _selector_to_dict(selector),
        "mode": int(mode),
        "caller": _caller_to_dict(caller),
    }
    if handler_timeout is not None:
        fields["handler_timeout"] = float(handler_timeout)
    return _frame(Kind.CALL, cid, pack_control(fields))


def encode_chunk(cid: int, data: bytes, last: bool) -> bytes:
    """Encode ``CHUNK{cid, data, last}`` (SPEC §4.4/§5). ``data`` = opaque bytes
    at byte offsets; NOT msgpack-wrapped, NOT deserialized here."""
    return _frame(Kind.CHUNK, cid, bytes((1 if last else 0,)) + bytes(data))


def encode_end(cid: int) -> bytes:
    """Encode ``END{cid}`` (terminator, value-less)."""
    return _frame(Kind.END, cid, pack_control({}))


def encode_error(cid: int, kind: ErrorKind, exc: Any = None) -> bytes:
    """Encode ``ERROR{cid, kind, exc}`` (terminator). ``kind`` (an int) decodes
    INDEPENDENTLY of ``exc`` (§5). ``exc`` may be an exception OBJECT (pickled
    here), pre-serialized ``bytes``, or ``None`` (kinds like NO_MATCH /
    NO_ENDPOINT carry no exc)."""
    if exc is None:
        exc_bytes = b""
    elif isinstance(exc, (bytes, bytearray)):
        exc_bytes = bytes(exc)
    else:
        exc_bytes = serialize_value(exc)
    return _frame(
        Kind.ERROR, cid, pack_control({"kind": int(kind), "exc": exc_bytes})
    )


# ---------------------------------------------------------------------------
# Decoding.
# ---------------------------------------------------------------------------
def decode_frame(body: bytes) -> Frame:
    """Decode one frame BODY (``[kind][cid+fields]``, length prefix already
    stripped) into a ``Frame`` (SPEC §4.4/§5). Raises ``ProtocolError`` on a
    malformed frame (the only tear-the-link condition, §4.4)."""
    if len(body) < 1 + CID_BYTES:
        raise ProtocolError(f"frame body too short: {len(body)} bytes")
    kind_byte = body[0]
    cid = int.from_bytes(body[1 : 1 + CID_BYTES], "big")
    rest = body[1 + CID_BYTES :]

    try:
        kind = Kind(kind_byte)
    except ValueError:
        raise ProtocolError(f"unknown frame kind byte: {kind_byte}")

    if kind == Kind.CHUNK:
        if len(rest) < 1:
            raise ProtocolError("CHUNK frame missing the last-flag byte")
        last = bool(rest[0])
        data = bytes(rest[1:])
        return Frame(kind=kind, cid=cid, data=data, last=last)

    fields = unpack_control(rest) if rest else {}
    if not isinstance(fields, dict):
        raise ProtocolError(f"{kind.name} fields not a map: {type(fields)!r}")

    if kind == Kind.PING:
        return Frame(kind=kind, cid=cid, have_hash=fields.get("have_hash"))
    if kind == Kind.PONG:
        return Frame(
            kind=kind,
            cid=cid,
            epoch=fields.get("epoch"),
            content_hash=fields.get("content_hash"),
            snapshot_follows=bool(fields.get("snapshot_follows")),
        )
    if kind == Kind.CANCEL:
        return Frame(kind=kind, cid=cid)
    if kind == Kind.CALL:
        sel = fields.get("selector")
        cal = fields.get("caller")
        if not isinstance(sel, dict) or not isinstance(cal, dict):
            raise ProtocolError("CALL missing selector/caller map")
        try:
            mode = Mode(int(fields["mode"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError(f"CALL bad mode: {exc!r}") from exc
        return Frame(
            kind=kind,
            cid=cid,
            selector=_dict_to_selector(sel),
            mode=mode,
            caller=_dict_to_caller(cal),
            handler_timeout=fields.get("handler_timeout"),
        )
    if kind == Kind.END:
        return Frame(kind=kind, cid=cid)
    if kind == Kind.ERROR:
        try:
            error_kind = ErrorKind(int(fields["kind"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError(f"ERROR bad kind: {exc!r}") from exc
        raw_exc = fields.get("exc")
        exc_bytes = bytes(raw_exc) if raw_exc else None
        return Frame(kind=kind, cid=cid, error_kind=error_kind, exc=exc_bytes)

    raise ProtocolError(f"unhandled frame kind: {kind!r}")


class FrameReader:
    """Reads length-prefixed frames off an ``asyncio.StreamReader`` (SPEC
    §4.4/§5). Each ``read_frame`` returns one decoded ``Frame``; raises
    ``LinkDown`` on EOF, ``ProtocolError`` on a malformed length/body."""

    def __init__(self, reader: "asyncio.StreamReader"):
        self._reader = reader

    async def read_frame(self) -> Frame:
        """Read the next length-prefixed frame; decode + return it (SPEC §5)."""
        try:
            header = await self._reader.readexactly(LENGTH_PREFIX_BYTES)
        except asyncio.IncompleteReadError as exc:
            raise LinkDown("EOF while reading frame length") from exc
        length = int.from_bytes(header, "big")
        if length < 1 + CID_BYTES:
            raise ProtocolError(f"frame length {length} below minimum")
        if length > MAX_FRAME_BYTES:
            raise ProtocolError(f"frame length {length} exceeds {MAX_FRAME_BYTES}")
        try:
            body = await self._reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            raise LinkDown("EOF while reading frame body") from exc
        return decode_frame(body)


# ---------------------------------------------------------------------------
# Chunking + reassembly primitives (SPEC §4.4/§5).
# ---------------------------------------------------------------------------
def chunk_value(
    data: bytes, chunk_size: int = CHUNK_SIZE
) -> Iterator[Tuple[bytes, bool]]:
    """Slice one logical value's serialized bytes into ``(fragment, last)``
    pairs (SPEC §5): a value <= ``chunk_size`` -> one ``(data, True)``; a larger
    value -> N fragments with ``last=True`` ONLY on the final one (an exact
    multiple gets NO trailing empty fragment); a 0-byte value -> one
    ``(b'', True)`` (distinct from an empty STREAM)."""
    n = len(data)
    if n == 0:
        yield (b"", True)
        return
    off = 0
    while off < n:
        frag = data[off : off + chunk_size]
        off += chunk_size
        yield (frag, off >= n)


class Reassembler:
    """Accumulates one cid's CHUNK fragments + enforces the per-cid 8 MB
    reassembly-byte bound (SPEC §4.4). The per-peer + node-wide budgets and the
    pop-once decrement live in Transport, driven by the ``delta_bytes`` this
    returns; the wire layer owns only the per-cid buffer + byte count."""

    def __init__(self, per_cid_cap: int = PER_CID_REASSEMBLY_CAP):
        self.per_cid_cap = per_cid_cap
        self._buf: list = []
        self.byte_count = 0

    def accept(self, data: bytes, last: bool) -> Tuple[bool, int]:
        """Append a fragment; return ``(complete, delta_bytes)`` where
        ``complete`` is the CHUNK ``last`` flag and ``delta_bytes`` is the count
        Transport adds to the per-peer/node-wide budgets. Raises
        ``ReassemblyBoundExceeded`` (NOT ProtocolError) BEFORE mutating any state
        if this fragment would cross the per-cid cap (SPEC §4.4 — fail closed,
        keep the link)."""
        delta = len(data)
        if self.byte_count + delta > self.per_cid_cap:
            raise ReassemblyBoundExceeded(
                f"per-cid reassembly bound {self.per_cid_cap} exceeded "
                f"(have {self.byte_count}, +{delta})"
            )
        self.byte_count += delta
        self._buf.append(bytes(data))
        return (bool(last), delta)

    def take(self) -> bytes:
        """Return the joined reassembled bytes (SPEC §4.4)."""
        return b"".join(self._buf)
