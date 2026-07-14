"""SPEC §5 wire codec for the hostile-peer harness.

Encodes/decodes the rewrite's frame format so the harness can inject frames a
rewrite node parses AND parse the frames it sends back. Locked composition pins
from SPEC §4.4/§5 + BUILD_BRIEF §3:

  Frame = ``[4B length][1B kind][cid + fields]``
    * length = big-endian uint32, counts ``[kind][cid + fields]`` (EXCLUDES the
      4 length bytes themselves).
    * kind byte table: PING=1, CALL=2, CANCEL=3, PONG=4, CHUNK=5, END=6, ERROR=7.
    * cid high bit = DIAL ROLE (dialer=1, acceptor=0). The hostile client is the
      DIALER, so every cid it opens sets the high bit (=1).
    * Control fields (all openers/terminators, DirectorySnapshot, vouched_peers)
      = msgpack. ``CHUNK.data`` = opaque bytes (a pickle byte-string the node
      feeds to ``safe_loads`` AFTER full reassembly — never per-chunk).

  Two carve-outs from "every cid is terminated by END/ERROR":
    * FANOUT/publish cid: no terminator, no reply (callee dispatches on the args'
      ``last=true``).
    * PING/PONG cid with ``snapshot_follows=false``: terminated by the PONG
      HEADER itself (no END).

============================ WIRE-LAYOUT ASSUMPTION ============================
SPEC §5 pins the kind table, the 4B-BE length convention, cid-high-bit=dial-role,
and the codec SPLIT (control=msgpack / CHUNK.data=opaque). It does NOT pin, to
the byte, the internal layout of ``[cid + fields]`` per kind (the cid field WIDTH
+ integer encoding, and where the msgpack map begins / how CHUNK's ``last`` flag
+ opaque data sit relative to the cid). This scaffold pins ONE self-consistent
layout (below) so the codec is concrete; if the winning rewrite lays the body out
differently, only the constants + the two encode/decode branches here change
(they are deliberately the single point of truth). This under-pin is the top open
item in WAVE2_TEST_MAP.md §Ambiguities — the byte layout must be confirmed against
the landed branch (or pinned into SPEC §5) before Type-X cells can go green, AND
it is a combine-compatibility pin (all 3 branches must encode identically or a
single Type-X harness cannot drive all three).

Assumed layout:
    control kinds (PING/CALL/CANCEL/PONG/END/ERROR):
        body = [8B cid, big-endian uint64, high bit = role] + msgpack(fields_dict)
        (fields_dict may be empty {} for END/CANCEL, which carry no fields)
    CHUNK:
        body = [8B cid] + [1B last flag: 0x00/0x01] + [opaque data bytes ...]
===============================================================================
"""
from __future__ import annotations

from typing import Any, NamedTuple, Optional

try:
    import msgpack  # the rewrite's control codec (a new dep the rewrite adds)
    HAVE_MSGPACK = True
except ImportError:  # pragma: no cover - scaffold import must stay clean pre-rewrite
    msgpack = None  # type: ignore[assignment]
    HAVE_MSGPACK = False

# --- kind byte table (SPEC §4.4/§5, LOCKED) --------------------------------
KIND_PING = 1
KIND_CALL = 2
KIND_CANCEL = 3
KIND_PONG = 4
KIND_CHUNK = 5
KIND_END = 6
KIND_ERROR = 7

KIND_NAME = {
    KIND_PING: "PING", KIND_CALL: "CALL", KIND_CANCEL: "CANCEL",
    KIND_PONG: "PONG", KIND_CHUNK: "CHUNK", KIND_END: "END", KIND_ERROR: "ERROR",
}

# --- mode ints (CALL.mode) — RE-POINTED to the winner's Mode enum (netcore
# types.py: UNARY=1/FIRST=2/STREAM=3/FANOUT=4/PING=5). The scaffold was authored
# 0-based; the winner is 1-based, and a 0 decodes as Mode(0)->ValueError->
# ProtocolError->link tear, so this MUST match. -----------------------------
MODE_UNARY = 1
MODE_FIRST = 2
MODE_STREAM = 3
MODE_FANOUT = 4

# --- ERROR.kind ints — RE-POINTED to the winner's ErrorKind enum (netcore
# types.py: NO_MATCH=1..NO_ENDPOINT=6), 1-based not 0-based. ------------------
ERR_NO_MATCH = 1
ERR_HANDLER_RAISED = 2
ERR_NETWORK = 3
ERR_RATE_LIMIT = 4
ERR_CAPABILITY = 5
ERR_NO_ENDPOINT = 6

# --- cid encoding (ASSUMPTION: 8B BE, high bit = dial role) ----------------
CID_BYTES = 8
_ROLE_BIT = 1 << (CID_BYTES * 8 - 1)  # top bit of the 64-bit cid


class WireError(Exception):
    """Malformed frame the codec cannot parse (short read, bad length, etc.)."""


def encode_cid(counter: int, *, dialer: bool = True) -> int:
    """Compose a cid from a per-link counter + the dial-role high bit.

    The hostile client is the DIALER, so ``dialer=True`` (high bit set) is the
    default — a node acting as ACCEPTOR treats a high-bit-set cid as peer-inbound
    (opens an inbound cid on CALL), which is exactly what a hostile injection
    needs. Pass ``dialer=False`` only to deliberately craft a WRONG-role cid
    (a frame the node should treat as its-own-outbound and thus discard).
    """
    if counter < 0 or counter >= _ROLE_BIT:
        raise ValueError(f"cid counter out of 63-bit range: {counter}")
    return (counter | _ROLE_BIT) if dialer else counter


def cid_role_is_dialer(cid: int) -> bool:
    return bool(cid & _ROLE_BIT)


class Frame(NamedTuple):
    """A decoded frame. ``fields`` is set for control kinds; ``data``/``last``
    for CHUNK. The raw undecoded body is kept on ``raw_body`` for adversarial
    asserts that need the exact bytes."""
    kind: int
    cid: int
    fields: Optional[dict]
    data: Optional[bytes]
    last: Optional[bool]
    raw_body: bytes

    @property
    def kind_name(self) -> str:
        return KIND_NAME.get(self.kind, f"UNKNOWN({self.kind})")


def _require_msgpack() -> None:
    if not HAVE_MSGPACK:
        raise RuntimeError(
            "msgpack is required to encode/decode control frames but is not "
            "installed. The rewrite adds it as a dependency; install it in the "
            "environment running the Type-X suite (pip install msgpack)."
        )


def encode_frame(
    kind: int,
    cid: int,
    *,
    fields: Optional[dict] = None,
    data: Optional[bytes] = None,
    last: Optional[bool] = None,
) -> bytes:
    """Encode one well-formed frame (length prefix + kind + cid + body)."""
    cid_bytes = cid.to_bytes(CID_BYTES, "big")
    if kind == KIND_CHUNK:
        body = cid_bytes + (b"\x01" if last else b"\x00") + (data or b"")
    else:
        _require_msgpack()
        body = cid_bytes + msgpack.packb(fields or {}, use_bin_type=True)
    payload = bytes([kind]) + body
    return len(payload).to_bytes(4, "big") + payload


def encode_raw(payload: bytes, *, declared_length: Optional[int] = None) -> bytes:
    """Encode a frame with a caller-chosen length prefix over an arbitrary
    payload — the malformed-frame primitive (TP-79). ``declared_length`` lets a
    cell LIE about the length (claim more/fewer bytes than ``payload`` carries)
    to drive a mid-frame-corruption / length-mismatch teardown. Defaults to the
    true length."""
    n = len(payload) if declared_length is None else declared_length
    return n.to_bytes(4, "big") + payload


def decode_frame(raw_frame: bytes) -> Frame:
    """Decode a full frame (INCLUDING the 4B length prefix). Raises WireError on
    a malformed / truncated frame."""
    if len(raw_frame) < 5:
        raise WireError(f"frame too short: {len(raw_frame)} bytes")
    declared = int.from_bytes(raw_frame[:4], "big")
    payload = raw_frame[4:]
    if len(payload) != declared:
        raise WireError(
            f"length mismatch: prefix says {declared}, body has {len(payload)}"
        )
    kind = payload[0]
    body = payload[1:]
    if len(body) < CID_BYTES:
        raise WireError(f"body shorter than a cid ({len(body)} < {CID_BYTES})")
    cid = int.from_bytes(body[:CID_BYTES], "big")
    rest = body[CID_BYTES:]
    if kind == KIND_CHUNK:
        if not rest:
            raise WireError("CHUNK body missing the last-flag byte")
        last = rest[0] == 0x01
        return Frame(kind, cid, None, rest[1:], last, rest)
    _require_msgpack()
    try:
        fields = msgpack.unpackb(rest, raw=False) if rest else {}
    except Exception as e:  # noqa: BLE001 - any msgpack failure = malformed
        raise WireError(f"msgpack decode failed for {KIND_NAME.get(kind)}: {e}")
    return Frame(kind, cid, fields, None, None, rest)
