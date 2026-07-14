"""Branch-local self-test for netcore.wire (Phase 2a).

Throwaway dev aid — the PARENT runs it (implementers can't run python). It
behaviorally gates wire.py before transport.py. Run from anywhere:

    python plexus/netcore/_wire_selftest.py

Exits non-zero (raises) on any failure; prints ``WIRE SELFTEST: PASS`` on
success.

REQUIRES: ``pip install msgpack`` (the SPEC-LOCKED control-field codec; not yet
a declared dependency — flagged to the maintainer).
"""

from __future__ import annotations

import os
import pickle
import sys

# Make ``plexus`` importable regardless of CWD (repo root = two levels up).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plexus.netcore import wire  # noqa: E402
from plexus.netcore.types import (  # noqa: E402
    CallerCtx,
    ErrorKind,
    ExecuteSelector,
    Kind,
    Mode,
    TopicSelector,
)


# A class NOT in the SafeUnpickler allowlist (module "__main__" when run as a
# script) — used to prove deserialize_value REJECTS a disallowed type.
class Disallowed:
    def __init__(self, x=1):
        self.x = x


def _decode(encoded: bytes) -> "wire.Frame":
    """Strip the 4B length prefix + decode, asserting the prefix is exact."""
    length = int.from_bytes(encoded[:4], "big")
    body = encoded[4:]
    assert length == len(body), f"length prefix {length} != body {len(body)}"
    return wire.decode_frame(body)


def test_frame_roundtrip():
    # PING
    f = _decode(wire.encode_ping(7, "hash-abc"))
    assert f.kind == Kind.PING and f.cid == 7 and f.have_hash == "hash-abc", f

    # PONG (both snapshot_follows values)
    for sf in (True, False):
        f = _decode(wire.encode_pong(9, "epoch-1", "chash-1", sf))
        assert f.kind == Kind.PONG and f.cid == 9
        assert f.epoch == "epoch-1" and f.content_hash == "chash-1"
        assert f.snapshot_follows is sf, f

    # CANCEL
    f = _decode(wire.encode_cancel(11))
    assert f.kind == Kind.CANCEL and f.cid == 11, f

    # CALL — execute selector, UNARY, with handler_timeout
    caller = CallerCtx("alice", "aid-1", "host-a", "req-1")
    sel = ExecuteSelector("MyPlugin", "do_thing", "uuid-xyz")
    f = _decode(wire.encode_call(13, sel, Mode.UNARY, caller, 30.5))
    assert f.kind == Kind.CALL and f.cid == 13
    assert f.selector == sel, f.selector
    assert f.mode == Mode.UNARY
    assert f.caller == caller, f.caller
    assert f.handler_timeout == 30.5, f.handler_timeout

    # CALL — topic selector, STREAM, handler_timeout=None (must round-trip None)
    tsel = TopicSelector("some/topic")
    f = _decode(wire.encode_call(15, tsel, Mode.STREAM, caller, None))
    assert f.selector == tsel and f.mode == Mode.STREAM
    assert f.handler_timeout is None, f.handler_timeout

    # CALL — FANOUT, handler_timeout absent
    f = _decode(wire.encode_call(17, tsel, Mode.FANOUT, caller, None))
    assert f.mode == Mode.FANOUT and f.handler_timeout is None, f

    # CALL — execute selector WITHOUT a plugin_uuid (uuid absent survives)
    sel2 = ExecuteSelector("P", "ep")
    f = _decode(wire.encode_call(18, sel2, Mode.FIRST, caller, 5.0))
    assert f.selector == sel2 and f.selector.plugin_uuid is None, f.selector

    # CHUNK
    f = _decode(wire.encode_chunk(19, b"\x00\x01\x02payload", True))
    assert f.kind == Kind.CHUNK and f.cid == 19
    assert f.data == b"\x00\x01\x02payload" and f.last is True, f
    f = _decode(wire.encode_chunk(19, b"", False))
    assert f.data == b"" and f.last is False, f

    # END
    f = _decode(wire.encode_end(21))
    assert f.kind == Kind.END and f.cid == 21, f

    # ERROR — kind only, no exc
    f = _decode(wire.encode_error(23, ErrorKind.NO_MATCH))
    assert f.kind == Kind.ERROR and f.cid == 23
    assert f.error_kind == ErrorKind.NO_MATCH and f.exc is None, f

    # ERROR — with an allowlisted exception object; exc bytes round-trip +
    # deserialize back to the SAME exception TYPE (kind decodes independently).
    from plexus.exceptions import RequestException

    f = _decode(wire.encode_error(25, ErrorKind.HANDLER_RAISED, RequestException("boom")))
    assert f.error_kind == ErrorKind.HANDLER_RAISED and f.exc is not None
    revived = wire.deserialize_value(f.exc)
    assert isinstance(revived, RequestException) and str(revived) == "boom", revived


def test_chunk_roundtrip_byte_exact():
    cs = wire.CHUNK_SIZE  # 64 KB
    sizes = [
        0,
        1024,
        cs,          # exactly 64 KB
        2 * cs,      # exactly 128 KB (exact multiple)
        cs - 1,      # 64 KB - 1
        cs + 1,      # 64 KB + 1
        3 * 1024 * 1024 + 7,  # multi-MB, not a clean multiple
    ]
    for n in sizes:
        data = bytes((i * 31 + 7) & 0xFF for i in range(n))
        frags = list(wire.chunk_value(data))

        # last-flag correctness: exactly one final True, all earlier False.
        assert frags, f"no fragments for n={n}"
        assert frags[-1][1] is True, f"final fragment not last (n={n})"
        assert all(not last for _, last in frags[:-1]), f"early last=True (n={n})"

        # exact-multiple + boundary chunk-COUNT checks.
        if n == 0:
            assert len(frags) == 1 and frags[0][0] == b"", f"0-byte value (n={n})"
        else:
            expected_chunks = (n + cs - 1) // cs
            assert len(frags) == expected_chunks, (
                f"n={n}: got {len(frags)} chunks, expected {expected_chunks}"
            )
            if n == 2 * cs:
                # exact multiple: 2 full chunks, NO trailing empty fragment.
                assert len(frags) == 2, frags
                assert len(frags[0][0]) == cs and len(frags[1][0]) == cs, frags

        # reassemble byte-exact.
        r = wire.Reassembler()
        complete = False
        for frag, last in frags:
            complete, _delta = r.accept(frag, last)
        assert complete is True, f"reassembly not complete (n={n})"
        assert r.take() == data, f"byte mismatch on n={n}"
        assert r.byte_count == n, f"byte_count {r.byte_count} != {n}"


def test_reassembly_delta_accounting():
    # accept returns (complete, delta_bytes) so Transport can drive budgets.
    r = wire.Reassembler()
    complete, delta = r.accept(b"a" * 100, False)
    assert complete is False and delta == 100, (complete, delta)
    complete, delta = r.accept(b"b" * 50, True)
    assert complete is True and delta == 50, (complete, delta)
    assert r.byte_count == 150 and r.take() == b"a" * 100 + b"b" * 50


def test_per_cid_bound_exceeded():
    r = wire.Reassembler(per_cid_cap=1024)
    r.accept(b"x" * 600, False)  # ok, under cap
    raised = False
    try:
        r.accept(b"y" * 600, True)  # 1200 > 1024 -> exceed
    except wire.ReassemblyBoundExceeded:
        raised = True
    assert raised, "expected ReassemblyBoundExceeded on per-cid over-cap"
    # State unchanged by the failing accept (fail closed BEFORE mutating).
    assert r.byte_count == 600, r.byte_count
    # And it is NOT a ProtocolError (that would tear the link).
    from plexus.netcore.types import ProtocolError

    assert not issubclass(wire.ReassemblyBoundExceeded, ProtocolError)


def test_safe_loads_allow_and_reject():
    # Allowlisted payload round-trips through serialize/deserialize.
    payload = {"a": [1, 2, 3], "b": "text", "c": (4, 5), "d": None, "e": b"raw"}
    raw = wire.serialize_value(payload)
    assert wire.deserialize_value(raw) == payload

    # A disallowed type is REJECTED after "reassembly" (safe_loads guard).
    hostile = pickle.dumps(Disallowed(99))
    rejected = False
    try:
        wire.deserialize_value(hostile)
    except pickle.UnpicklingError:
        rejected = True
    assert rejected, "expected SafeUnpickler to reject a disallowed type"


def test_malformed_frame_protocol_error():
    from plexus.netcore.types import ProtocolError

    # Truncated body (no cid) -> ProtocolError (tear-link condition).
    for bad in (b"", b"\x02", b"\x02\x00\x00"):
        raised = False
        try:
            wire.decode_frame(bad)
        except ProtocolError:
            raised = True
        assert raised, f"expected ProtocolError on malformed body {bad!r}"

    # Unknown kind byte -> ProtocolError.
    bad_kind = bytes((99,)) + (0).to_bytes(wire.CID_BYTES, "big") + wire.pack_control({})
    raised = False
    try:
        wire.decode_frame(bad_kind)
    except ProtocolError:
        raised = True
    assert raised, "expected ProtocolError on unknown kind byte"


def main():
    test_frame_roundtrip()
    test_chunk_roundtrip_byte_exact()
    test_reassembly_delta_accounting()
    test_per_cid_bound_exceeded()
    test_safe_loads_allow_and_reject()
    test_malformed_frame_protocol_error()
    print("WIRE SELFTEST: PASS")


if __name__ == "__main__":
    main()
