"""Branch-local loopback self-test for netcore.transport (Phase 2b).

Throwaway dev aid — the PARENT runs it (implementers can't run python):

    python -m plexus.netcore._transport_selftest

Prints ``TRANSPORT SELFTEST: PASS``; exits non-zero (raises) on any failure.

The three stub collaborators (Membership context-provider / Directory /
Dispatch) are INJECTED as minimal test-doubles: a real self-signed mTLS context
pair + matching pin set (Membership), a fixed-Pong Directory, and an echo /
stream / slow-cancellable inbound handler (Dispatch). A real loopback TLS
PeerLink PAIR is driven through: unary round-trip, a multi-MB BYTE-EXACT value,
a 3-item stream + an empty stream, a CANCEL mid-stream (producer actually
stops), and a per-cid reassembly-bound-exceed (cid dropped + CANCEL + LINK STAYS
UP → a later normal call on the same link succeeds).
"""

from __future__ import annotations

import asyncio
import os
import ssl
import sys
import tempfile

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plexus.serialization import generate_keypair  # noqa: E402
from plexus.netcore import wire  # noqa: E402
from plexus.netcore.transport import Transport, _OutValue  # noqa: E402
from plexus.netcore.types import (  # noqa: E402
    CallerCtx,
    DirectorySnapshot,
    EndpointEntry,
    ExecuteSelector,
    Mode,
    PeerIdentity,
    PeerSpec,
    Pong,
    RemoteSub,
    VouchedPeer,
)
from plexus.netcore.wire import Frame, Kind  # noqa: E402


# --- test-double collaborators ---------------------------------------------
def _build_ctx(protocol, cert_file, key_file, peer_pem):
    ctx = ssl.SSLContext(protocol)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    ctx.load_verify_locations(cadata=peer_pem)
    return ctx


class FakeMembership:
    """Stands in for Membership's context-provider + roster/pin/identity seam."""

    def __init__(self, self_hostname, cert_file, key_file, peer_hostname, peer_fp, peer_pem):
        self.self_hostname = self_hostname
        self._server_ctx = _build_ctx(ssl.PROTOCOL_TLS_SERVER, cert_file, key_file, peer_pem)
        self._client_ctx = _build_ctx(ssl.PROTOCOL_TLS_CLIENT, cert_file, key_file, peer_pem)
        self._pins = {peer_fp: peer_hostname}
        self._roster = {peer_hostname}
        self.link_up = asyncio.Event()

    def server_ssl_context(self):
        return self._server_ctx

    def client_ssl_context(self):
        return self._client_ctx

    def resolve_pin(self, fingerprint):
        return self._pins.get(fingerprint)

    def in_roster(self, hostname):
        return hostname in self._roster

    def identity_for(self, hostname):
        return PeerIdentity(hostname, False)

    def on_link_up(self, hostname):
        self.link_up.set()


class FakeDirectory:
    def build_pong(self, have_hash):
        return Pong(epoch="epoch-x", content_hash="hash-y", snapshot_follows=False)

    def serve_ping(self, peer, have_hash):
        return self.build_pong(have_hash)


class FakeSnapshotDirectory:
    """Returns a LARGE (>64KB, multi-chunk) snapshot_follows=True snapshot so the
    requester must reassemble + msgpack-decode it (proves the §4.4 migration)."""

    def __init__(self, snapshot):
        self._snap = snapshot

    def build_pong(self, have_hash):
        follows = have_hash != self._snap.content_hash
        return Pong(
            epoch=self._snap.epoch,
            content_hash=self._snap.content_hash,
            snapshot_follows=follows,
            snapshot=self._snap if follows else None,
        )

    def serve_ping(self, peer, have_hash):
        return self.build_pong(have_hash)


class FakeDispatch:
    def __init__(self):
        self.stream_cancelled = asyncio.Event()

    def authorize_inbound(self, identity, frame):
        return None  # accept everything

    def dispatch_inbound(self, identity, frame, args):
        if frame.mode == Mode.STREAM:
            return self._stream(args)
        return self._echo(args)  # coroutine for UNARY/FIRST

    async def _echo(self, args):
        return args

    async def _stream(self, args):
        kind = args.get("kind") if isinstance(args, dict) else None
        if kind == "empty":
            if False:
                yield None  # makes this an async generator; empty stream
            return
        if kind == "slow":
            try:
                yield "item-0"
                await asyncio.sleep(100)  # cancellable; the CANCEL hits here
                yield "item-1"
            finally:
                self.stream_cancelled.set()
            return
        for i in range(3):
            yield f"item-{i}"


# --- harness ----------------------------------------------------------------
def _caller():
    return CallerCtx("tester", "tid", "a", "req-1")


def _call_frame(mode, endpoint="echo"):
    return Frame(
        kind=Kind.CALL,
        cid=0,
        selector=ExecuteSelector("P", endpoint),
        mode=mode,
        caller=_caller(),
        handler_timeout=10.0 if mode in (Mode.UNARY, Mode.FIRST) else None,
    )


async def _make_pair(directory=None, **tkw):
    """Build + start a loopback pair a<->b (a dials b). Returns
    (ta, tb, dispatch_b, cleanup). ``directory`` overrides the shared fake
    Directory (e.g. FakeSnapshotDirectory for the snapshot round-trip)."""
    tmp = tempfile.mkdtemp(prefix="netcore_tp_")
    dir_a = os.path.join(tmp, "a")
    dir_b = os.path.join(tmp, "b")
    ca, ka, fpa, pema = generate_keypair(dir_a, "a")
    cb, kb, fpb, pemb = generate_keypair(dir_b, "b")

    mem_a = FakeMembership("a", ca, ka, "b", fpb, pemb)
    mem_b = FakeMembership("b", cb, kb, "a", fpa, pema)
    dir_obj = directory if directory is not None else FakeDirectory()
    disp_a = FakeDispatch()
    disp_b = FakeDispatch()

    common = dict(idle_read_deadline=120.0, drain_timeout=60.0)
    common.update(tkw)

    tb = Transport(mem_b, dir_obj, disp_b, listen_host="127.0.0.1", listen_port=0, **common)
    await tb.start()
    port_b = tb._server.sockets[0].getsockname()[1]
    ta = Transport(mem_a, dir_obj, disp_a, listen_host="127.0.0.1", listen_port=0, **common)
    await ta.start()

    spec_b = PeerSpec(hostname="b", ip="127.0.0.1", port=port_b, cert_pem=pemb, fingerprint=fpb)
    ta.start_link(spec_b)  # a<b -> a dials; b only accepts

    # wait for the a->b link
    loop = asyncio.get_event_loop()
    deadline = loop.time() + 10
    while loop.time() < deadline:
        try:
            ta._get_link("b")
            break
        except Exception:
            await asyncio.sleep(0.05)
    else:
        raise RuntimeError("link a->b did not come up")

    async def cleanup():
        try:
            await asyncio.wait_for(ta.stop(), 5)
        except Exception:
            pass
        try:
            await asyncio.wait_for(tb.stop(), 5)
        except Exception:
            pass

    return ta, tb, disp_b, cleanup


async def test_unary_roundtrip():
    ta, tb, _disp, cleanup = await _make_pair()
    try:
        loop = asyncio.get_event_loop()
        result = await ta.request(
            "b", _call_frame(Mode.UNARY), {"hello": "world"}, loop.time() + 10
        )
        assert result == {"hello": "world"}, result
    finally:
        await cleanup()


async def test_large_value_byte_exact():
    ta, tb, _disp, cleanup = await _make_pair()
    try:
        loop = asyncio.get_event_loop()
        blob = os.urandom(3 * 1024 * 1024 + 123)  # multi-MB, > CHUNK_SIZE
        result = await ta.request(
            "b", _call_frame(Mode.UNARY), blob, loop.time() + 30
        )
        assert isinstance(result, bytes) and result == blob, (
            f"large value mismatch: {len(result)} vs {len(blob)}"
        )
    finally:
        await cleanup()


async def test_stream_three_and_empty():
    ta, tb, _disp, cleanup = await _make_pair()
    try:
        q = await ta.open_stream("b", _call_frame(Mode.STREAM), {"kind": "three"})
        items = [item async for item in q]
        assert items == ["item-0", "item-1", "item-2"], items

        q2 = await ta.open_stream("b", _call_frame(Mode.STREAM), {"kind": "empty"})
        empty = [item async for item in q2]
        assert empty == [], empty
    finally:
        await cleanup()


async def test_cancel_mid_stream():
    ta, tb, disp_b, cleanup = await _make_pair()
    try:
        q = await ta.open_stream("b", _call_frame(Mode.STREAM), {"kind": "slow"})
        first = await q.__anext__()
        assert first == "item-0", first
        # abandon: cancel the outbound stream cid.
        ta.cancel("b", q.cid)
        # the callee's producer must actually stop (its generator finally runs).
        await asyncio.wait_for(disp_b.stream_cancelled.wait(), 5)
        assert disp_b.stream_cancelled.is_set()
    finally:
        await cleanup()


async def test_reassembly_bound_exceed_link_survives():
    # tiny per-cid cap so a modest value trips the per-cid bound on the callee.
    ta, tb, _disp, cleanup = await _make_pair(per_cid_cap=512)
    try:
        loop = asyncio.get_event_loop()
        big = b"x" * 4000  # pickled > 512 -> exceeds the callee per-cid bound
        raised = False
        try:
            await ta.request("b", _call_frame(Mode.UNARY), big, loop.time() + 10)
        except Exception:
            raised = True  # CANCEL from callee -> pending fails
        assert raised, "expected the over-bound call to fail"

        # LINK STAYS UP: a later normal (small) call on the SAME link succeeds.
        ok = await ta.request(
            "b", _call_frame(Mode.UNARY), b"ok", loop.time() + 10
        )
        assert ok == b"ok", ok
    finally:
        await cleanup()


async def test_slowdrip_absolute_deadline():
    # tiny ABSOLUTE per-reassembly deadline + LARGE idle deadline, so the
    # ABSOLUTE (monotonic) deadline is what fires on a reassembly that STARTS
    # but never completes and stays UNDER the idle deadline (the v4.4.2 slow-drip
    # guard, TG-18/TP-75).
    ta, tb, _disp, cleanup = await _make_pair(
        reassembly_abs_deadline=0.5, stream_idle=10.0
    )
    try:
        loop = asyncio.get_event_loop()
        link = ta._get_link("b")
        cid = link._alloc_cid()
        cf = _call_frame(Mode.UNARY)
        # manually send a CALL + ONE non-last CHUNK, then silence: the callee
        # opens the inbound cid, buffers a partial arg value, and never sees the
        # rest. The absolute deadline must drop that cid + CANCEL + KEEP the link.
        frames = [
            wire.encode_call(cid, cf.selector, cf.mode, cf.caller, cf.handler_timeout),
            wire.encode_chunk(cid, b"partial-then-silence", False),
        ]
        link.enqueue_value(_OutValue(frames))
        await asyncio.sleep(1.5)  # > abs(0.5), << idle(10) -> the absolute fired
        # LINK STAYS UP: a normal call on the SAME link still succeeds.
        ok = await ta.request(
            "b", _call_frame(Mode.UNARY), b"still-alive", loop.time() + 10
        )
        assert ok == b"still-alive", ok
    finally:
        await cleanup()


async def test_ping_snapshot_roundtrip_msgpack():
    # §4.4 migration proof: a LARGE (>64KB, multi-chunk) snapshot_follows=True
    # snapshot round-trips over a REAL loopback link and msgpack-decodes
    # field-for-field on the requester.
    big_desc = "x" * 200_000  # forces a multi-chunk (>64KB) msgpack body
    snapshot = DirectorySnapshot(
        epoch="epoch-snap",
        content_hash="sha256:deadbeef",
        endpoints=[
            EndpointEntry("b", "run", "plugX", "uuid-1", "2.0", big_desc,
                          {"nested": {"k": [1, 2, 3]}}, ["ai_tool", "x"], True, True),
            EndpointEntry("b", "ping", "plugY", "uuid-2", "1.0", "small",
                          {}, [], True, True),
        ],
        tagged={},  # derived on decode; not sent
        subs=[RemoteSub("s1", "topic/*", ["alice"], [], ["h1"], [], "plugX", True)],
        vouched_peers=[VouchedPeer("v1", "127.0.0.1:2510", "sha256:fp1", "PEM-DATA")],
    )
    ta, tb, _disp, cleanup = await _make_pair(
        directory=FakeSnapshotDirectory(snapshot)
    )
    try:
        loop = asyncio.get_event_loop()
        # ping with a MISMATCHING have_hash -> snapshot_follows=True.
        pong = await ta.ping("b", "not-the-hash", loop.time() + 10)
        assert pong.snapshot_follows is True, pong
        assert pong.snapshot is not None
        got = await asyncio.wait_for(pong.snapshot, 10)  # reassemble + msgpack-decode
        assert isinstance(got, DirectorySnapshot), type(got)
        assert got.epoch == "epoch-snap" and got.content_hash == "sha256:deadbeef"
        # endpoints field-for-field (incl. the multi-chunk big description).
        assert len(got.endpoints) == 2
        e0 = got.endpoints[0]
        assert isinstance(e0, EndpointEntry)
        assert e0.access_name == "run" and e0.plugin_name == "plugX"
        assert e0.description == big_desc and len(e0.description) == 200_000
        assert e0.arguments == {"nested": {"k": [1, 2, 3]}}
        assert e0.tags == ["ai_tool", "x"]
        # tagged re-derived from endpoints on decode.
        assert set(got.tagged.keys()) == {"ai_tool", "x"}
        # subs + vouched field-for-field.
        assert isinstance(got.subs[0], RemoteSub) and got.subs[0].sub_uuid == "s1"
        assert got.subs[0].authors == ["alice"] and got.subs[0].hosts == ["h1"]
        assert isinstance(got.vouched_peers[0], VouchedPeer)
        assert got.vouched_peers[0].hostname == "v1"
        assert got.vouched_peers[0].cert_pem == "PEM-DATA"
    finally:
        await cleanup()


async def test_ping_header():
    ta, tb, _disp, cleanup = await _make_pair()
    try:
        loop = asyncio.get_event_loop()
        pong = await ta.ping("b", "some-have-hash", loop.time() + 10)
        assert pong.epoch == "epoch-x" and pong.content_hash == "hash-y", pong
        assert pong.snapshot_follows is False
    finally:
        await cleanup()


def test_node_wide_reservation_guaranteed_minimum():
    """§4.4/§F#19 (TG-09 at the unit level): the node-wide cap reserves a per-peer
    MINIMUM. A peer whose usage stays within `per_peer_min` is ALWAYS admitted, even
    when the node is at/over `node_cap`; above the minimum it must fit the node cap;
    `per_peer_cap` is the hard per-peer ceiling. `can_charge` reads only these four
    self-attrs + the link's `_reasm_bytes`, so a duck-typed stand-in exercises it
    without sockets. This is the guarantee the `node_reassembly_cap` knob makes
    testable at a realistically-low node ceiling."""
    from types import SimpleNamespace
    MB = 1024 * 1024
    t = SimpleNamespace(per_peer_cap=16 * MB, per_peer_min=2 * MB,
                        node_cap=24 * MB, _node_reasm=24 * MB)  # node FULL
    # a newcomer's small reassembly (1MB < 2MB min) is admitted despite the full node.
    assert Transport.can_charge(t, SimpleNamespace(_reasm_bytes=0), 1 * MB) is True
    # a peer already at its min, growing further while the node is full → rejected.
    assert Transport.can_charge(t, SimpleNamespace(_reasm_bytes=2 * MB), 1 * MB) is False
    # with node headroom, growth above the min is fine.
    t._node_reasm = 0
    assert Transport.can_charge(t, SimpleNamespace(_reasm_bytes=2 * MB), 5 * MB) is True
    # the per_peer_cap ceiling is enforced regardless of node headroom.
    assert Transport.can_charge(t, SimpleNamespace(_reasm_bytes=16 * MB), 1) is False
    # a LOWER node_cap makes the reservation bite earlier (the knob's effect):
    t2 = SimpleNamespace(per_peer_cap=16 * MB, per_peer_min=2 * MB,
                         node_cap=8 * MB, _node_reasm=8 * MB)
    assert Transport.can_charge(t2, SimpleNamespace(_reasm_bytes=0), 1 * MB) is True   # min still honored
    assert Transport.can_charge(t2, SimpleNamespace(_reasm_bytes=3 * MB), 1 * MB) is False  # over min, node full


async def main():
    test_node_wide_reservation_guaranteed_minimum()
    await test_unary_roundtrip()
    await test_large_value_byte_exact()
    await test_stream_three_and_empty()
    await test_cancel_mid_stream()
    await test_reassembly_bound_exceed_link_survives()
    await test_slowdrip_absolute_deadline()
    await test_ping_snapshot_roundtrip_msgpack()
    await test_ping_header()
    print("TRANSPORT SELFTEST: PASS")


if __name__ == "__main__":
    asyncio.run(main())
