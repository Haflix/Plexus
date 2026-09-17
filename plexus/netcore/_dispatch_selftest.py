"""Branch-local self-test for netcore.dispatch (Phase 5).

Throwaway dev aid — the PARENT runs it (implementers can't run python):

    python -m plexus.netcore._dispatch_selftest

Prints ``DISPATCH SELFTEST: PASS``; exits non-zero (raises) on any failure.

Covers: (a) the 5 senders' ERROR.kind->TYPE mapping incl. the HANDLER_RAISED
nested-Network wrap (fake Transport); (b) inbound authz — anti-spoof drop +
`_core/peer/hostname_mismatch`, system_caller from RECORD not wire,
nodes_in/framework_in/IN-set ordering + no-double-charge, IN-set NOT charged on
re-match fail (fake rate-limiter); (c) THE BIG ONE — a REAL 2-node end-to-end
(all modules real) proving all 5 primitives A->B round-trip / raise the right
TYPE / stream in order / NO_MATCH falls through / uuid-wrong-instance ->
NO_ENDPOINT. Injected fakes only for the core registry/notifier + rate-limiter.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plexus.serialization import generate_keypair  # noqa: E402
from plexus.exceptions import (  # noqa: E402
    CapabilityException,
    NetworkRequestException,
    NoLocalSubException,
    RateLimitException,
    RequestException,
)
from plexus.netcore.directory import Directory  # noqa: E402
from plexus.netcore.dispatch import Dispatch, NoEndpointError  # noqa: E402
from plexus.netcore.membership import Membership  # noqa: E402
from plexus.netcore.transport import InboundReject, Transport  # noqa: E402
from plexus.netcore.types import (  # noqa: E402
    CallerCtx,
    ErrorKind,
    ExecuteSelector,
    LinkDown,
    Mode,
    PeerIdentity,
    PeerSpec,
    Timeout,
    TopicSelector,
)
from plexus.netcore.wire import Frame, Kind, serialize_value  # noqa: E402


# --- (a) sender-mapping fakes ----------------------------------------------
class _FakeStream:
    def __init__(self, items, error=None):
        self._items = list(items)
        self._error = error
        self._i = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._i < len(self._items):
            v = self._items[self._i]
            self._i += 1
            return v
        if self._error is not None:
            raise self._error
        raise StopAsyncIteration


class FakeTransport:
    def __init__(self):
        self.reply = None
        self.raise_exc = None
        self.stream_items = []
        self.stream_error = None
        self.sent = None

    async def request(self, hostname, call_frame, args, deadline):
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.reply

    async def open_stream(self, hostname, call_frame, args):
        return _FakeStream(self.stream_items, self.stream_error)

    def send(self, hostname, call_frame, args):
        self.sent = (hostname, call_frame, args)


def _err(kind, exc=None):
    return Frame(kind=Kind.ERROR, cid=0, error_kind=kind,
                 exc=serialize_value(exc) if exc is not None else None)


async def _capture(coro_fn):
    try:
        await coro_fn()
    except BaseException as e:  # noqa: BLE001
        return e
    return None


async def test_sender_error_mapping():
    ft = FakeTransport()
    d = Dispatch(transport=ft)
    caller = CallerCtx("x", "x", "a", "r")
    sel = ExecuteSelector("p", "e")

    async def call():
        return await d.execute_remote("b", sel, {}, caller, 10.0, deadline=0.0)

    cases = [
        (_err(ErrorKind.NO_MATCH), NoLocalSubException),
        (_err(ErrorKind.NETWORK), NetworkRequestException),
        (_err(ErrorKind.NO_ENDPOINT), NetworkRequestException),
        (_err(ErrorKind.RATE_LIMIT), RateLimitException),
        (_err(ErrorKind.CAPABILITY), CapabilityException),
    ]
    for reply, exc_type in cases:
        ft.reply = reply
        got = await _capture(call)
        assert isinstance(got, exc_type), f"{reply.error_kind} -> {type(got)} != {exc_type}"

    # #2 unified typing — HANDLER_RAISED mapping:
    # (i) a RAW handler exception (ValueError) is WRAPPED in RequestException so it
    #     never propagates to the caller as itself (request_event contract), and the
    #     wrap message carries the original type name.
    ft.reply = _err(ErrorKind.HANDLER_RAISED, ValueError("boom"))
    got = await _capture(call)
    assert type(got) is RequestException, type(got)
    assert not isinstance(got, ValueError), "raw handler ValueError leaked to caller"
    assert "ValueError" in str(got) and "boom" in str(got), got
    # (ii) a RequestException SUBTYPE raised by the handler is PRESERVED by type so
    #      the caller can `except RateLimitException`.
    ft.reply = _err(ErrorKind.HANDLER_RAISED, RateLimitException("slow down"))
    got = await _capture(call)
    assert type(got) is RateLimitException, type(got)
    assert "slow down" in str(got), got

    # HANDLER_RAISED nested-Network -> WRAPPED in a NON-Network RequestException.
    ft.reply = _err(ErrorKind.HANDLER_RAISED, NetworkRequestException("net"))
    got = await _capture(call)
    assert type(got) is RequestException, type(got)
    assert not isinstance(got, NetworkRequestException), "nested-Network not unwrapped"

    # link-level LinkDown / Timeout -> NetworkRequestException (fall through).
    ft.reply = None
    for raiser in (LinkDown("down"), Timeout("t")):
        ft.raise_exc = raiser
        got = await _capture(call)
        assert isinstance(got, NetworkRequestException), (raiser, type(got))
    ft.raise_exc = None

    # value passthrough.
    ft.reply = {"ok": 1}
    assert await call() == {"ok": 1}

    # stream sender maps a terminal ERROR frame; yields items in order.
    ft.stream_items = [{"i": 0}, {"i": 1}]
    ft.stream_error = None
    out = [x async for x in d.request_event_stream_remote("b", TopicSelector("t"), {}, caller, deadline=0.0)]
    assert out == [{"i": 0}, {"i": 1}], out

    err = LinkDown("stream err")
    err.error_frame = _err(ErrorKind.NO_MATCH)  # type: ignore[attr-defined]
    ft.stream_items = [{"i": 0}]
    ft.stream_error = err

    async def drain_stream():
        return [x async for x in d.request_event_stream_remote("b", TopicSelector("t"), {}, caller, deadline=0.0)]

    got = await _capture(drain_stream)
    assert isinstance(got, NoLocalSubException), type(got)

    # fanout sender is fire-and-forget (no reply); it just calls Transport.send.
    await d.publish_event_remote("b", "evt", {"z": 1}, caller)
    assert ft.sent is not None and ft.sent[0] == "b"


# --- (b) inbound-authz fakes -----------------------------------------------
class FakeRate:
    def __init__(self, allow=True):
        self.allow = allow
        self.order = []
        self.counts = {}

    def _tick(self, name):
        self.order.append(name)
        self.counts[name] = self.counts.get(name, 0) + 1

    def charge_nodes_in(self, hostname):
        self._tick("nodes_in")
        return self.allow

    def charge_framework_in(self):
        self._tick("framework_in")
        return self.allow

    def charge_in_set(self):
        self._tick("in_set")
        return True


class FakeMem:
    def __init__(self, roster=("a",)):
        self._roster = set(roster)

    def in_roster(self, h):
        return h in self._roster

    def identity_for(self, h):
        return PeerIdentity(h, False)


class FakeRegB:
    def __init__(self, rate):
        self.rate = rate
        self.got_identity = None

    async def execute(self, selector, payload, identity, caller):
        self.got_identity = identity
        if selector.endpoint == "missing":
            raise NoEndpointError("no such endpoint")  # re-match fail
        self.rate.charge_in_set()  # local re-entry charges the IN-set LAST
        return {"sys": identity.system_caller, "author": caller.author}


def _call_frame(author_host, endpoint="echo"):
    return Frame(kind=Kind.CALL, cid=0, selector=ExecuteSelector("p", endpoint),
                 mode=Mode.UNARY,
                 caller=CallerCtx("system", "aid", author_host, "r"),
                 handler_timeout=10.0)


async def test_inbound_authz():
    identity = PeerIdentity("a", False)  # authenticated record: system_caller=False
    mem = FakeMem(roster=("a",))

    # anti-spoof drop: wire author_host != authenticated hostname.
    obs = []
    rate = FakeRate()
    d = Dispatch(transport=None, membership=mem, registry=FakeRegB(rate), rate=rate,
                 observe=lambda e, p: obs.append((e, p)))
    got = None
    try:
        d.authorize_inbound(identity, _call_frame("wrong-host"))
    except InboundReject as r:
        got = r
    assert got is not None and got.error_kind == ErrorKind.NETWORK
    assert any(e == "_core/peer/hostname_mismatch" for e, _ in obs)

    # ordering + no-double-charge: nodes_in FIRST, framework_in, then IN-set.
    rate2 = FakeRate()
    reg2 = FakeRegB(rate2)
    d2 = Dispatch(transport=None, membership=mem, registry=reg2, rate=rate2)
    frame_ok = _call_frame("a")  # ExecuteSelector (execute)
    d2.authorize_inbound(identity, frame_ok)
    # EXECUTE: framework_in is NOT charged in authorize (the core execute re-entry
    # charges it — learning 12) -> nodes_in ONLY.
    assert rate2.order == ["nodes_in"], rate2.order
    result = await d2.dispatch_inbound(identity, frame_ok, {})
    # the registry re-entry (FakeRegB.execute) charges the IN-set.
    assert rate2.order == ["nodes_in", "in_set"], rate2.order
    assert rate2.counts == {"nodes_in": 1, "in_set": 1}, rate2.counts

    # an EVENT (TopicSelector) DOES charge framework_in in authorize (learning 12).
    rate_ev = FakeRate()
    d_ev = Dispatch(transport=None, membership=mem, registry=FakeRegB(rate_ev), rate=rate_ev)
    ev_frame = Frame(kind=Kind.CALL, cid=0, selector=TopicSelector("t/x"), mode=Mode.FIRST,
                     caller=CallerCtx("system", "aid", "a", "r"), handler_timeout=10.0)
    d_ev.authorize_inbound(identity, ev_frame)
    assert rate_ev.order == ["nodes_in", "framework_in"], rate_ev.order

    # system_caller from the RECORD (False), NOT the wire (author="system"). G6
    # anti-escalation: an ungranted peer that asserts author="system" has that claim
    # DOWNGRADED in-module (to author_id) before the registry sees it — the registry
    # never observes a wire-spoofed system author it did not grant.
    assert result["sys"] is False and result["author"] == "aid"
    assert reg2.got_identity.system_caller is False

    # IN-set NOT charged when re-match fails.
    rate3 = FakeRate()
    d3 = Dispatch(transport=None, membership=mem, registry=FakeRegB(rate3), rate=rate3)
    frame_missing = _call_frame("a", endpoint="missing")
    d3.authorize_inbound(identity, frame_missing)
    got = None
    try:
        await d3.dispatch_inbound(identity, frame_missing, {})
    except InboundReject as r:
        got = r
    assert got is not None and got.error_kind == ErrorKind.NO_ENDPOINT
    assert "in_set" not in rate3.counts, "IN-set charged on a re-match fail"


# --- (c) real 2-node end-to-end --------------------------------------------
class EmptyProvider:
    def endpoints(self):
        return []

    def subs(self):
        return []


class AllowRate:
    def charge_nodes_in(self, hostname):
        return True

    def charge_framework_in(self):
        return True


class EndToEndRegistry:
    """The callee's fake core registry re-entry (node B's handler logic)."""

    def __init__(self, host):
        self.host = host
        self.published = None
        self.stream_closed = False

    async def execute(self, selector, payload, identity, caller):
        if selector.plugin_uuid and selector.plugin_uuid != "real-uuid":
            raise NoEndpointError("uuid mismatch")  # §F#14
        if selector.endpoint == "boom":
            raise ValueError("handler blew up")
        if selector.endpoint == "echo":
            return {"echoed": payload, "by": self.host,
                    "sys": identity.system_caller, "author": caller.author}
        raise NoEndpointError("no such endpoint")

    async def request_event(self, topic, payload, identity, caller):
        if topic == "no/match":
            raise NoLocalSubException("no sub")
        return {"answered": topic, "payload": payload}

    def request_event_stream(self, topic, payload, identity, caller):
        if topic == "no/match":
            raise NoLocalSubException("no sub")
        if topic == "abandon/me":
            import time as _time

            def _slow():  # long SYNC gen; its finally MUST run on consumer abandon
                try:
                    for i in range(100):
                        _time.sleep(0.02)
                        yield {"item": i}
                finally:
                    self.stream_closed = True

            return _slow()

        def _gen():  # a SYNC generator -> exercises the B-081 drive (§F#20)
            for i in range(3):
                yield {"item": i}

        return _gen()

    def execute_stream(self, selector, payload, identity, caller):
        def _gen():
            for i in range(2):
                yield {"e_item": i}

        return _gen()

    async def publish_event(self, topic, payload, identity, caller):
        self.published = (topic, payload)


async def _make_node(tmp, hostname):
    cert, key, fp, pem = generate_keypair(os.path.join(tmp, hostname), hostname)
    provider = EmptyProvider()
    directory = Directory(provider, membership=None, self_hostname=hostname)
    mem = Membership(self_hostname=hostname, cert_file=cert, key_file=key,
                     directory=directory, require_peers=False,
                     heartbeat_interval=0.3, probe_timeout=1.0, liveness_timeout=5.0)
    directory._membership = mem  # patch the mutual ref
    registry = EndToEndRegistry(hostname)
    dispatch = Dispatch(transport=None, membership=mem, registry=registry, rate=AllowRate())
    transport = Transport(mem, directory, dispatch, listen_host="127.0.0.1",
                          listen_port=0, idle_read_deadline=120.0, drain_timeout=60.0,
                          liveness_timeout=5.0)
    mem.attach_transport(transport)
    dispatch.attach_transport(transport)
    await transport.start()
    port = transport._server.sockets[0].getsockname()[1]
    from types import SimpleNamespace
    return SimpleNamespace(hostname=hostname, fp=fp, pem=pem, mem=mem,
                           directory=directory, dispatch=dispatch,
                           transport=transport, registry=registry, port=port)


async def _wait(pred, timeout=8.0):
    loop = asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if pred():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_end_to_end():
    tmp = tempfile.mkdtemp(prefix="disp_e2e_")
    na = await _make_node(tmp, "a")
    nb = await _make_node(tmp, "b")
    try:
        na.mem.add_peer(PeerSpec("b", "127.0.0.1", nb.port, nb.pem, nb.fp))  # a<b -> a dials b
        nb.mem.add_peer(PeerSpec("a", "127.0.0.1", na.port, na.pem, na.fp))
        await na.mem.start()
        await nb.mem.start()
        up = await _wait(lambda: na.mem.reachable("b"), timeout=8)
        assert up, "link a->b did not come up"

        loop = asyncio.get_event_loop()
        caller = CallerCtx("system", "aid", "a", "r1")  # author="system" (must be IGNORED)

        def dl():
            return loop.time() + 10

        # execute (UNARY) round-trips; system_caller from RECORD (False), not wire.
        # G6 anti-escalation: the ungranted wire author="system" is downgraded to the
        # author_id ("aid") in-module before the callee registry sees it.
        r = await na.dispatch.execute_remote("b", ExecuteSelector("plug", "echo"),
                                             {"x": 1}, caller, 10.0, deadline=dl())
        assert r == {"echoed": {"x": 1}, "by": "b", "sys": False, "author": "aid"}, r

        # raising handler -> HANDLER_RAISED -> #2: a RAW ValueError is WRAPPED in
        # RequestException (never propagated to the caller as itself), with the
        # original type name preserved in the message.
        got = await _capture(lambda: na.dispatch.execute_remote(
            "b", ExecuteSelector("plug", "boom"), {}, caller, 10.0, deadline=dl()))
        assert type(got) is RequestException and not isinstance(got, ValueError), type(got)
        assert "ValueError" in str(got) and "handler blew up" in str(got), got

        # request_event (FIRST) round-trips.
        r2 = await na.dispatch.request_event_remote("b", TopicSelector("some/topic"),
                                                    {"y": 2}, caller, 10.0, deadline=dl())
        assert r2 == {"answered": "some/topic", "payload": {"y": 2}}, r2

        # NO_MATCH falls through -> NoLocalSubException.
        got = await _capture(lambda: na.dispatch.request_event_remote(
            "b", TopicSelector("no/match"), {}, caller, 10.0, deadline=dl()))
        assert isinstance(got, NoLocalSubException), type(got)

        # request_event_stream yields items IN ORDER (sync-gen driven on B).
        items = [x async for x in na.dispatch.request_event_stream_remote(
            "b", TopicSelector("s/t"), {}, caller, deadline=dl())]
        assert [x["item"] for x in items] == [0, 1, 2], items

        # execute stream too.
        eitems = [x async for x in na.dispatch.execute_remote_stream(
            "b", ExecuteSelector("plug", "gen"), {}, caller, deadline=dl())]
        assert [x["e_item"] for x in eitems] == [0, 1], eitems

        # uuid-WRONG-instance -> NO_ENDPOINT -> NetworkRequestException (fall through).
        got = await _capture(lambda: na.dispatch.execute_remote(
            "b", ExecuteSelector("plug", "echo", "wrong-uuid"), {}, caller, 10.0, deadline=dl()))
        assert isinstance(got, NetworkRequestException), type(got)

        # uuid-RIGHT-instance answers.
        r3 = await na.dispatch.execute_remote(
            "b", ExecuteSelector("plug", "echo", "real-uuid"), {"ok": 1}, caller, 10.0, deadline=dl())
        assert r3["echoed"] == {"ok": 1}, r3

        # publish_event (FANOUT) fire-and-forget reaches B's handler.
        await na.dispatch.publish_event_remote("b", "evt/x", {"z": 3}, caller)
        arrived = await _wait(lambda: nb.registry.published == ("evt/x", {"z": 3}), timeout=5)
        assert arrived, f"fanout did not arrive: {nb.registry.published}"

        # TP-19: early CONSUMER abandonment -> the remote producer is CANCELLED
        # promptly (B's sync-gen finally: runs), not left lingering.
        gen = na.dispatch.request_event_stream_remote(
            "b", TopicSelector("abandon/me"), {}, caller, deadline=dl())
        first = await gen.__anext__()
        assert first == {"item": 0}, first
        await gen.aclose()  # consumer abandons after 1 item
        closed = await _wait(lambda: nb.registry.stream_closed, timeout=5)
        assert closed, "remote stream producer not closed on consumer abandon (TP-19)"
    finally:
        for n in (na, nb):
            try:
                await asyncio.wait_for(n.mem.stop(), 3)
            except Exception:
                pass
            try:
                await asyncio.wait_for(n.transport.stop(), 5)
            except Exception:
                pass


async def main():
    await test_sender_error_mapping()
    await test_inbound_authz()
    await test_end_to_end()
    print("DISPATCH SELFTEST: PASS")


if __name__ == "__main__":
    asyncio.run(main())
