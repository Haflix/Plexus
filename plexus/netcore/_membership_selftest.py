"""Branch-local self-test for netcore.membership (Phase 3).

Throwaway dev aid — the PARENT runs it (implementers can't run python):

    python -m plexus.netcore._membership_selftest

Prints ``MEMBERSHIP SELFTEST: PASS``; exits non-zero (raises) on any failure.

Coverage:
 (a) the 3 mutators' state transitions + tombstone persistence across a reload +
     voucher-budget cap + LAN-CIDR reject + fingerprint-conflict + empty-peers
     boot error;
 (b) a REAL 2-node link-up with PLAIN generate_keypair certs (add_peer both
     ends -> Transport dials -> mutual mTLS -> SPKI pin verified -> link up + a
     cross-node ``ping`` succeeds);
 (c) revoke -> link torn + roster-gated (peer stays gone against a racing pulse
     stamp);
 (d) runtime add of a peer that connects INBOUND (proves the acceptor
     context-refresh — the phase-2b carry-over).

Directory + Dispatch are injected fakes.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import sys
import tempfile
from types import SimpleNamespace

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plexus.serialization import generate_keypair  # noqa: E402
from plexus.netcore.membership import Membership  # noqa: E402
from plexus.netcore.transport import Transport  # noqa: E402
from plexus.netcore.types import (  # noqa: E402
    PeerSource,
    PeerSpec,
    Pong,
    VouchedPeer,
)


# --- fakes ------------------------------------------------------------------
class FakeDirectory:
    def __init__(self, hostname):
        self.epoch = "epoch-" + hostname
        self.remote = {}

    def have_hash(self, peer):
        return ""

    def replace(self, peer, snap):
        self.remote[peer] = snap

    def drop_remote(self, hostname):
        self.remote.pop(hostname, None)

    def build_pong(self, have_hash):
        return Pong(epoch=self.epoch, content_hash="h", snapshot_follows=False)

    def serve_ping(self, peer, have_hash):
        return self.build_pong(have_hash)


class FakeDispatch:
    def authorize_inbound(self, identity, frame):
        return None

    def dispatch_inbound(self, identity, frame, args):
        async def _echo():
            return args

        return _echo()


# --- helpers ----------------------------------------------------------------
def _gen(tmp, dirname, hostname):
    cert, key, fp, pem = generate_keypair(os.path.join(tmp, dirname), hostname)
    return cert, key, fp, pem


def _peer_spec(tmp, dirname, hostname, ip="127.0.0.1", port=2510, **kw):
    _c, _k, fp, pem = _gen(tmp, dirname, hostname)
    return PeerSpec(hostname=hostname, ip=ip, port=port, cert_pem=pem, fingerprint=fp, **kw)


def _vouched(tmp, dirname, hostname, address):
    _c, _k, fp, pem = _gen(tmp, dirname, hostname)
    return VouchedPeer(hostname=hostname, address=address, fingerprint=fp, cert_pem=pem)


def _unit_membership(tmp, self_host, **kw):
    cert, key, _fp, _pem = _gen(tmp, "self_" + self_host, self_host)
    events = []
    mem = Membership(
        self_hostname=self_host,
        cert_file=cert,
        key_file=key,
        directory=FakeDirectory(self_host),
        transport=None,
        observe=lambda e, p: events.append((e, p)),
        require_peers=False,
        discoverable=kw.pop("discoverable", True),  # §4.7: these cells exercise ingest
        **kw,
    )
    return mem, events


async def _wait_until(pred, timeout=8.0):
    loop = asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if pred():
            return True
        await asyncio.sleep(0.05)
    return False


async def _make_node(tmp, hostname, **mem_kw):
    cert, key, fp, pem = _gen(tmp, "node_" + hostname, hostname)
    directory = FakeDirectory(hostname)
    dispatch = FakeDispatch()
    mem = Membership(
        self_hostname=hostname,
        cert_file=cert,
        key_file=key,
        directory=directory,
        require_peers=False,
        heartbeat_interval=0.3,
        probe_timeout=1.0,
        liveness_timeout=5.0,
        discoverable=mem_kw.pop("discoverable", True),  # §4.7: socket cells may exercise ingest
        **mem_kw,
    )
    transport = Transport(
        mem,
        directory,
        dispatch,
        listen_host="127.0.0.1",
        listen_port=0,
        idle_read_deadline=120.0,
        drain_timeout=60.0,
        liveness_timeout=5.0,
    )
    mem.attach_transport(transport)
    await transport.start()
    port = transport._server.sockets[0].getsockname()[1]
    return SimpleNamespace(
        hostname=hostname, cert=cert, key=key, fp=fp, pem=pem,
        directory=directory, mem=mem, transport=transport, port=port,
    )


async def _teardown(*nodes):
    for n in nodes:
        try:
            await asyncio.wait_for(n.mem.stop(), 3)
        except Exception:
            pass
        try:
            await asyncio.wait_for(n.transport.stop(), 5)
        except Exception:
            pass


# --- (a) unit tests of the 3 mutators --------------------------------------
async def test_add_remove_roster_pin():
    tmp = tempfile.mkdtemp(prefix="ms_a_")
    mem, _ev = _unit_membership(tmp, "self")
    spec = _peer_spec(tmp, "p1", "peer1", system_caller=True)
    mem.add_peer(spec)
    assert mem.in_roster("peer1")
    assert mem.resolve_pin(spec.fingerprint) == "peer1"
    assert mem.identity_for("peer1").system_caller is True

    mem.remove_peer("peer1")
    assert not mem.in_roster("peer1")
    assert mem.resolve_pin(spec.fingerprint) is None
    assert "peer1" in mem._tombstone
    assert mem.reachable("peer1") is False


async def test_tombstone_persist_reload():
    tmp = tempfile.mkdtemp(prefix="ms_tomb_")
    tomb = os.path.join(tmp, "tombstones.json")
    specx = _peer_spec(tmp, "px", "peerX")

    m1, _ = _unit_membership(tmp, "self1", tombstone_path=tomb)
    m1.add_peer(specx)
    m1.remove_peer("peerX")  # persisted

    # reload: seed_config_peers must SKIP the revoked hostname.
    m2, _ = _unit_membership(tmp, "self1b", tombstone_path=tomb)
    assert "peerX" in m2._tombstone, "tombstone not reloaded"
    m2.seed_config_peers([specx])
    assert not m2.in_roster("peerX"), "revoked peer re-added by reload"

    # explicit operator add_peer is the ONLY clear.
    m2.add_peer(specx)
    assert m2.in_roster("peerX")
    assert "peerX" not in m2._tombstone


async def test_voucher_budget_cap():
    tmp = tempfile.mkdtemp(prefix="ms_bud_")
    mem, events = _unit_membership(tmp, "self", voucher_cap=2)
    voucher = _peer_spec(tmp, "v", "voucher")
    mem.add_peer(voucher)  # voucher must be in roster (source-voucher gate)

    entries = [
        _vouched(tmp, "c1", "c1", "127.0.0.1:40001"),
        _vouched(tmp, "c2", "c2", "127.0.0.1:40002"),
        _vouched(tmp, "c3", "c3", "127.0.0.1:40003"),
    ]
    mem.ingest_vouched("voucher", entries)
    assert mem.in_roster("c1") and mem.in_roster("c2")
    assert not mem.in_roster("c3"), "3rd vouch exceeded cap but was added"
    assert mem._per_voucher_active.get("voucher") == 2
    assert any(e == "_core/peer/vouched" and p["hostname"] == "c1" for e, p in events)
    assert any(
        e == "_core/peer/vouch_rejected" and p.get("reason") == "budget"
        for e, p in events
    ), "no budget-reject audit"

    # churn frees budget: removing c1 decrements the voucher's active count.
    mem.remove_peer("c1")
    assert mem._per_voucher_active.get("voucher") == 1


async def test_cidr_reject():
    tmp = tempfile.mkdtemp(prefix="ms_cidr_")
    mem, events = _unit_membership(tmp, "self")
    voucher = _peer_spec(tmp, "v", "voucher")
    mem.add_peer(voucher)

    bad = _vouched(tmp, "cbad", "cbad", "8.8.8.8:2510")  # public IP, outside LAN CIDR
    mem.ingest_vouched("voucher", [bad])
    assert not mem.in_roster("cbad")
    assert any(
        e == "_core/peer/vouch_rejected" and p.get("reason") == "cidr"
        for e, p in events
    ), "no CIDR-reject audit"


async def test_fingerprint_conflict():
    tmp = tempfile.mkdtemp(prefix="ms_conf_")
    mem, events = _unit_membership(tmp, "self")
    voucher = _peer_spec(tmp, "v", "voucher")
    mem.add_peer(voucher)

    specx = _peer_spec(tmp, "px", "peerX")  # config-pinned peerX with fp X
    mem.add_peer(specx)

    # a vouch for the SAME hostname with a DIFFERENT fingerprint -> conflict,
    # existing pin WINS, never auto-replace.
    conflicting = _vouched(tmp, "px_alt", "peerX", "127.0.0.1:40010")
    assert conflicting.fingerprint != specx.fingerprint
    mem.ingest_vouched("voucher", [conflicting])
    assert mem.resolve_pin(specx.fingerprint) == "peerX", "existing pin lost"
    assert mem.resolve_pin(conflicting.fingerprint) is None, "conflicting fp pinned"
    assert any(e == "_core/peer/vouch_conflict" for e, _p in events)


async def test_failed_add_preserves_tombstone():
    # F#1 regression: a FAILING add_peer (bad PEM -> context build raises) for a
    # revoked hostname must NOT wipe the persisted tombstone then abort (that
    # would be a revoke-durability hole).
    tmp = tempfile.mkdtemp(prefix="ms_f1_")
    tomb = os.path.join(tmp, "t.json")
    mem, _ev = _unit_membership(tmp, "self", tombstone_path=tomb)
    specx = _peer_spec(tmp, "px", "peerX")
    mem.add_peer(specx)
    mem.remove_peer("peerX")  # tombstoned + persisted
    assert "peerX" in mem._tombstone

    bad = dataclasses.replace(
        specx,
        cert_pem="-----BEGIN CERTIFICATE-----\nnot-a-valid-cert\n-----END CERTIFICATE-----\n",
    )
    raised = False
    try:
        mem.add_peer(bad)
    except Exception:
        raised = True
    assert raised, "a bad-PEM add should raise"
    assert "peerX" in mem._tombstone, "F#1: a failed add wiped the tombstone"
    assert not mem.in_roster("peerX")


async def test_empty_peers_boot_error():
    tmp = tempfile.mkdtemp(prefix="ms_empty_")
    cert, key, _fp, _pem = _gen(tmp, "self", "self")
    mem = Membership(
        self_hostname="self",
        cert_file=cert,
        key_file=key,
        directory=FakeDirectory("self"),
        require_peers=True,
    )
    raised = False
    try:
        await mem.start()
    except RuntimeError:
        raised = True
    assert raised, "empty peers: should be a hard boot error (§4.1)"


# --- (b)+(c) real 2-node link-up + revoke -----------------------------------
async def test_socket_linkup_and_revoke():
    tmp = tempfile.mkdtemp(prefix="ms_sock_")
    na = await _make_node(tmp, "a")
    nb = await _make_node(tmp, "b")
    try:
        spec_b = PeerSpec(hostname="b", ip="127.0.0.1", port=nb.port,
                          cert_pem=nb.pem, fingerprint=nb.fp)
        spec_a = PeerSpec(hostname="a", ip="127.0.0.1", port=na.port,
                          cert_pem=na.pem, fingerprint=na.fp)
        na.mem.add_peer(spec_b)  # a<b -> a dials b
        nb.mem.add_peer(spec_a)  # b accepts
        await na.mem.start()
        await nb.mem.start()

        # (b) link up (mutual mTLS + SPKI pin) -> reachable + a cross-node ping.
        up = await _wait_until(lambda: na.mem.reachable("b"), timeout=8)
        assert up, "a never became reachable to b (mutual mTLS link-up failed)"
        loop = asyncio.get_event_loop()
        pong = await na.transport.ping("b", "", loop.time() + 3)
        assert pong is not None and pong.epoch == nb.directory.epoch, pong

        # (c) revoke -> roster-gated + link torn.
        na.mem.remove_peer("b")
        assert not na.mem.in_roster("b")
        assert "b" in na.mem._tombstone
        assert na.mem.reachable("b") is False
        # racing pulse stamp must NOT resurrect a revoked peer (§F#3).
        na.mem._stamp_alive("b", "racing-epoch")
        assert na.mem.reachable("b") is False, "roster-gate failed: peer resurrected"
        # link torn: a ping now fails (no link).
        raised = False
        try:
            await na.transport.ping("b", "", loop.time() + 2)
        except Exception:
            raised = True
        assert raised, "link to a revoked peer should be torn"
    finally:
        await _teardown(na, nb)


# --- (d) acceptor context-refresh on runtime ADD ----------------------------
async def test_acceptor_context_refresh():
    tmp = tempfile.mkdtemp(prefix="ms_refresh_")
    # n2 is the LISTENER, started with an EMPTY roster (trusts nobody at bind).
    n2 = await _make_node(tmp, "n2")
    # n1 is a NEW, lex-lower peer added at runtime -> it DIALS n2 (inbound at n2).
    n1 = await _make_node(tmp, "n1")
    try:
        spec_n1 = PeerSpec(hostname="n1", ip="127.0.0.1", port=n1.port,
                           cert_pem=n1.pem, fingerprint=n1.fp)
        spec_n2 = PeerSpec(hostname="n2", ip="127.0.0.1", port=n2.port,
                           cert_pem=n2.pem, fingerprint=n2.fp)
        # n2 initially trusts NOBODY -> n1 could not handshake inbound yet.
        assert n2.mem.resolve_pin(n1.fp) is None
        # runtime ADD n1 on n2 -> MUST refresh n2's acceptor context to trust n1.
        n2.mem.add_peer(spec_n1)
        assert n2.mem.resolve_pin(n1.fp) == "n1"
        n1.mem.add_peer(spec_n2)  # n1<n2 -> n1 dials n2 INBOUND
        await n1.mem.start()
        await n2.mem.start()

        up = await _wait_until(lambda: n1.mem.reachable("n2"), timeout=8)
        assert up, "inbound link failed -> acceptor context was NOT refreshed on ADD"
    finally:
        await _teardown(n1, n2)


async def main():
    await test_add_remove_roster_pin()
    await test_tombstone_persist_reload()
    await test_voucher_budget_cap()
    await test_cidr_reject()
    await test_fingerprint_conflict()
    await test_failed_add_preserves_tombstone()
    await test_empty_peers_boot_error()
    await test_socket_linkup_and_revoke()
    await test_acceptor_context_refresh()
    print("MEMBERSHIP SELFTEST: PASS")


if __name__ == "__main__":
    asyncio.run(main())
