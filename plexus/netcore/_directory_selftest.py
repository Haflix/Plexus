"""Branch-local self-test for netcore.directory (Phase 4).

Throwaway dev aid — the PARENT runs it (implementers can't run python):

    python -m plexus.netcore._directory_selftest

Prints ``DIRECTORY SELFTEST: PASS``; exits non-zero (raises) on any failure.

Directory has no async / socket surface, so this is fully synchronous with an
injected fake registry-provider + fake Membership. Covers: content_hash
STABILITY (reorder nested args/authors/hosts/vouched + NFC/NFD-unicode desc ->
ZERO change; a REAL change -> bump); the export filter; route_* selection
(reachable INTERSECT roster INTERSECT topic-match, hostname-lex + declaration
order); replace apply-on-change / NOOP-on-same; drop_remote; build_pong; and the
PING-floor suppress.
"""

from __future__ import annotations

import os
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from plexus.netcore.directory import Directory  # noqa: E402
from plexus.netcore.types import (  # noqa: E402
    DirectorySnapshot,
    EndpointEntry,
    PeerSource,
    PeerSpec,
    RemoteSub,
)


# --- fakes ------------------------------------------------------------------
class FakeProvider:
    def __init__(self, endpoints=None, subs=None):
        self._endpoints = endpoints or []
        self._subs = subs or []

    def endpoints(self):
        return self._endpoints

    def subs(self):
        return self._subs


class FakeMembership:
    def __init__(self, reachable=(), roster=(), specs=None):
        self._reach = frozenset(reachable)
        self._roster_list = list(roster)
        self._specs = specs or {}

    @property
    def reachable_set(self):
        return self._reach

    def in_roster(self, h):
        return h in self._roster_list

    def roster_snapshot(self):
        return tuple(self._roster_list)

    def spec_for(self, h):
        return self._specs.get(h)


# --- record builders --------------------------------------------------------
def ep_record(name, plugin="plug", remote=True, enabled=True, owner_active=True,
              accessible=True, args=None, tags=None, desc="", uuid_="u", version="1"):
    return {
        "access_name": name, "plugin_name": plugin, "plugin_uuid": uuid_,
        "plugin_version": version, "description": desc,
        "arguments": args if args is not None else {}, "tags": tags or [],
        "remote": remote, "accessible_by_other_plugins": accessible,
        "enabled": enabled, "owner_active": owner_active,
    }


def sub_record(uuid_, pattern, plugin="plug", remote=True, enabled=True,
               owner_active=True, authors=None, hosts=None):
    return {
        "sub_uuid": uuid_, "topic_pattern": pattern, "authors": authors or [],
        "blocked_authors": [], "hosts": hosts or [], "blocked_hosts": [],
        "plugin_name": plugin, "remote": remote, "enabled": enabled,
        "owner_active": owner_active,
    }


def sub(uuid_, pattern, plugin="plug"):
    return RemoteSub(uuid_, pattern, [], [], [], [], plugin, True)


def ep(host, name, plugin, tags=None):
    return EndpointEntry(host, name, plugin, "u", "1", "", {}, tags or [], True, True)


def snap(host, ch, subs=None, endpoints=None):
    endpoints = endpoints or []
    tagged = {}
    for e in endpoints:
        for t in e.tags:
            tagged.setdefault(t, []).append(e)
    return DirectorySnapshot("epoch", ch, endpoints, tagged, subs or [], [])


def config_spec(tmp, hostname, ip="127.0.0.1", port=2510):
    from plexus.serialization import generate_keypair
    _c, _k, fp, pem = generate_keypair(os.path.join(tmp, hostname), hostname)
    return PeerSpec(hostname=hostname, ip=ip, port=port, cert_pem=pem,
                    fingerprint=fp, source=PeerSource.CONFIG)


# --- tests ------------------------------------------------------------------
def test_content_hash_stability():
    import tempfile
    tmp = tempfile.mkdtemp(prefix="dir_hash_")
    specs = {"cfg1": config_spec(tmp, "cfg1", port=1), "cfg2": config_spec(tmp, "cfg2", port=2)}
    mem = FakeMembership(roster=("cfg1", "cfg2"), specs=specs)
    prov = FakeProvider(
        endpoints=[ep_record("e1", args={"b": 1, "a": {"n": 2, "m": 1}},
                             tags=["y", "x"], desc="café")],  # NFC "café"
        subs=[sub_record("s1", "a/b", authors=["bob", "alice"], hosts=["h2", "h1"])],
    )
    d = Directory(prov, mem, self_hostname="me")
    h1 = d.build_pong("").content_hash

    # reorder EVERYTHING equivalently: arg keys (incl. nested), tags, authors,
    # hosts, the vouched/config-peer order, + NFD description -> ZERO change.
    prov._endpoints = [ep_record("e1", args={"a": {"m": 1, "n": 2}, "b": 1},
                                 tags=["x", "y"], desc="café")]  # NFD "café"
    prov._subs = [sub_record("s1", "a/b", authors=["alice", "bob"], hosts=["h1", "h2"])]
    mem._roster_list = ["cfg2", "cfg1"]  # reorder config peers (vouched order)
    h2 = d.build_pong("").content_hash
    assert h1 == h2, f"content_hash changed on an equivalent reorder: {h1} != {h2}"

    # a REAL change -> bump.
    prov._subs = [sub_record("s1", "a/DIFFERENT", authors=["alice"], hosts=[])]
    h3 = d.build_pong("").content_hash
    assert h3 != h1, "content_hash did not change on a real content change"


def test_content_hash_total_order():
    # Two SAME-named endpoints on DISTINCT plugins must not flip the hash on a
    # registry reorder. Ordering is by canonical CONTENT (here they differ by
    # plugin_name), NOT by the per-boot plugin_uuid (which is excluded, TP-30).
    mem = FakeMembership()
    e_a = ep_record("run", plugin="plugA", uuid_="ua")
    e_b = ep_record("run", plugin="plugB", uuid_="ub")
    d = Directory(FakeProvider(endpoints=[e_a, e_b]), mem, self_hostname="me")
    h1 = d.build_pong("").content_hash
    d._provider._endpoints = [e_b, e_a]  # reorder byte-identical content
    h2 = d.build_pong("").content_hash
    assert h1 == h2, "same-named endpoints reorder flipped the hash (not total-order)"


def test_content_hash_ignores_per_boot_identity():
    # TP-30 / §10: plugin_uuid + sub_uuid are per-boot uuid4 (IDENTITY, not content).
    # A same-content reboot regenerates them, so they MUST NOT feed the hash — else
    # every peer refetches + re-applies a byte-identical directory on each reboot.
    mem = FakeMembership()
    prov = FakeProvider(
        endpoints=[ep_record("e1", plugin="p", uuid_="boot-A-ep")],
        subs=[sub_record("boot-A-sub", "a/b")],
    )
    d = Directory(prov, mem, self_hostname="me")
    h1 = d.build_pong("").content_hash
    # "reboot": IDENTICAL content, only the per-boot uuids regenerate.
    prov._endpoints = [ep_record("e1", plugin="p", uuid_="boot-B-ep")]
    prov._subs = [sub_record("boot-B-sub", "a/b")]
    h2 = d.build_pong("").content_hash
    assert h1 == h2, f"content_hash changed on a same-content reboot (uuid leaked into hash): {h1} != {h2}"
    # a REAL content change (renamed endpoint) STILL bumps — the hash is not inert.
    prov._endpoints = [ep_record("e1-RENAMED", plugin="p", uuid_="boot-B-ep")]
    h3 = d.build_pong("").content_hash
    assert h3 != h1, "content_hash did not change on a real content change"
    # sub_uuid is still EXPORTED on the wire (§4.3), just not hashed.
    prov._subs = [sub_record("boot-C-sub", "a/b")]
    exported = d._export_snapshot()
    assert [x.sub_uuid for x in exported.subs] == ["boot-C-sub"], "sub_uuid dropped from the wire shape"


def test_export_filter():
    prov = FakeProvider(
        endpoints=[
            ep_record("good"),
            ep_record("notremote", remote=False),
            ep_record("notaccessible", accessible=False),
            ep_record("disabled", enabled=False),
            ep_record("owner_inactive", owner_active=False),
        ],
        subs=[
            sub_record("s_good", "a/b"),
            sub_record("s_notremote", "a/b", remote=False),
            sub_record("s_disabled", "a/b", enabled=False),
            sub_record("s_owner_inactive", "a/b", owner_active=False),
        ],
    )
    d = Directory(prov, FakeMembership(), self_hostname="me")
    s = d._export_snapshot()
    assert [e.access_name for e in s.endpoints] == ["good"], [e.access_name for e in s.endpoints]
    assert [x.sub_uuid for x in s.subs] == ["s_good"], [x.sub_uuid for x in s.subs]


def test_route_selection():
    mem = FakeMembership(
        reachable=("a", "b", "d", "u"),   # u reachable but NOT in roster
        roster=("a", "b", "d", "e"),      # e in roster but NOT reachable
    )
    d = Directory(FakeProvider(), mem, self_hostname="me")
    # insert out of lex order to prove sorting.
    d.replace("d", snap("d", "hd",
                        subs=[sub("sd1", "t/one")],
                        endpoints=[ep("d", "run", "plugX", tags=["ai_tool"])]))
    d.replace("b", snap("b", "hb",
                        subs=[sub("sb1", "t/one"), sub("sb2", "t/*")],  # decl order
                        endpoints=[ep("b", "run", "plugX")]))
    d.replace("a", snap("a", "ha",
                        subs=[sub("sa1", "t/two")],
                        endpoints=[ep("a", "run", "plugX", tags=["ai_tool"])]))
    # a non-reachable / non-roster peer's snapshot must NOT route.
    d.replace("e", snap("e", "he", subs=[sub("se1", "t/one")]))  # e: roster but unreachable
    # "u" is reachable but not in roster -> replace is roster-gated so it won't
    # even store; assert have_hash stays empty.
    d.replace("u", snap("u", "hu", subs=[sub("su1", "t/one")]))
    assert d.have_hash("u") == "", "roster-gate let a non-roster snapshot in"

    # route_request("t/one"): b(sb1) + d(sd1) match; hostname-lex order b<d; a's
    # sa1 is "t/two" (no match); b's sb2 "t/*" ALSO matches -> declaration order.
    got = list(d.route_request("t/one"))
    assert [(h, s.sub_uuid) for h, s in got] == [("b", "sb1"), ("b", "sb2"), ("d", "sd1")], got

    # e (unreachable) excluded.
    assert all(h != "e" for h, _ in got), "unreachable peer routed"

    # route_execute(plugX, run): all three reachable+roster peers, lex order.
    ex = [(h, e.access_name) for h, e in d.route_execute("plugX", "run")]
    assert ex == [("a", "run"), ("b", "run"), ("d", "run")], ex

    # route_publish("t/one"): grouped per peer with >=1 match.
    pub = [(h, [s.sub_uuid for s in subs]) for h, subs in d.route_publish("t/one")]
    assert pub == [("b", ["sb1", "sb2"]), ("d", ["sd1"])], pub

    # route_tagged("ai_tool"): REMOTE only, lex order (a, d have it; b doesn't).
    tg = [(h, e.access_name) for h, e in d.route_tagged("ai_tool")]
    assert tg == [("a", "run"), ("d", "run")], tg

    # reachable()
    assert d.reachable("a") and d.reachable("b") and d.reachable("d")
    assert not d.reachable("e")  # unreachable
    assert not d.reachable("u")  # not in roster


def test_replace_and_drop():
    events = []
    mem = FakeMembership(reachable=("a",), roster=("a",))
    d = Directory(FakeProvider(), mem, self_hostname="me",
                  observe=lambda e, p: events.append((e, p)))
    d.replace("a", snap("a", "h1", subs=[sub("s1", "t/x")]))
    assert d.have_hash("a") == "h1"
    n_after_first = sum(1 for e, _ in events if e == "_core/directory/replaced")
    assert n_after_first == 1

    d.replace("a", snap("a", "h1", subs=[sub("s1", "t/x")]))  # SAME hash -> NOOP
    assert sum(1 for e, _ in events if e == "_core/directory/replaced") == 1, "NOOP fired an event"

    d.replace("a", snap("a", "h2", subs=[sub("s1", "t/y")]))  # changed -> apply
    assert d.have_hash("a") == "h2"
    assert sum(1 for e, _ in events if e == "_core/directory/replaced") == 2

    d.drop_remote("a")
    assert d.have_hash("a") == ""
    assert list(d.route_request("t/y")) == []


def test_build_pong():
    prov = FakeProvider(endpoints=[ep_record("e1")], subs=[sub_record("s1", "a/b")])
    d = Directory(prov, FakeMembership(), self_hostname="me")
    ch = d._export_snapshot().content_hash

    p_match = d.build_pong(ch)
    assert p_match.snapshot_follows is False and p_match.snapshot is None, p_match

    p_miss = d.build_pong("something-else")
    assert p_miss.snapshot_follows is True
    assert isinstance(p_miss.snapshot, DirectorySnapshot)
    assert p_miss.snapshot.content_hash == ch
    assert p_miss.epoch == d._epoch  # epoch off the apply path (identity only)


def test_ping_floor_suppress():
    d = Directory(FakeProvider(), FakeMembership(), self_hostname="me", ping_floor=0.3)
    p1 = d.serve_ping("peer", "")
    assert p1 is not None, "at-interval PING was not answered"
    p2 = d.serve_ping("peer", "")  # immediate -> below floor
    assert p2 is None, "below-floor PING was not suppressed"
    p3 = d.serve_ping("peer", "")
    assert p3 is None, "flood PING was not suppressed"
    # a DIFFERENT peer has its own window.
    assert d.serve_ping("peer2", "") is not None
    time.sleep(0.35)  # window elapsed
    assert d.serve_ping("peer", "") is not None, "PING not answered after the floor elapsed"


def main():
    test_content_hash_stability()
    test_content_hash_total_order()
    test_content_hash_ignores_per_boot_identity()
    test_export_filter()
    test_route_selection()
    test_replace_and_drop()
    test_build_pong()
    test_ping_floor_suppress()
    print("DIRECTORY SELFTEST: PASS")


if __name__ == "__main__":
    main()
