"""Capability-gate integration suite.

Drives the gate END-TO-END through real ``execute()`` dispatches (the pure
decision logic is exhaustively covered by test_capability.py; this proves the
WIRING: that the gate is actually called at execute, reads the real caller
chain, raises CapabilityException, scopes the assertion, and is inert when off).

Grants are injected programmatically into the live Plexus; config-loaded grants
are covered by the parse_capabilities unit path.

Cases:
- inert-off: no grant -> an asserting call passes through ungated.
- system deny / allow (system_caller grant).
- impersonation without grant -> deny.
- ancestor scope allow (via a relay that puts the asserted plugin in the chain).
- no-chaining deny (proves the asserted-identity scope propagates).
- self-call passthrough while the gate is active.
- sync gated: execute_sync assertion now denied loop-side (dispatch-unify
  cleanup extended the gate to the sync path).
- stream async/sync gated: execute_stream / execute_stream_sync assertions
  denied through the shared _create_gen_request_gated body (stream cleanup).
- stream async lazy: execute_stream is a lazy async generator -- creation does
  not gate, only iteration does.

``TestCapabilityActor`` is loaded twice by the test config -- once as ACTOR,
once as ACTOR2 -- to provide two distinct identities and an ancestry chain.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.2.0"
ACTOR = "TestCapabilityActor"
ACTOR2 = "TestCapabilityActor2"


class TestCapabilitySuite(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    def _set_grants(self, grants: Dict[str, dict]) -> None:
        self._plexus._capability_grants = grants
        self._plexus._recompute_capability_active()

    async def _drive_assert(self, actor, target, method, author, author_id):
        """Run an asserting do_assert call; return (outcome, detail) where the
        actor reports its own gate result as a marker dict."""
        marker = await self.execute(
            actor, "do_assert",
            args={"target": target, "method": method,
                  "author": author, "author_id": author_id},
        )
        return marker["outcome"], marker.get("result") or marker.get("reason")

    @async_log_errors
    async def run(
        self,
        category: Optional[str] = None,
        host: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        bug_ids: Optional[List[str]] = None,
        skip_slow: bool = False,
        allow_destructive: bool = True,
    ) -> Dict[str, Any]:
        rec = CaseRecorder("TestCapabilitySuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids, bug_ids_filter=bug_ids,
            category_filter=category, host_filter=host,
            skip_slow=skip_slow, allow_destructive=allow_destructive,
            remote_available=False,
        )

        orig_grants = self._plexus._capability_grants
        orig_cap = self._plexus._capability_active
        orig_id = self._plexus._identity_active
        try:
            await self._case_inert_off(rec, kw)
            await self._case_system_deny(rec, kw)
            await self._case_system_allow(rec, kw)
            await self._case_impersonation_no_grant(rec, kw)
            await self._case_ancestor_allow(rec, kw)
            await self._case_no_chaining_deny(rec, kw)
            await self._case_self_call_passthrough(rec, kw)
            await self._case_sync_gated(rec, kw)
            await self._case_stream_async_gated(rec, kw)
            await self._case_stream_sync_gated(rec, kw)
            await self._case_stream_async_lazy(rec, kw)
            await self._case_audit_dedup(rec, kw)
        finally:
            self._plexus._capability_grants = orig_grants
            self._plexus._capability_active = orig_cap
            self._plexus._identity_active = orig_id
            self._plexus._identity_audit_log.clear()

        return rec.to_dict()

    async def _case_inert_off(self, rec, kw):
        async def body(c):
            self._set_grants({})  # capability inactive
            # Spoof the author NAME but keep a valid author_id so the dispatch
            # itself resolves -- the point is that with no grant the gate never
            # fires, so a mismatched author is simply a label (historical
            # behaviour), not a denial.
            actor_uuid = self._plexus.plugins[ACTOR].plugin_uuid
            outcome, res = await self._drive_assert(
                ACTOR, ACTOR, "echo", "GhostIdentity", actor_uuid
            )
            if outcome != "ok" or res != "echo":
                raise AssertionError(
                    f"inert-off: assertion should pass ungated, got {outcome}/{res!r}"
                )
        await rec.run_case("capability.inert_off", body, **kw)

    async def _case_system_deny(self, rec, kw):
        async def body(c):
            # Gate active (Actor has only impersonation), Actor lacks system_caller.
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            outcome, reason = await self._drive_assert(
                ACTOR, ACTOR, "echo", "system", "system"
            )
            if outcome != "denied":
                raise AssertionError(f"system without grant must deny, got {outcome}")
            if "system_caller" not in reason:
                raise AssertionError(f"deny reason should name system_caller: {reason!r}")
        await rec.run_case("capability.system.deny", body, **kw)

    async def _case_system_allow(self, rec, kw):
        async def body(c):
            self._set_grants({ACTOR: {"system_caller": True}})
            outcome, res = await self._drive_assert(
                ACTOR, ACTOR, "echo", "system", "system"
            )
            if outcome != "ok" or res != "echo":
                raise AssertionError(f"system with grant must allow, got {outcome}/{res!r}")
        await rec.run_case("capability.system.allow", body, **kw)

    async def _case_impersonation_no_grant(self, rec, kw):
        async def body(c):
            self._set_grants({"SomeOtherPlugin": {"system_caller": True}})  # active, not Actor
            outcome, reason = await self._drive_assert(
                ACTOR, ACTOR, "echo", "Victim", "victim-uuid"
            )
            if outcome != "denied":
                raise AssertionError(f"impersonation without grant must deny, got {outcome}")
        await rec.run_case("capability.impersonation.no_grant_deny", body, **kw)

    async def _case_ancestor_allow(self, rec, kw):
        async def body(c):
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            actor2_uuid = self._plexus.plugins[ACTOR2].plugin_uuid
            # Actor2 -> relay -> Actor.do_assert(assert Actor2). Inside Actor the
            # chain is (Actor2, Actor); Actor impersonates its ancestor Actor2.
            spec = {
                "plugin": ACTOR,
                "method": "do_assert",
                "args": {"target": ACTOR, "method": "echo",
                         "author": ACTOR2, "author_id": actor2_uuid},
            }
            marker = await self.execute(ACTOR2, "relay", args={"spec": spec})
            if not isinstance(marker, dict) or marker.get("outcome") != "ok" \
                    or marker.get("result") != "echo":
                raise AssertionError(
                    f"ancestor impersonation should allow + echo, got {marker!r}"
                )
        await rec.run_case("capability.impersonation.ancestor_allow", body, **kw)

    async def _case_no_chaining_deny(self, rec, kw):
        async def body(c):
            # ACTOR holds BOTH grants -> a bare system assertion WOULD be
            # allowed. We first establish an ACTOR2 impersonation (ancestor),
            # then the impersonated target (try_reassert) attempts a DIFFERENT
            # assertion (system). It must be denied by NO-CHAINING, not by a
            # missing grant -- proving _asserted_identity propagated through the
            # real dispatch into the nested gate.
            self._set_grants(
                {ACTOR: {"system_caller": True, "impersonation": "ancestor"}}
            )
            actor2_uuid = self._plexus.plugins[ACTOR2].plugin_uuid
            spec = {
                "plugin": ACTOR, "method": "do_assert",
                "args": {"target": ACTOR, "method": "try_reassert",
                         "author": ACTOR2, "author_id": actor2_uuid},
            }
            outer = await self.execute(ACTOR2, "relay", args={"spec": spec})
            inner = outer.get("result") if isinstance(outer, dict) else None
            if not isinstance(inner, dict) or inner.get("outcome") != "denied":
                raise AssertionError(
                    f"no-chaining must deny the inner reassert, got {outer!r}"
                )
            if "no-chaining" not in (inner.get("reason") or ""):
                raise AssertionError(
                    f"deny reason should be no-chaining, got {inner!r}"
                )
        await rec.run_case("capability.no_chaining.deny", body, **kw)

    async def _case_self_call_passthrough(self, rec, kw):
        async def body(c):
            # Gate ACTIVE; an explicit claim of the actor's OWN identity must hit
            # the self-call branch and pass (not treated as an assertion).
            self._set_grants({ACTOR: {"system_caller": True}})
            actor_uuid = self._plexus.plugins[ACTOR].plugin_uuid
            outcome, res = await self._drive_assert(
                ACTOR, ACTOR, "echo", ACTOR, actor_uuid
            )
            if outcome != "ok" or res != "echo":
                raise AssertionError(
                    f"explicit self-claim should pass under active gate, "
                    f"got {outcome}/{res!r}"
                )
        await rec.run_case("capability.self_call.passthrough", body, **kw)

    async def _case_sync_gated(self, rec, kw):
        async def body(c):
            # The dispatch-unify cleanup folded execute() + execute_sync into one
            # loop-side _dispatch_request, so execute_sync is now gated too. Gate
            # active (Actor has impersonation only, NO system_caller); a SYNC-path
            # assertion of "system" must now be DENIED loop-side, the
            # CapabilityException crossing the sync bridge back to the asserting
            # sync handler (do_assert_sync). Before the cleanup execute_sync
            # rewrote author worker-side and this passed through ungated.
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            marker = await self.execute(
                ACTOR, "do_assert_sync",
                args={"target": ACTOR, "method": "echo",
                      "author": "system", "author_id": "system"},
            )
            outcome = marker["outcome"]
            reason = marker.get("reason") or ""
            if outcome != "denied":
                raise AssertionError(
                    f"execute_sync system assertion must now deny, got {outcome}"
                )
            if "system_caller" not in reason:
                raise AssertionError(
                    f"sync deny reason should name system_caller: {reason!r}"
                )
        await rec.run_case("capability.sync.gated", body, **kw)

    async def _case_stream_async_gated(self, rec, kw):
        async def body(c):
            # execute_stream gated through the shared _create_gen_request_gated
            # body. Gate active (Actor has impersonation only, NO system_caller);
            # an async-stream assertion of "system" must be DENIED on iteration.
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            marker = await self.execute(
                ACTOR, "do_assert_stream",
                args={"target": ACTOR, "method": "echo",
                      "author": "system", "author_id": "system"},
            )
            if marker.get("outcome") != "denied":
                raise AssertionError(
                    f"execute_stream system assertion must deny, got {marker!r}"
                )
            if "system_caller" not in (marker.get("reason") or ""):
                raise AssertionError(
                    f"async-stream deny reason should name system_caller: {marker!r}"
                )
        await rec.run_case("capability.stream_async.gated", body, **kw)

    async def _case_stream_sync_gated(self, rec, kw):
        async def body(c):
            # execute_stream_sync gated: the gate runs in the bridged construction
            # loop-side (_create_gen_request_gated), and the CapabilityException
            # crosses the sync bridge back to the asserting sync handler.
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            marker = await self.execute(
                ACTOR, "do_assert_stream_sync",
                args={"target": ACTOR, "method": "echo",
                      "author": "system", "author_id": "system"},
            )
            if marker.get("outcome") != "denied":
                raise AssertionError(
                    f"execute_stream_sync system assertion must deny, got {marker!r}"
                )
            if "system_caller" not in (marker.get("reason") or ""):
                raise AssertionError(
                    f"sync-stream deny reason should name system_caller: {marker!r}"
                )
        await rec.run_case("capability.stream_sync.gated", body, **kw)

    async def _case_stream_async_lazy(self, rec, kw):
        async def body(c):
            # execute_stream is a LAZY async generator: merely creating it must
            # NOT gate; only iterating triggers the denial. The fixture returns a
            # marker proving construction succeeded (created) and the denial
            # happened on iteration (denied_on_iter). Guards against a future
            # eager-eval regression that the iterating gated cases would hide.
            self._set_grants({ACTOR: {"impersonation": "ancestor"}})
            marker = await self.execute(
                ACTOR, "do_assert_stream_lazy",
                args={"target": ACTOR, "method": "echo",
                      "author": "system", "author_id": "system"},
            )
            if not (isinstance(marker, dict)
                    and marker.get("created") is True
                    and marker.get("denied_on_iter") is True):
                raise AssertionError(
                    f"execute_stream must be lazy (create-no-gate, deny-on-iter); "
                    f"got {marker!r}"
                )
        await rec.run_case("capability.stream_async.lazy", body, **kw)

    async def _case_audit_dedup(self, rec, kw):
        async def body(c):
            # The capability gate emits a `_core/security/identity_asserted` bus
            # event per assertion/deny; window-suppression collapses a repeated
            # identical assertion to ONE event + a count (Section 13, the audit
            # half of the Step-5 reject suppression). ACTOR may act as system, so
            # the SAME (ACTOR -> "system", allowed) assertion repeated in-window
            # must emit once; the next emit after the window carries the count.
            from plexus.core import IDENTITY_AUDIT_WINDOW
            px = self._plexus
            events: List[dict] = []

            def _obs(topic, payload):
                events.append(dict(payload))

            self.internal_observe("_core/security/identity_asserted", _obs)
            px._identity_audit_log.clear()
            try:
                self._set_grants({ACTOR: {"system_caller": True}})
                N = 4
                for _ in range(N):
                    outcome, res = await self._drive_assert(
                        ACTOR, ACTOR, "echo", "system", "system"
                    )
                    if outcome != "ok":
                        raise AssertionError(
                            f"system_caller assertion should allow; got {outcome}/{res!r}"
                        )
                # First assertion emits; the other N-1 are suppressed in-window.
                if len(events) != 1:
                    raise AssertionError(
                        f"in-window: exactly 1 audit event expected for {N} identical "
                        f"assertions; got {len(events)}: {events}"
                    )
                e0 = events[0]
                if e0.get("suppressed") != 0:
                    raise AssertionError(f"first emit must carry suppressed=0; got {e0!r}")
                if e0.get("denied") is not False or e0.get("asserted") != "system":
                    raise AssertionError(f"audit payload wrong on first emit: {e0!r}")
                # Side-table accumulated the N-1 suppressed; key is name-based.
                key = (px.plugins[ACTOR].plugin_uuid, "system", False)
                st = px._identity_audit_log.get(key)
                if st is None or st["suppressed"] != N - 1:
                    raise AssertionError(
                        f"side-table must hold {N - 1} suppressed for {key}; got {st!r}"
                    )
                # Force the window elapsed, drive one more -> a 2nd emit that
                # CARRIES the suppressed count (no security event's volume lost).
                st["last_emit"] -= (IDENTITY_AUDIT_WINDOW + 1.0)
                outcome, _ = await self._drive_assert(
                    ACTOR, ACTOR, "echo", "system", "system"
                )
                if outcome != "ok":
                    raise AssertionError(f"post-window assertion should allow; got {outcome}")
                if len(events) != 2:
                    raise AssertionError(
                        f"post-window: a 2nd audit event expected; got {len(events)}"
                    )
                if events[1].get("suppressed") != N - 1:
                    raise AssertionError(
                        f"2nd emit must report {N - 1} suppressed; got {events[1]!r}"
                    )
            finally:
                self.internal_unobserve("_core/security/identity_asserted", _obs)
                px._identity_audit_log.clear()
        await rec.run_case("capability.audit_dedup", body, **kw)
