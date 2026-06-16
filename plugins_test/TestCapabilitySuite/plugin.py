"""TestCapabilitySuite — rate-limiter Step 2b capability-gate integration.

Drives the gate END-TO-END through real ``execute()`` dispatches (the pure
decision logic is exhaustively covered by test_capability.py; this proves the
WIRING: that the gate is actually called at execute, reads the real caller
chain, raises CapabilityException, scopes the assertion, and is inert when off).

Grants are injected programmatically (like Step 2a forced _identity_active);
config-loaded grants are covered by the parse_capabilities unit path.

Cases:
- inert-off: no grant -> an asserting call passes through ungated.
- system deny / allow (system_caller grant).
- impersonation without grant -> deny.
- ancestor scope allow (via a relay that puts the asserted plugin in the chain).
- self-call passthrough while the gate is active.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"
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
            await self._case_sync_stream_ungated_stub(rec, kw)
        finally:
            self._plexus._capability_grants = orig_grants
            self._plexus._capability_active = orig_cap
            self._plexus._identity_active = orig_id

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

    async def _case_sync_stream_ungated_stub(self, rec, kw):
        async def body(c):
            # Step 2b known gap: execute_sync / execute_stream assertions are NOT
            # gated yet (they rewrite author worker-side / iterate as generators;
            # the gate lands when the deferred _dispatch_request cleanup relocates
            # those bodies loop-side -- see ratelimiter_design.md). This skip is
            # the anchor to FLIP to an expect-denied case once that lands.
            c.skip(
                "execute_sync/execute_stream gating deferred to the "
                "_dispatch_request cleanup; flip to expect-denied then"
            )
        await rec.run_case("capability.sync_stream.ungated_until_cleanup", body, **kw)
