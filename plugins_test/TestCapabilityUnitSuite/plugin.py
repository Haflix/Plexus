"""TestCapabilityUnitSuite — pure-function unit tests for the capability decision.

Ported from the former root-level ``test_capability.py``. Self-contained:
imports ``evaluate_capability`` / ``CallerIdentity`` / ``parse_capabilities`` and
exercises them with synthetic identities. No Plexus boot, no event loop semantics
needed -- the framework gate (ContextVar reads, audit, raise) is integration-
tested by TestCapabilitySuite.

Categories: ``evaluate`` (the decision) and ``parse`` (config parsing).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.runtime import CallerIdentity, evaluate_capability  # noqa: E402
from plexus.helpers.config import parse_capabilities  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


def _I(name: str, uuid: str) -> CallerIdentity:
    return CallerIdentity(name, uuid)


def _ev(chain, author, author_id, grant=None, active=None):
    # real is always chain[-1].
    return evaluate_capability(chain[-1], chain, author, author_id, grant or {}, active)


class TestCapabilityUnitSuite(Plugin):
    """Pure-function unit suite for evaluate_capability + parse_capabilities."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestCapabilityUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestCapabilityUnitSuite disabled")

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
        rec = CaseRecorder("TestCapabilityUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        # evaluate.* cases
        await self._self_call(rec, kw)
        await self._system_granted(rec, kw)
        await self._system_denied(rec, kw)
        await self._impersonation_no_grant(rec, kw)
        await self._ancestor_real_uuid(rec, kw)
        await self._ancestor_not_in_chain(rec, kw)
        await self._caller_scope_immediate(rec, kw)
        await self._explicit_list(rec, kw)
        await self._no_chaining_same(rec, kw)
        await self._no_chaining_different(rec, kw)
        await self._unrecognised_scope(rec, kw)
        await self._caller_scope_no_parent(rec, kw)
        # parse.* cases
        await self._parse_false_grant_inert(rec, kw)
        await self._parse_rejects_malformed(rec, kw)

        return rec.to_dict()

    # ---------------- evaluate cases ----------------

    async def _self_call(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "P", "u1")
            assert v.allowed, "self allowed"
            assert v.is_assertion is False, "self not assertion"
            assert v.asserted is None, "self no asserted scope"

        await rec.run_case(
            "capability.self_call_not_assertion", body,
            tags=("capability", "self"), category="evaluate", **kw
        )

    async def _system_granted(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "system", "system", grant={"system_caller": True})
            assert v.allowed, "system granted allowed"
            assert v.author == "system" and v.author_id == "system", "system effective author"
            assert v.asserted is not None and v.asserted.name == "system", "system asserted set"
            assert v.is_assertion, "system is assertion"

        await rec.run_case(
            "capability.system_granted", body,
            tags=("capability", "system"), category="evaluate", **kw
        )

    async def _system_denied(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "system", "system", grant={})
            assert not v.allowed, "system denied without grant"
            assert "system_caller" in v.reason, "system deny reason mentions grant"

        await rec.run_case(
            "capability.system_denied_without_grant", body,
            tags=("capability", "system"), category="evaluate", **kw
        )

    async def _impersonation_no_grant(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "X", "ux", grant={})
            assert not v.allowed, "impersonation no grant denied"

        await rec.run_case(
            "capability.impersonation_no_grant_denied", body,
            tags=("capability", "impersonation"), category="evaluate", **kw
        )

    async def _ancestor_real_uuid(self, rec, kw):
        async def body(c):
            O = _I("Orchestrator", "uo")
            P = _I("P", "u1")
            # Caller passes a WRONG uuid for O; the gate must adopt the chain's real uuid.
            v = _ev((O, P), "Orchestrator", "wrong-uuid", grant={"impersonation": "ancestor"})
            assert v.allowed, "ancestor allowed"
            assert v.author_id == "uo", "ancestor normalises to real uuid"
            assert v.asserted == O, "ancestor asserted is the real frame"

        await rec.run_case(
            "capability.ancestor_in_chain_uses_real_uuid", body,
            tags=("capability", "impersonation", "ancestor"), category="evaluate", **kw
        )

    async def _ancestor_not_in_chain(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "Ghost", "ug", grant={"impersonation": "ancestor"})
            assert not v.allowed, "ancestor not in chain denied"

        await rec.run_case(
            "capability.ancestor_not_in_chain_denied", body,
            tags=("capability", "impersonation", "ancestor"), category="evaluate", **kw
        )

    async def _caller_scope_immediate(self, rec, kw):
        async def body(c):
            O = _I("O", "uo")       # grandparent
            M = _I("M", "um")       # immediate caller
            P = _I("P", "u1")       # real
            chain = (O, M, P)
            v_imm = _ev(chain, "M", "um", grant={"impersonation": "caller"})
            assert v_imm.allowed, "caller scope: immediate allowed"
            v_grand = _ev(chain, "O", "uo", grant={"impersonation": "caller"})
            assert not v_grand.allowed, "caller scope: grandparent denied"
            v_anc = _ev(chain, "O", "uo", grant={"impersonation": "ancestor"})
            assert v_anc.allowed, "ancestor scope: grandparent allowed"

        await rec.run_case(
            "capability.caller_scope_immediate_only", body,
            tags=("capability", "impersonation", "caller"), category="evaluate", **kw
        )

    async def _explicit_list(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v_ok = _ev((P,), "BillingService", "ub", grant={"impersonation": ["BillingService"]})
            assert v_ok.allowed, "explicit list: listed allowed"
            assert v_ok.author_id == "ub", "explicit list: caller-supplied uuid kept"
            v_no = _ev((P,), "Other", "uo", grant={"impersonation": ["BillingService"]})
            assert not v_no.allowed, "explicit list: unlisted denied"

        await rec.run_case(
            "capability.explicit_list", body,
            tags=("capability", "impersonation", "list"), category="evaluate", **kw
        )

    async def _no_chaining_same(self, rec, kw):
        async def body(c):
            O = _I("Orchestrator", "uo")
            P = _I("P", "u1")
            # Already asserting Orchestrator; asserting it again continues (allowed),
            # no new scope.
            v = _ev((O, P), "Orchestrator", "uo",
                    grant={"impersonation": "ancestor"}, active=O)
            assert v.allowed, "no-chaining: continue same allowed"
            assert v.asserted is None, "no-chaining: continue adds no new scope"

        await rec.run_case(
            "capability.no_chaining_same_continues", body,
            tags=("capability", "no-chaining"), category="evaluate", **kw
        )

    async def _no_chaining_different(self, rec, kw):
        async def body(c):
            O = _I("Orchestrator", "uo")
            P = _I("P", "u1")
            # P has a system_caller grant, but the chain is already asserting
            # Orchestrator -> a DIFFERENT assertion (system) is denied.
            v = _ev((O, P), "system", "system",
                    grant={"system_caller": True, "impersonation": "ancestor"}, active=O)
            assert not v.allowed, "no-chaining: different assertion denied despite grant"
            assert "no-chaining" in v.reason, "no-chaining: reason names no-chaining"

        await rec.run_case(
            "capability.no_chaining_different_denied", body,
            tags=("capability", "no-chaining"), category="evaluate", **kw
        )

    async def _unrecognised_scope(self, rec, kw):
        async def body(c):
            P = _I("P", "u1")
            v = _ev((P,), "X", "ux", grant={"impersonation": "banana"})
            assert not v.allowed, "unrecognised scope denied"

        await rec.run_case(
            "capability.unrecognised_scope_denied", body,
            tags=("capability", "impersonation"), category="evaluate", **kw
        )

    async def _caller_scope_no_parent(self, rec, kw):
        async def body(c):
            # Single-frame chain: real has no caller, ancestry is empty -> the
            # `candidates = () if not ancestry` guard must deny any caller-scope assert.
            P = _I("P", "u1")
            v = _ev((P,), "X", "ux", grant={"impersonation": "caller"})
            assert not v.allowed, "caller scope: empty ancestry denied"

        await rec.run_case(
            "capability.caller_scope_no_parent_denied", body,
            tags=("capability", "impersonation", "caller"), category="evaluate", **kw
        )

    # ---------------- parse cases ----------------

    async def _parse_false_grant_inert(self, rec, kw):
        async def body(c):
            # An entry that grants NOTHING must NOT be stored; an entry that
            # grants SOMETHING is stored as written (keys on "confers a
            # capability", not on any single field's value).
            assert parse_capabilities({"P": {"system_caller": False}}) == {}, \
                "system_caller false -> no grant"
            assert parse_capabilities({"P": {"system_caller": True}}) \
                == {"P": {"system_caller": True}}, "system_caller true -> stored"
            assert parse_capabilities({"P": {"impersonation_allowed": "ancestor"}}) \
                == {"P": {"impersonation": "ancestor"}}, "impersonation normalises key"
            assert parse_capabilities(
                {"P": {"system_caller": False, "impersonation_allowed": "caller"}}) \
                == {"P": {"system_caller": False, "impersonation": "caller"}}, \
                "false+impersonation still stored"

        await rec.run_case(
            "capability.parse_false_grant_inert", body,
            tags=("capability", "parse"), category="parse", **kw
        )

    async def _parse_rejects_malformed(self, rec, kw):
        async def body(c):
            def raises(fn):
                try:
                    fn()
                    return False
                except ValueError:
                    return True
            assert raises(lambda: parse_capabilities({"P": {"system_caller": "yes"}})), \
                "non-bool system_caller rejected"
            assert raises(lambda: parse_capabilities({"P": {"impersonation_allowed": 3}})), \
                "bad impersonation rejected"
            assert raises(lambda: parse_capabilities({"P": {"bogus": True}})), \
                "unknown key rejected"
            assert raises(lambda: parse_capabilities({"P": {"impersonation_allowed": []}})), \
                "empty list rejected"

        await rec.run_case(
            "capability.parse_rejects_malformed", body,
            tags=("capability", "parse"), category="parse", **kw
        )
