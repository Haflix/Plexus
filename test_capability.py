"""Unit tests for the pure capability decision (rate-limiter Step 2b).

Exercises ``evaluate_capability`` in isolation: self-calls, system_caller,
the three impersonation scopes (caller / ancestor / explicit list), default-
deny, and the no-chaining rule. No Plexus, no event loop -- the framework gate
(ContextVar reads, audit, raise) is integration-tested by TestCapabilitySuite.

Standalone: ``python test_capability.py`` (exit 0 = pass).
"""
import sys

from plexus.runtime import CallerIdentity, evaluate_capability
from plexus.helpers.config import parse_capabilities

_failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        _failures.append(name)


def I(name, uuid):
    return CallerIdentity(name, uuid)


# real is always chain[-1].
def ev(chain, author, author_id, grant=None, active=None):
    return evaluate_capability(chain[-1], chain, author, author_id, grant or {}, active)


def test_self_call_not_assertion():
    P = I("P", "u1")
    v = ev((P,), "P", "u1")
    check("self allowed", v.allowed)
    check("self not assertion", v.is_assertion is False)
    check("self no asserted scope", v.asserted is None)


def test_system_granted():
    P = I("P", "u1")
    v = ev((P,), "system", "system", grant={"system_caller": True})
    check("system granted allowed", v.allowed)
    check("system effective author", v.author == "system" and v.author_id == "system")
    check("system asserted set", v.asserted is not None and v.asserted.name == "system")
    check("system is assertion", v.is_assertion)


def test_system_denied_without_grant():
    P = I("P", "u1")
    v = ev((P,), "system", "system", grant={})
    check("system denied without grant", not v.allowed)
    check("system deny reason mentions grant", "system_caller" in v.reason)


def test_impersonation_no_grant_denied():
    P = I("P", "u1")
    v = ev((P,), "X", "ux", grant={})
    check("impersonation no grant denied", not v.allowed)


def test_ancestor_in_chain_allowed_uses_real_uuid():
    O = I("Orchestrator", "uo")
    P = I("P", "u1")
    # Caller passes a WRONG uuid for O; the gate must adopt the chain's real uuid.
    v = ev((O, P), "Orchestrator", "wrong-uuid", grant={"impersonation": "ancestor"})
    check("ancestor allowed", v.allowed)
    check("ancestor normalises to real uuid", v.author_id == "uo")
    check("ancestor asserted is the real frame", v.asserted == O)


def test_ancestor_not_in_chain_denied():
    P = I("P", "u1")
    v = ev((P,), "Ghost", "ug", grant={"impersonation": "ancestor"})
    check("ancestor not in chain denied", not v.allowed)


def test_caller_scope_immediate_only():
    O = I("O", "uo")       # grandparent
    M = I("M", "um")       # immediate caller
    P = I("P", "u1")       # real
    chain = (O, M, P)
    v_imm = ev(chain, "M", "um", grant={"impersonation": "caller"})
    check("caller scope: immediate allowed", v_imm.allowed)
    v_grand = ev(chain, "O", "uo", grant={"impersonation": "caller"})
    check("caller scope: grandparent denied", not v_grand.allowed)
    # ancestor scope allows the grandparent
    v_anc = ev(chain, "O", "uo", grant={"impersonation": "ancestor"})
    check("ancestor scope: grandparent allowed", v_anc.allowed)


def test_explicit_list():
    P = I("P", "u1")
    v_ok = ev((P,), "BillingService", "ub", grant={"impersonation": ["BillingService"]})
    check("explicit list: listed allowed", v_ok.allowed)
    check("explicit list: caller-supplied uuid kept", v_ok.author_id == "ub")
    v_no = ev((P,), "Other", "uo", grant={"impersonation": ["BillingService"]})
    check("explicit list: unlisted denied", not v_no.allowed)


def test_no_chaining_same_continues():
    O = I("Orchestrator", "uo")
    P = I("P", "u1")
    # Already asserting Orchestrator; asserting it again continues (allowed),
    # no new scope.
    v = ev((O, P), "Orchestrator", "uo",
           grant={"impersonation": "ancestor"}, active=O)
    check("no-chaining: continue same allowed", v.allowed)
    check("no-chaining: continue adds no new scope", v.asserted is None)


def test_no_chaining_different_denied_even_with_grant():
    O = I("Orchestrator", "uo")
    P = I("P", "u1")
    # P has a system_caller grant, but the chain is already asserting
    # Orchestrator -> a DIFFERENT assertion (system) is denied (no-chaining
    # short-circuits the grant).
    v = ev((O, P), "system", "system",
           grant={"system_caller": True, "impersonation": "ancestor"}, active=O)
    check("no-chaining: different assertion denied despite grant", not v.allowed)
    check("no-chaining: reason names no-chaining", "no-chaining" in v.reason)


def test_unrecognised_scope_denied():
    P = I("P", "u1")
    v = ev((P,), "X", "ux", grant={"impersonation": "banana"})
    check("unrecognised scope denied", not v.allowed)


def test_caller_scope_no_parent_denied():
    # Single-frame chain: real has no caller, ancestry is empty -> the
    # `candidates = () if not ancestry` guard must deny any caller-scope assert.
    P = I("P", "u1")
    v = ev((P,), "X", "ux", grant={"impersonation": "caller"})
    check("caller scope: empty ancestry denied", not v.allowed)


def test_parse_false_grant_is_inert():
    # A `{system_caller: false}` (or empty) entry grants nothing and must NOT
    # be stored -- else it would flip the gate on node-wide (review finding).
    check("parse: system_caller false -> no grant",
          parse_capabilities({"P": {"system_caller": False}}) == {})
    check("parse: system_caller true -> stored",
          parse_capabilities({"P": {"system_caller": True}})
          == {"P": {"system_caller": True}})
    check("parse: impersonation normalises key",
          parse_capabilities({"P": {"impersonation_allowed": "ancestor"}})
          == {"P": {"impersonation": "ancestor"}})
    check("parse: false+impersonation still stored",
          parse_capabilities(
              {"P": {"system_caller": False, "impersonation_allowed": "caller"}})
          == {"P": {"system_caller": False, "impersonation": "caller"}})


def test_parse_rejects_malformed():
    def raises(fn):
        try:
            fn()
            return False
        except ValueError:
            return True
    check("parse: non-bool system_caller rejected",
          raises(lambda: parse_capabilities({"P": {"system_caller": "yes"}})))
    check("parse: bad impersonation rejected",
          raises(lambda: parse_capabilities({"P": {"impersonation_allowed": 3}})))
    check("parse: unknown key rejected",
          raises(lambda: parse_capabilities({"P": {"bogus": True}})))
    check("parse: empty list rejected",
          raises(lambda: parse_capabilities({"P": {"impersonation_allowed": []}})))


def main():
    tests = [
        test_self_call_not_assertion,
        test_system_granted,
        test_system_denied_without_grant,
        test_impersonation_no_grant_denied,
        test_ancestor_in_chain_allowed_uses_real_uuid,
        test_ancestor_not_in_chain_denied,
        test_caller_scope_immediate_only,
        test_explicit_list,
        test_no_chaining_same_continues,
        test_no_chaining_different_denied_even_with_grant,
        test_unrecognised_scope_denied,
        test_caller_scope_no_parent_denied,
        test_parse_false_grant_is_inert,
        test_parse_rejects_malformed,
    ]
    for t in tests:
        print(t.__name__)
        t()
    print()
    if _failures:
        print(f"FAILED: {len(_failures)} -> {_failures}")
        sys.exit(1)
    print("ALL PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
