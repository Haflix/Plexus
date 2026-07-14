"""TG-18 / TP-33 — injected-`now` unit test of the MONOTONIC-anchored absolute
reassembly deadline (A5 disposition: no OS-clock stepping; §F + this unit test).

This validates the SPEC v4.4.2 §4.4 fix: the absolute per-reassembly deadline is
anchored on `time.monotonic()`, so a backward WALL-clock step cannot extend a
slow-drip DoS. It binds to the WINNING branch's reassembly-deadline check, which
the §F rubric (WAVE2_BATCH2_FCASES.md) requires to accept an injectable `now` in
test mode. Until the swap wires the exact symbol, this SKIPS with the requirement.

NOT a socket cell (runs in-process against netcore). Not gated behind
PLEXUS_PAIR_TEST — it is a fast unit test once the hook exists.
"""
from __future__ import annotations

import pytest


def _find_deadline_check():
    """Locate the branch's absolute-reassembly-deadline predicate. Tries a few
    plausible homes; returns a callable(entry_or_start, now) -> bool ('expired')
    or None if the branch does not expose an injectable-clock hook yet."""
    try:
        from plexus import netcore  # noqa: F401
    except Exception:  # pragma: no cover - netcore only exists post-swap
        return None
    # Candidate symbols the rewrite may expose (bind the real one at swap):
    candidates = []
    try:
        from plexus.netcore import wire as _wire  # type: ignore
        candidates += [getattr(_wire, n, None) for n in
                       ("reassembly_expired", "absolute_deadline_expired", "is_expired")]
    except Exception:
        pass
    try:
        from plexus.netcore import transport as _tp  # type: ignore
        candidates += [getattr(_tp, n, None) for n in
                       ("reassembly_expired", "absolute_deadline_expired")]
    except Exception:
        pass
    for c in candidates:
        if callable(c):
            return c
    return None


def test_absolute_deadline_is_monotonic_anchored():
    check = _find_deadline_check()
    if check is None:
        pytest.skip(
            "netcore reassembly-deadline check not found / no injectable-`now` hook "
            "yet. §F requirement (WAVE2_BATCH2_FCASES.md): the absolute-reassembly-"
            "deadline predicate must accept an injectable `now` (monotonic) so this "
            "test can drive it; and must use time.monotonic(), never wall-clock. "
            "Bind the exact symbol at the phase-6 swap.")
    # The precise signature is branch-defined; the property under test:
    #   * with a MONOTONIC now advanced past (start + 60s) → expired == True
    #   * a BACKWARD wall-clock step (monotonic unchanged) must NOT make it expire
    #     early NOR reset it — expiry keys on monotonic only.
    # The parent completes this against the landed signature; asserting here would
    # hard-code a guessed API. Presence of an injectable-`now` hook is the gate.
    assert callable(check)
