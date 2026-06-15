"""Unit tests for plexus.ratelimiter (Step 1: pure Bucket + RateLimiter).

Standalone + deterministic: every test injects ``now`` so there are no sleeps
and no wall-clock flakiness. Run with: python test_ratelimiter.py
Exit code 0 = all pass.
"""
from plexus.ratelimiter import Bucket, RateLimiter
from plexus.exceptions import ConfigException

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' -- ' + detail) if detail else ''}")


def raises_config(fn):
    try:
        fn()
        return False
    except ConfigException:
        return True


# ── refill math ────────────────────────────────────────────────────────
def test_refill():
    b = Bucket(max_tokens=10, window=1, now=0.0)   # rate = 10 tokens/s
    check("refill: starts full", b.tokens == 10.0)
    b.tokens = 0.0
    b.refill(now=0.5)                               # 0.5s * 10/s = 5
    check("refill: lazy continuous", b.tokens == 5.0, f"tokens={b.tokens}")
    b.refill(now=100.0)                             # would be huge -> clamp to max
    check("refill: clamps at max", b.tokens == 10.0, f"tokens={b.tokens}")
    # fractional window/rate
    b2 = Bucket(max_tokens=1, window=60, now=0.0)   # 1 per 60s -> rate 1/60
    b2.tokens = 0.0
    b2.refill(now=30.0)
    check("refill: fractional rate (1/60 over 30s = 0.5)",
          abs(b2.tokens - 0.5) < 1e-9, f"tokens={b2.tokens}")


# ── admit: commit-all, reject-no-leak, boundary, order ─────────────────
def test_admit_commit_all():
    rl = RateLimiter()
    b1 = Bucket(5, 1, 0.0); b2 = Bucket(5, 1, 0.0)
    res = rl.admit([b1, b2], cost=1.0, now=0.0)
    check("admit: all-pass returns None", res is None)
    check("admit: both committed -cost", b1.tokens == 4.0 and b2.tokens == 4.0)
    check("admit: both charged++", b1.charged == 1 and b2.charged == 1)


def test_admit_reject_no_leak():
    rl = RateLimiter()
    full = Bucket(5, 1, 0.0)
    dry = Bucket(5, 1, 0.0); dry.tokens = 0.0
    res = rl.admit([full, dry], cost=1.0, now=0.0)
    check("admit: returns the dry bucket", res is dry)
    check("admit: NO leak -- earlier bucket untouched", full.tokens == 5.0,
          f"full.tokens={full.tokens}")
    check("admit: earlier bucket not charged", full.charged == 0)
    check("admit: dry bucket rejected++ (and not charged)",
          dry.rejected == 1 and dry.charged == 0)


def test_admit_boundary():
    # tokens == cost exactly must ADMIT (tokens < cost is False)
    b = Bucket(5, 1, 0.0); b.tokens = 1.0
    res = RateLimiter().admit([b], cost=1.0, now=0.0)
    check("admit: tokens == cost admits (boundary)",
          res is None and b.tokens == 0.0, f"tokens={b.tokens}")
    # now empty, cost 1 -> reject
    res2 = RateLimiter().admit([b], cost=1.0, now=0.0)
    check("admit: empty then cost=1 rejects", res2 is b)


def test_admit_deterministic_order():
    a = Bucket(5, 1, 0.0)
    d1 = Bucket(5, 1, 0.0); d1.tokens = 0.0
    d2 = Bucket(5, 1, 0.0); d2.tokens = 0.0
    res = RateLimiter().admit([a, d1, d2], cost=1.0, now=0.0)
    check("admit: returns FIRST dry in iteration order", res is d1)
    check("admit: only the first dry is counted rejected",
          d1.rejected == 1 and d2.rejected == 0)


def test_admit_empty():
    check("admit: empty charge-set admits", RateLimiter().admit([], 1.0, 0.0) is None)


# ── fractional cost (stream weight feeds cost) ─────────────────────────
def test_fractional_cost():
    b = Bucket(5, 1, 0.0); b.tokens = 3.0
    res = RateLimiter().admit([b], cost=2.5, now=0.0)
    check("admit: fractional cost commits", res is None and abs(b.tokens - 0.5) < 1e-9)
    res2 = RateLimiter().admit([b], cost=2.5, now=0.0)
    check("admit: fractional cost rejects when short", res2 is b)


# ── reconfigure: clamp-on-shrink, rate change, stream-weight guard ─────
def test_reconfigure():
    b = Bucket(10, 1, 0.0); b.tokens = 8.0
    b.reconfigure(max_tokens=5, window=1)          # shrink max 10 -> 5
    check("reconfigure: clamps tokens down on shrink", b.tokens == 5.0,
          f"tokens={b.tokens}")
    check("reconfigure: updates max", b.max == 5.0)
    b.reconfigure(max_tokens=20, window=2)         # rate 20/2 = 10/s
    check("reconfigure: updates rate", b.rate == 10.0, f"rate={b.rate}")
    # fractional max is allowed (max_stream_weight is 0.0 by default)
    b.reconfigure(max_tokens=0.5, window=1)
    check("reconfigure: fractional max allowed (no stream weight)", b.max == 0.5)
    # invalid reconfig
    check("reconfigure: max<=0 rejected", raises_config(lambda: b.reconfigure(0, 1)))
    check("reconfigure: window<=0 rejected", raises_config(lambda: b.reconfigure(5, 0)))


def test_stream_weight():
    b = Bucket(3, 1, 0.0)
    check("stream_weight: weight > max rejected at registration",
          raises_config(lambda: b.register_stream_weight(5)))
    b.register_stream_weight(2)                     # ok, <= max 3
    check("stream_weight: recorded", b.max_stream_weight == 2.0)
    # multiple registrations keep the MAXIMUM, not last/sum/min
    b.register_stream_weight(1)                     # smaller -> must NOT lower it
    check("stream_weight: smaller second registration keeps the max",
          b.max_stream_weight == 2.0)
    # now reconfigure below the registered weight must fail
    check("stream_weight: reconfigure below registered weight rejected",
          raises_config(lambda: b.reconfigure(1, 1)))
    # reconfigure at/above is fine
    b.reconfigure(2, 1)
    check("stream_weight: reconfigure at weight ok", b.max == 2.0)
    check("stream_weight: weight <= 0 rejected",
          raises_config(lambda: b.register_stream_weight(0)))
    # consistent numeric discipline: nan/bool must raise, not silently no-op
    check("stream_weight: nan rejected (not a silent no-op)",
          raises_config(lambda: b.register_stream_weight(float("nan"))))
    check("stream_weight: bool rejected",
          raises_config(lambda: b.register_stream_weight(True)))
    # boundary: weight == max is allowed (the guard is strict >)
    be = Bucket(3, 1, 0.0)
    be.register_stream_weight(3)
    check("stream_weight: weight == max allowed (boundary)",
          be.max_stream_weight == 3.0)


# ── RateLimiter registry: configure / get / remove / live reconfigure ──
def test_registry():
    rl = RateLimiter()
    b = rl.configure("plugin_out", "P", max_tokens=10, window=1, now=0.0)
    check("registry: configure creates bucket", rl.get("plugin_out", "P") is b)
    # configure again reconfigures the SAME bucket (does not replace) and the
    # clamp-on-shrink fires via the registry path (tokens 8 -> new max 5).
    b.tokens = 8.0
    b2 = rl.configure("plugin_out", "P", max_tokens=5, window=1, now=0.0)
    check("registry: re-configure reuses bucket + clamps tokens to new max",
          b2 is b and b.max == 5.0 and b.tokens == 5.0, f"tokens={b.tokens}")
    check("registry: get miss returns None", rl.get("plugin_out", "Q") is None)
    rl.remove("plugin_out", "P")
    check("registry: remove tears down bucket", rl.get("plugin_out", "P") is None)
    check("registry: remove missing is a no-op", rl.remove("x", "y") is None)


def test_config_validation():
    rl = RateLimiter()
    check("config: max=0 rejected", raises_config(lambda: rl.configure("d", "k", 0, 1)))
    check("config: window=0 rejected", raises_config(lambda: rl.configure("d", "k", 5, 0)))
    check("config: negative max rejected", raises_config(lambda: rl.configure("d", "k", -5, 1)))
    check("config: non-numeric rejected", raises_config(lambda: rl.configure("d", "k", "abc", 1)))
    # bool is an int subclass; float(True)==1.0 must NOT slip through as a 1-token bucket
    check("config: max=True (bool) rejected", raises_config(lambda: rl.configure("d", "k", True, 1)))
    check("config: window=False (bool) rejected", raises_config(lambda: rl.configure("d", "k", 5, False)))
    # inf/nan slip past a bare `<= 0` check and create silently-broken buckets
    check("config: max=inf rejected", raises_config(lambda: rl.configure("d", "k", float("inf"), 1)))
    check("config: window=inf rejected", raises_config(lambda: rl.configure("d", "k", 5, float("inf"))))
    check("config: max=nan rejected", raises_config(lambda: rl.configure("d", "k", float("nan"), 1)))


# ── counters reflect true volume ───────────────────────────────────────
def test_counters():
    rl = RateLimiter()
    b = Bucket(2, 1, 0.0)
    rl.admit([b], 1.0, 0.0)            # charge
    rl.admit([b], 1.0, 0.0)            # charge (tokens now 0)
    rl.admit([b], 1.0, 0.0)            # reject
    rl.admit([b], 1.0, 0.0)            # reject
    check("counters: charged counts commits", b.charged == 2, f"charged={b.charged}")
    check("counters: rejected counts rejects", b.rejected == 2, f"rejected={b.rejected}")


def test_admit_refill_mid_charge():
    # admit() must refill before peeking: a bucket too dry at t0 admits at t1
    # because time advanced. This is the runtime path; the bare refill() tests
    # don't exercise it through admit().
    b = Bucket(10, 1, 0.0)            # rate = 10/s
    b.tokens = 0.5
    check("admit: dry at t=0 rejects", RateLimiter().admit([b], 1.0, now=0.0) is b)
    res = RateLimiter().admit([b], 1.0, now=0.1)   # +0.1s * 10/s = +1 -> 1.5
    check("admit: refill during admit lets it pass at t=0.1",
          res is None and abs(b.tokens - 0.5) < 1e-9, f"tokens={b.tokens}")


def test_reconfigure_rate_effect():
    # After a rate change, refill must accrue at the NEW rate, not the old one.
    b = Bucket(10, 1, 0.0); b.tokens = 0.0          # rate 10/s
    b.reconfigure(max_tokens=6, window=3)           # new rate = 2/s
    b.refill(now=1.0)                               # 1s * 2/s = 2 tokens
    check("reconfigure: subsequent refill uses the new rate",
          abs(b.tokens - 2.0) < 1e-9, f"tokens={b.tokens}")


def test_backward_now_is_noop():
    # A non-monotonic / stale now must NOT drain tokens (it is clamped to a
    # no-op); last must not move backward.
    b = Bucket(10, 1, now=5.0); b.tokens = 7.0
    b.refill(now=3.0)                               # now < last -> no-op
    check("backward now: tokens not drained", b.tokens == 7.0, f"tokens={b.tokens}")
    check("backward now: last not moved backward", b.last == 5.0, f"last={b.last}")
    # and admit() with a backward now likewise does not falsely reject
    res = RateLimiter().admit([b], 1.0, now=3.0)
    check("backward now: admit still works (no false reject)",
          res is None and b.tokens == 6.0, f"tokens={b.tokens}")


def test_admit_cost_guard():
    b = Bucket(5, 1, 0.0)
    check("admit: cost=0 rejected (raises)",
          raises_config(lambda: RateLimiter().admit([b], cost=0.0, now=0.0)))
    check("admit: negative cost rejected (raises)",
          raises_config(lambda: RateLimiter().admit([b], cost=-2.0, now=0.0)))
    check("admit: cost guard did not touch tokens", b.tokens == 5.0)
    # a generator would be exhausted by the peek phase -> commit charges nothing
    # -> silent admit-without-charge. admit must reject non-list/tuple.
    check("admit: generator rejected (silent-no-charge trap)",
          raises_config(lambda: RateLimiter().admit((x for x in [b]), 1.0, now=0.0)))
    # tuple is allowed (re-iterable)
    check("admit: tuple charge-set allowed",
          RateLimiter().admit((b,), 1.0, now=0.0) is None)


if __name__ == "__main__":
    print("plexus.ratelimiter unit tests:")
    for t in (test_refill, test_admit_commit_all, test_admit_reject_no_leak,
              test_admit_boundary, test_admit_deterministic_order, test_admit_empty,
              test_admit_refill_mid_charge, test_fractional_cost, test_reconfigure,
              test_reconfigure_rate_effect, test_backward_now_is_noop,
              test_admit_cost_guard, test_stream_weight,
              test_registry, test_config_validation, test_counters):
        t()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", ", ".join(FAIL))
        raise SystemExit(1)
    print("ALL PASS")
