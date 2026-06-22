"""TestRateLimiterUnitSuite — pure-function unit tests for the Bucket + RateLimiter core.

Ported from the former root-level ``test_ratelimiter.py``. Self-contained:
imports Bucket / RateLimiter / charge_set / endpoint_key / event_key and
exercises them with injected ``now`` values so there are no sleeps and no
wall-clock flakiness. No Plexus boot, no event loop semantics needed.

Categories: ``bucket`` (refill / reconfigure / stream_weight),
``admit`` (commit / reject / boundary / cost guard),
``keys`` (helper functions / charge_set),
``registry`` (configure / get / remove / locate / config validation),
``stats`` (counters / stats() / refill-for-show).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.ratelimiter import (  # noqa: E402
    Bucket, RateLimiter, charge_set, endpoint_key, event_key,
    DIM_PLUGIN_IN, DIM_ENDPOINT_IN, DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY,
)
from plexus.exceptions import ConfigException  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


def _raises_config(fn):
    """Return True if fn() raises ConfigException, False otherwise."""
    try:
        fn()
        return False
    except ConfigException:
        return True


class TestRateLimiterUnitSuite(Plugin):
    """Pure-function unit suite for the Bucket + RateLimiter core."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestRateLimiterUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestRateLimiterUnitSuite disabled")

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
        rec = CaseRecorder("TestRateLimiterUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        # bucket cases
        await self._refill(rec, kw)
        await self._reconfigure(rec, kw)
        await self._stream_weight(rec, kw)
        await self._reconfigure_reset_stream_weight(rec, kw)
        await self._reconfigure_rate_effect(rec, kw)
        await self._bug036_idle_credit_old_rate(rec, kw)
        await self._backward_now_is_noop(rec, kw)
        # admit cases
        await self._admit_commit_all(rec, kw)
        await self._admit_reject_no_leak(rec, kw)
        await self._admit_boundary(rec, kw)
        await self._admit_deterministic_order(rec, kw)
        await self._admit_empty(rec, kw)
        await self._fractional_cost(rec, kw)
        await self._admit_refill_mid_charge(rec, kw)
        await self._admit_cost_guard(rec, kw)
        # keys cases
        await self._key_helpers(rec, kw)
        await self._charge_set(rec, kw)
        # registry cases
        await self._registry(rec, kw)
        await self._locate(rec, kw)
        await self._config_validation(rec, kw)
        # stats cases
        await self._counters(rec, kw)
        await self._stats(rec, kw)
        await self._stats_last_rate_refill_for_show(rec, kw)

        return rec.to_dict()

    # ── bucket cases ────────────────────────────────────────────────────────

    async def _refill(self, rec, kw):
        async def body(c):
            b = Bucket(max_tokens=10, window=1, now=0.0)   # rate = 10 tokens/s
            assert b.tokens == 10.0, "refill: starts full"
            b.tokens = 0.0
            b.refill(now=0.5)                               # 0.5s * 10/s = 5
            assert b.tokens == 5.0, f"refill: lazy continuous (tokens={b.tokens})"
            b.refill(now=100.0)                             # would be huge -> clamp to max
            assert b.tokens == 10.0, f"refill: clamps at max (tokens={b.tokens})"
            # fractional window/rate
            b2 = Bucket(max_tokens=1, window=60, now=0.0)   # 1 per 60s -> rate 1/60
            b2.tokens = 0.0
            b2.refill(now=30.0)
            assert abs(b2.tokens - 0.5) < 1e-9, \
                f"refill: fractional rate (1/60 over 30s = 0.5) (tokens={b2.tokens})"

        await rec.run_case(
            "ratelimiter.refill", body,
            tags=("ratelimiter", "bucket", "refill"), category="bucket", **kw
        )

    async def _reconfigure(self, rec, kw):
        async def body(c):
            b = Bucket(10, 1, 0.0); b.tokens = 8.0
            b.reconfigure(max_tokens=5, window=1, now=0.0)  # shrink max 10 -> 5
            assert b.tokens == 5.0, \
                f"reconfigure: clamps tokens down on shrink (tokens={b.tokens})"
            assert b.max == 5.0, "reconfigure: updates max"
            b.reconfigure(max_tokens=20, window=2, now=0.0)  # rate 20/2 = 10/s
            assert b.rate == 10.0, f"reconfigure: updates rate (rate={b.rate})"
            # fractional max is allowed (max_stream_weight is 0.0 by default)
            b.reconfigure(max_tokens=0.5, window=1, now=0.0)
            assert b.max == 0.5, "reconfigure: fractional max allowed (no stream weight)"
            # invalid reconfig
            assert _raises_config(lambda: b.reconfigure(0, 1, now=0.0)), \
                "reconfigure: max<=0 rejected"
            assert _raises_config(lambda: b.reconfigure(5, 0, now=0.0)), \
                "reconfigure: window<=0 rejected"

        await rec.run_case(
            "ratelimiter.reconfigure", body,
            tags=("ratelimiter", "bucket", "reconfigure"), category="bucket", **kw
        )

    async def _stream_weight(self, rec, kw):
        async def body(c):
            b = Bucket(3, 1, 0.0)
            assert _raises_config(lambda: b.register_stream_weight(5)), \
                "stream_weight: weight > max rejected at registration"
            b.register_stream_weight(2)                     # ok, <= max 3
            assert b.max_stream_weight == 2.0, "stream_weight: recorded"
            # multiple registrations keep the MAXIMUM, not last/sum/min
            b.register_stream_weight(1)                     # smaller -> must NOT lower it
            assert b.max_stream_weight == 2.0, \
                "stream_weight: smaller second registration keeps the max"
            # now reconfigure below the registered weight must fail
            assert _raises_config(lambda: b.reconfigure(1, 1, now=0.0)), \
                "stream_weight: reconfigure below registered weight rejected"
            # reconfigure at/above is fine
            b.reconfigure(2, 1, now=0.0)
            assert b.max == 2.0, "stream_weight: reconfigure at weight ok"
            assert _raises_config(lambda: b.register_stream_weight(0)), \
                "stream_weight: weight <= 0 rejected"
            # consistent numeric discipline: nan/bool must raise, not silently no-op
            assert _raises_config(lambda: b.register_stream_weight(float("nan"))), \
                "stream_weight: nan rejected (not a silent no-op)"
            assert _raises_config(lambda: b.register_stream_weight(True)), \
                "stream_weight: bool rejected"
            # boundary: weight == max is allowed (the guard is strict >)
            be = Bucket(3, 1, 0.0)
            be.register_stream_weight(3)
            assert be.max_stream_weight == 3.0, \
                "stream_weight: weight == max allowed (boundary)"

        await rec.run_case(
            "ratelimiter.stream_weight", body,
            tags=("ratelimiter", "bucket", "stream_weight"), category="bucket", **kw
        )

    async def _reconfigure_reset_stream_weight(self, rec, kw):
        async def body(c):
            # Regression: the charge-set REBUILD reconfigures a bucket and then
            # RE-REGISTERS stream weights from scratch in the same pass. A reload
            # that legitimately LOWERS both a stream_weight and the bucket max must
            # not be rejected by the stale grow-only floor.
            # reset_stream_weight=True (what the rebuild passes) clears the floor
            # first; the default keeps the live-tuning guard.
            br = Bucket(12, 1, 0.0)
            br.register_stream_weight(10)                    # floor now 10, max 12
            # default reconfigure still rejects lowering max below the active weight
            assert _raises_config(lambda: br.reconfigure(5, 1, now=0.0)), \
                "reset_stream_weight: default still guards (max<weight rejected)"
            # rebuild flow: reset clears the stale floor so the lower max is accepted
            br.reconfigure(5, 1, now=0.0, reset_stream_weight=True)
            assert br.max_stream_weight == 0.0, \
                "reset_stream_weight: clears the stale floor"
            assert br.max == 5.0, "reset_stream_weight: applies the lowered max"
            br.register_stream_weight(2)                     # rebuild re-registers new weight
            assert br.max_stream_weight == 2.0, \
                "reset_stream_weight: new lower weight re-registers fine"
            # the per-registration guard still catches a genuinely over-weight stream
            assert _raises_config(lambda: br.register_stream_weight(9)), \
                "reset_stream_weight: over-max weight still rejected at registration"

        await rec.run_case(
            "ratelimiter.reconfigure_reset_stream_weight", body,
            tags=("ratelimiter", "bucket", "reconfigure", "stream_weight"),
            category="bucket", **kw
        )

    async def _reconfigure_rate_effect(self, rec, kw):
        async def body(c):
            # After a rate change, refill must accrue at the NEW rate, not the old one.
            b = Bucket(10, 1, 0.0); b.tokens = 0.0          # rate 10/s, last=0.0
            b.reconfigure(max_tokens=6, window=3, now=0.0)  # new rate = 2/s, anchor at 0.0
            b.refill(now=1.0)                               # 1s * 2/s = 2 tokens
            assert abs(b.tokens - 2.0) < 1e-9, \
                f"reconfigure: subsequent refill uses the new rate (tokens={b.tokens})"

        await rec.run_case(
            "ratelimiter.reconfigure_rate_effect", body,
            tags=("ratelimiter", "bucket", "reconfigure", "refill"), category="bucket", **kw
        )

    async def _bug036_idle_credit_old_rate(self, rec, kw):
        # BUG-036: a bucket that sat idle, then is reconfigured to a HIGHER rate,
        # must credit the pre-reconfigure idle interval at the OLD rate and
        # re-anchor `last` to `now` BEFORE swapping the rate -- so the new rate is
        # NOT retro-applied to that idle interval. Drain at t=0, idle to t=50,
        # reconfigure 0.1/s -> 10/s at t=50, then refill at the SAME instant t=50:
        # the only credit is 50s of idle at the OLD 0.1/s rate (= 5 tokens). The
        # bug retro-credited 50s at the NEW 10/s rate (= 500, clamped to max 10).
        async def body(c):
            b = Bucket(10, 100, now=0.0)    # rate 0.1/s
            b.tokens = 0.0                  # drained at t=0; last still 0.0 (idle)
            b.reconfigure(10, 1, now=50.0)  # -> 10/s; refill-at-old-rate + re-anchor
            b.refill(now=50.0)              # same instant: 0s elapsed at the new rate
            # 50s idle credited at OLD 0.1/s = 5 tokens; NOT 500 (clamped to 10).
            assert abs(b.tokens - 5.0) < 1e-9, (
                f"idle interval must credit at the OLD rate (5 tokens), got {b.tokens}"
            )

        await rec.run_case(
            "ratelimiter.reconfigure_idle_credit_old_rate", body,
            tags=("ratelimiter", "bucket", "reconfigure", "refill"),
            bug_ids=("BUG-036",), category="bucket", **kw
        )

    async def _backward_now_is_noop(self, rec, kw):
        async def body(c):
            # A non-monotonic / stale now must NOT drain tokens (it is clamped to a
            # no-op); last must not move backward.
            b = Bucket(10, 1, now=5.0); b.tokens = 7.0
            b.refill(now=3.0)                               # now < last -> no-op
            assert b.tokens == 7.0, \
                f"backward now: tokens not drained (tokens={b.tokens})"
            assert b.last == 5.0, \
                f"backward now: last not moved backward (last={b.last})"
            # and admit() with a backward now likewise does not falsely reject
            res = RateLimiter().admit([b], 1.0, now=3.0)
            assert res is None and b.tokens == 6.0, \
                f"backward now: admit still works (no false reject) (tokens={b.tokens})"

        await rec.run_case(
            "ratelimiter.backward_now_is_noop", body,
            tags=("ratelimiter", "bucket", "refill", "admit"), category="bucket", **kw
        )

    # ── admit cases ─────────────────────────────────────────────────────────

    async def _admit_commit_all(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            b1 = Bucket(5, 1, 0.0); b2 = Bucket(5, 1, 0.0)
            res = rl.admit([b1, b2], cost=1.0, now=0.0)
            assert res is None, "admit: all-pass returns None"
            assert b1.tokens == 4.0 and b2.tokens == 4.0, \
                "admit: both committed -cost"
            assert b1.charged == 1 and b2.charged == 1, \
                "admit: both charged++"

        await rec.run_case(
            "ratelimiter.admit_commit_all", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _admit_reject_no_leak(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            full = Bucket(5, 1, 0.0)
            dry = Bucket(5, 1, 0.0); dry.tokens = 0.0
            res = rl.admit([full, dry], cost=1.0, now=0.0)
            assert res is dry, "admit: returns the dry bucket"
            assert full.tokens == 5.0, \
                f"admit: NO leak -- earlier bucket untouched (full.tokens={full.tokens})"
            assert full.charged == 0, "admit: earlier bucket not charged"
            assert dry.rejected == 1 and dry.charged == 0, \
                "admit: dry bucket rejected++ (and not charged)"

        await rec.run_case(
            "ratelimiter.admit_reject_no_leak", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _admit_boundary(self, rec, kw):
        async def body(c):
            # tokens == cost exactly must ADMIT (tokens < cost is False)
            b = Bucket(5, 1, 0.0); b.tokens = 1.0
            res = RateLimiter().admit([b], cost=1.0, now=0.0)
            assert res is None and b.tokens == 0.0, \
                f"admit: tokens == cost admits (boundary) (tokens={b.tokens})"
            # now empty, cost 1 -> reject
            res2 = RateLimiter().admit([b], cost=1.0, now=0.0)
            assert res2 is b, "admit: empty then cost=1 rejects"

        await rec.run_case(
            "ratelimiter.admit_boundary", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _admit_deterministic_order(self, rec, kw):
        async def body(c):
            a = Bucket(5, 1, 0.0)
            d1 = Bucket(5, 1, 0.0); d1.tokens = 0.0
            d2 = Bucket(5, 1, 0.0); d2.tokens = 0.0
            res = RateLimiter().admit([a, d1, d2], cost=1.0, now=0.0)
            assert res is d1, "admit: returns FIRST dry in iteration order"
            assert d1.rejected == 1 and d2.rejected == 0, \
                "admit: only the first dry is counted rejected"

        await rec.run_case(
            "ratelimiter.admit_deterministic_order", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _admit_empty(self, rec, kw):
        async def body(c):
            assert RateLimiter().admit([], 1.0, 0.0) is None, \
                "admit: empty charge-set admits"

        await rec.run_case(
            "ratelimiter.admit_empty", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _fractional_cost(self, rec, kw):
        async def body(c):
            b = Bucket(5, 1, 0.0); b.tokens = 3.0
            res = RateLimiter().admit([b], cost=2.5, now=0.0)
            assert res is None and abs(b.tokens - 0.5) < 1e-9, \
                "admit: fractional cost commits"
            res2 = RateLimiter().admit([b], cost=2.5, now=0.0)
            assert res2 is b, "admit: fractional cost rejects when short"

        await rec.run_case(
            "ratelimiter.fractional_cost", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    async def _admit_refill_mid_charge(self, rec, kw):
        async def body(c):
            # admit() must refill before peeking: a bucket too dry at t0 admits at t1
            # because time advanced. This is the runtime path; the bare refill() tests
            # don't exercise it through admit().
            b = Bucket(10, 1, 0.0)            # rate = 10/s
            b.tokens = 0.5
            assert RateLimiter().admit([b], 1.0, now=0.0) is b, \
                "admit: dry at t=0 rejects"
            res = RateLimiter().admit([b], 1.0, now=0.1)   # +0.1s * 10/s = +1 -> 1.5
            assert res is None and abs(b.tokens - 0.5) < 1e-9, \
                f"admit: refill during admit lets it pass at t=0.1 (tokens={b.tokens})"

        await rec.run_case(
            "ratelimiter.admit_refill_mid_charge", body,
            tags=("ratelimiter", "admit", "refill"), category="admit", **kw
        )

    async def _admit_cost_guard(self, rec, kw):
        async def body(c):
            b = Bucket(5, 1, 0.0)
            assert _raises_config(lambda: RateLimiter().admit([b], cost=0.0, now=0.0)), \
                "admit: cost=0 rejected (raises)"
            assert _raises_config(lambda: RateLimiter().admit([b], cost=-2.0, now=0.0)), \
                "admit: negative cost rejected (raises)"
            assert b.tokens == 5.0, "admit: cost guard did not touch tokens"
            # a generator would be exhausted by the peek phase -> commit charges nothing
            # -> silent admit-without-charge. admit must reject non-list/tuple.
            assert _raises_config(
                lambda: RateLimiter().admit((x for x in [b]), 1.0, now=0.0)
            ), "admit: generator rejected (silent-no-charge trap)"
            # tuple is allowed (re-iterable)
            assert RateLimiter().admit((b,), 1.0, now=0.0) is None, \
                "admit: tuple charge-set allowed"

        await rec.run_case(
            "ratelimiter.admit_cost_guard", body,
            tags=("ratelimiter", "admit"), category="admit", **kw
        )

    # ── keys cases ──────────────────────────────────────────────────────────

    async def _key_helpers(self, rec, kw):
        async def body(c):
            assert endpoint_key("LLM", "complete") == "LLM:complete", \
                "key: endpoint_key joins plugin:access"
            assert event_key("Orch", "response") == "Orch:response", \
                "key: event_key joins plugin:event"

        await rec.run_case(
            "ratelimiter.key_helpers", body,
            tags=("ratelimiter", "keys"), category="keys", **kw
        )

    async def _charge_set(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            # Configure two of three dimensions; the unconfigured one is skipped.
            ep = rl.configure(DIM_ENDPOINT_IN, endpoint_key("Q", "E"), 20, 1, now=0.0)
            pin = rl.configure(DIM_PLUGIN_IN, "Q", 100, 1, now=0.0)
            specs = [
                (DIM_ENDPOINT_IN, endpoint_key("Q", "E")),
                (DIM_PLUGIN_IN, "Q"),
                (DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY),   # NOT configured -> skipped
            ]
            cs = charge_set(rl, specs)
            assert cs == [ep, pin], \
                "charge_set: returns configured buckets in spec order"
            assert isinstance(cs, list), \
                "charge_set: is a re-iterable list (admit requirement)"
            # Now configure framework_in too -> it appears LAST (spec order preserved).
            fin = rl.configure(DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY, 1000, 1, now=0.0)
            cs2 = charge_set(rl, specs)
            assert cs2 == [ep, pin, fin], \
                "charge_set: newly-configured dim joins in pinned spec order"
            # All-unconfigured -> empty -> admit no-ops (zero-overhead-off).
            empty = charge_set(rl, [(DIM_PLUGIN_IN, "Nope"), (DIM_ENDPOINT_IN, "x:y")])
            assert empty == [], \
                "charge_set: all-unconfigured yields empty list"
            assert rl.admit(empty, 1.0, 0.0) is None, \
                "charge_set: empty set admits (no-op)"

        await rec.run_case(
            "ratelimiter.charge_set", body,
            tags=("ratelimiter", "keys", "charge_set"), category="keys", **kw
        )

    # ── registry cases ───────────────────────────────────────────────────────

    async def _registry(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            # __len__ is the bucket count that drives the framework's
            # _rate_limits_active master switch (zero-overhead-off).
            assert len(rl) == 0, \
                "registry: empty len 0 (rate_limits_active stays off)"
            b = rl.configure("plugin_out", "P", max_tokens=10, window=1, now=0.0)
            assert rl.get("plugin_out", "P") is b, \
                "registry: configure creates bucket"
            assert len(rl) == 1, "registry: len 1 after first configure"
            # configure again reconfigures the SAME bucket (does not replace) and the
            # clamp-on-shrink fires via the registry path (tokens 8 -> new max 5).
            b.tokens = 8.0
            b2 = rl.configure("plugin_out", "P", max_tokens=5, window=1, now=0.0)
            assert b2 is b and b.max == 5.0 and b.tokens == 5.0, \
                f"registry: re-configure reuses bucket + clamps tokens to new max (tokens={b.tokens})"
            assert len(rl) == 1, \
                "registry: re-configure of same key does NOT bump len"
            rl.configure("plugin_in", "Q", max_tokens=5, window=1, now=0.0)
            assert len(rl) == 2, "registry: distinct key bumps len to 2"
            assert set(rl.keys()) == {("plugin_out", "P"), ("plugin_in", "Q")}, \
                "registry: keys() snapshots all configured (dim,key)"
            assert rl.get("plugin_out", "Z") is None, \
                "registry: get miss returns None"
            rl.remove("plugin_out", "P")
            assert rl.get("plugin_out", "P") is None, \
                "registry: remove tears down bucket"
            assert len(rl) == 1, "registry: len drops to 1 after remove"
            assert rl.remove("x", "y") is None, \
                "registry: remove missing is a no-op"

        await rec.run_case(
            "ratelimiter.registry", body,
            tags=("ratelimiter", "registry"), category="registry", **kw
        )

    async def _locate(self, rec, kw):
        async def body(c):
            # locate() reverse-maps a live Bucket back to its (dimension, key) so the
            # reject site can name the binding limit (admit returns the bucket but not
            # its identity). Used only on the reject path.
            rl = RateLimiter()
            a = rl.configure("plugin_out", "P", max_tokens=10, window=1, now=0.0)
            b = rl.configure("framework_in", "global", max_tokens=5, window=1, now=0.0)
            assert rl.locate(a) == ("plugin_out", "P"), \
                "locate: maps bucket A to its key"
            assert rl.locate(b) == ("framework_in", "global"), \
                "locate: maps bucket B to its key"
            # a bucket not in this registry (or removed) -> None
            stray = Bucket(3, 1, 0.0)
            assert rl.locate(stray) is None, \
                "locate: unregistered bucket -> None"
            rl.remove("plugin_out", "P")
            assert rl.locate(a) is None, \
                "locate: removed bucket -> None"

        await rec.run_case(
            "ratelimiter.locate", body,
            tags=("ratelimiter", "registry", "locate"), category="registry", **kw
        )

    async def _config_validation(self, rec, kw):
        async def body(c):
            rl = RateLimiter()

            def rejects(max_tokens, window):
                return _raises_config(lambda: rl.configure("d", "k", max_tokens, window))

            assert rejects(0, 1), "config: max=0 rejected"
            assert rejects(5, 0), "config: window=0 rejected"
            assert rejects(-5, 1), "config: negative max rejected"
            assert rejects("abc", 1), "config: non-numeric rejected"
            # bool is an int subclass; float(True)==1.0 must NOT slip through as a
            # silent 1-token bucket.
            assert rejects(True, 1), "config: max=True (bool) rejected"
            assert rejects(5, False), "config: window=False (bool) rejected"
            # inf/nan slip past a bare `<= 0` check and create silently-broken buckets.
            assert rejects(float("inf"), 1), "config: max=inf rejected"
            assert rejects(5, float("inf")), "config: window=inf rejected"
            assert rejects(float("nan"), 1), "config: max=nan rejected"

        await rec.run_case(
            "ratelimiter.config_validation", body,
            tags=("ratelimiter", "registry", "validation"), category="registry", **kw
        )

    # ── stats cases ──────────────────────────────────────────────────────────

    async def _counters(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            b = Bucket(2, 1, 0.0)
            rl.admit([b], 1.0, 0.0)            # charge
            rl.admit([b], 1.0, 0.0)            # charge (tokens now 0)
            rl.admit([b], 1.0, 0.0)            # reject
            rl.admit([b], 1.0, 0.0)            # reject
            assert b.charged == 2, f"counters: charged counts commits (charged={b.charged})"
            assert b.rejected == 2, f"counters: rejected counts rejects (rejected={b.rejected})"

        await rec.run_case(
            "ratelimiter.counters", body,
            tags=("ratelimiter", "stats", "counters"), category="stats", **kw
        )

    async def _stats(self, rec, kw):
        async def body(c):
            rl = RateLimiter()
            # empty limiter -> empty list.
            assert rl.stats() == [], "stats: empty -> []"
            rl.configure(DIM_PLUGIN_IN, "P", 2, 1, now=0.0)
            rl.configure(DIM_ENDPOINT_IN, endpoint_key("P", "e"), 5, 1, now=0.0)
            pin = rl.get(DIM_PLUGIN_IN, "P")
            rl.admit([pin], 1.0, 0.0)            # charge (tokens 2 -> 1)
            rl.admit([pin], 1.0, 0.0)            # charge (1 -> 0)
            rl.admit([pin], 1.0, 0.0)            # reject (0 tokens)
            recs = rl.stats()
            assert len(recs) == 2, f"stats: one record per bucket (got {len(recs)})"
            assert all(isinstance(r, dict) for r in recs), \
                "stats: list of dict records"
            by_key = {(r["dim"], r["key"]): r for r in recs}
            pr = by_key[(DIM_PLUGIN_IN, "P")]
            assert pr["charged"] == 2, f"stats: charged reported (charged={pr['charged']})"
            assert pr["rejected"] == 1, f"stats: rejected reported (rejected={pr['rejected']})"
            assert pr["max"] == 2.0, f"stats: max reported (max={pr['max']})"
            assert pr["tokens"] == 0.0, \
                f"stats: raw tokens (no refill side effect) (tokens={pr['tokens']})"
            # stats() must not have mutated the bucket (no refill).
            assert pin.tokens == 0.0, \
                f"stats: pure (tokens unchanged after stats) (tokens={pin.tokens})"
            # the idle, never-charged endpoint bucket reports its full starting tokens.
            er = by_key[(DIM_ENDPOINT_IN, endpoint_key("P", "e"))]
            assert er["tokens"] == 5.0 and er["charged"] == 0, \
                "stats: untouched bucket full"

        await rec.run_case(
            "ratelimiter.stats", body,
            tags=("ratelimiter", "stats"), category="stats", **kw
        )

    async def _stats_last_rate_refill_for_show(self, rec, kw):
        async def body(c):
            # stats() exposes `last` + `rate` so a display layer can refill-for-show
            # WITHOUT mutating the bucket. Verify the fields are present, correct, and
            # that the documented formula reconstructs the live level of an idle bucket.
            rl = RateLimiter()
            rl.configure(DIM_PLUGIN_IN, "P", 10, 2, now=100.0)   # rate = 10/2 = 5/s
            pin = rl.get(DIM_PLUGIN_IN, "P")
            rl.admit([pin], 4.0, 100.0)                          # tokens 10 -> 6 at t=100
            rec_stat = rl.stats()[0]
            assert rec_stat.get("last") == 100.0, \
                f"stats: last present (last={rec_stat.get('last')})"
            assert rec_stat.get("rate") == 5.0, \
                f"stats: rate present (rate={rec_stat.get('rate')})"
            assert rec_stat["tokens"] == 6.0, \
                f"stats: raw tokens unrefilled (tokens={rec_stat['tokens']})"
            # refill-for-show at t=100.5 (idle 0.5s): 6 + 0.5*5 = 8.5, no mutation.
            now = 100.5
            live = min(rec_stat["max"], rec_stat["tokens"] + (now - rec_stat["last"]) * rec_stat["rate"])
            assert abs(live - 8.5) < 1e-9, f"stats: refill-for-show math (live={live})"
            assert pin.tokens == 6.0, \
                f"stats: refill-for-show did NOT mutate bucket (tokens={pin.tokens})"
            # clamps at max: far-future read cannot exceed capacity.
            live_far = min(rec_stat["max"], rec_stat["tokens"] + (1000.0 - rec_stat["last"]) * rec_stat["rate"])
            assert live_far == 10.0, \
                f"stats: refill-for-show clamps at max (live={live_far})"

        await rec.run_case(
            "ratelimiter.stats_last_rate_refill_for_show", body,
            tags=("ratelimiter", "stats", "refill_for_show"), category="stats", **kw
        )
