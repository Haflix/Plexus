"""Rate-limit charge-set precompute integration suite (Step 3b).

Proves that ``_rebuild_charge_sets`` attaches the CORRECT precomputed buckets to
the Plexus-owned side-tables, asserting exact ``Bucket`` OBJECT IDENTITY (so the
cross-plugin / fallback / idempotency cases prove the real references, not just
"something is attached"). NO ``admit()`` calls -- those land in 3c/3d.

Config is injected directly into ``_rate_limit_config`` /
``_rate_limit_sub_config`` (Step 4 will flatten the YAML ``rate_limits:`` section
into them). Each case starts from a FRESH limiter so prior test buckets don't
leak; ``run`` restores the boot limiter + config + flags in ``finally``.

Cases:
- endpoint_in_set: endpoint IN-set == [endpoint_in, plugin_in]; unconfigured dim skipped.
- event_out: the event_out bucket is stored by (plugin, event_id).
- cross_plugin_sub: a sub owned by the suite but targeting another plugin keys its
  IN-set on the TARGET (+ declared_id -> sub_uuid resolution).
- runtime_sub_fallback: a runtime sub (no declared_id) gets no Sub-IN and its
  charge-set is built on subscribe; unsubscribe tears it down.
- teardown_sub_bucket: _rl_teardown_sub removes the Sub-IN bucket + the entry.
- empty_config: a default node has empty side-tables and _rate_limits_active False.
- idempotent: rebuilding twice does not double the attachments.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.ratelimiter import (  # noqa: E402
    RateLimiter, endpoint_key, event_key,
    DIM_PLUGIN_IN, DIM_ENDPOINT_IN, DIM_EVENT_OUT, DIM_SUB_IN,
)

from _test_helpers import CaseRecorder  # noqa: E402

SUITE_VERSION = "0.1.0"
SUITE = "TestRateLimitSuite"
TARGET = "TestRateLimitTarget"


class TestRateLimitSuite(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def ep_a(self, value: Any = None) -> str:
        return "ep_a"

    def _apply(self, cfg: Dict, subcfg: Optional[Dict] = None) -> None:
        """Reset to a FRESH limiter (drop prior test buckets) + inject config.
        Caller awaits ``_rebuild_charge_sets`` after."""
        px = self._plexus
        px._rate_limiter = RateLimiter()
        px._rate_limit_config = dict(cfg)
        px._rate_limit_sub_config = dict(subcfg or {})

    async def _xsub_uuid(self) -> str:
        subs = await self._plexus.topic_registry.get_plugin_subscriptions(
            self.plugin_uuid
        )
        for s in subs:
            if s.declared_id == "xsub":
                return s.sub_uuid
        raise AssertionError("declared sub 'xsub' not found on the suite")

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
        rec = CaseRecorder("TestRateLimitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids, bug_ids_filter=bug_ids,
            category_filter=category, host_filter=host,
            skip_slow=skip_slow, allow_destructive=allow_destructive,
            remote_available=False,
        )
        px = self._plexus
        orig_limiter = px._rate_limiter
        orig_cfg = px._rate_limit_config
        orig_subcfg = px._rate_limit_sub_config
        orig_active = px._rate_limits_active
        orig_id = px._identity_active
        runtime_subs: List[str] = []
        try:
            await self._case_endpoint_in_set(rec, kw)
            await self._case_event_out(rec, kw)
            await self._case_cross_plugin_sub(rec, kw)
            await self._case_runtime_sub_fallback(rec, kw, runtime_subs)
            await self._case_teardown_sub_bucket(rec, kw)
            await self._case_empty_config(rec, kw)
            await self._case_idempotent(rec, kw)
            await self._case_orphan_prune(rec, kw)
        finally:
            for su in runtime_subs:
                try:
                    await px.unsubscribe_event(su)
                except Exception:
                    pass
            px._rate_limiter = orig_limiter
            px._rate_limit_config = orig_cfg
            px._rate_limit_sub_config = orig_subcfg
            await px._rebuild_charge_sets()
            px._rate_limits_active = orig_active
            px._identity_active = orig_id
        return rec.to_dict()

    async def _case_endpoint_in_set(self, rec, kw):
        async def body(c):
            px = self._plexus
            self._apply({
                (DIM_ENDPOINT_IN, endpoint_key(SUITE, "ep_a")): {"max": 20, "window": 1},
                (DIM_PLUGIN_IN, SUITE): {"max": 100, "window": 1},
            })
            await px._rebuild_charge_sets()
            ep_b = px._rate_limiter.get(DIM_ENDPOINT_IN, endpoint_key(SUITE, "ep_a"))
            pin_b = px._rate_limiter.get(DIM_PLUGIN_IN, SUITE)
            if ep_b is None or pin_b is None:
                raise AssertionError("endpoint_in / plugin_in buckets not configured")
            cs = px._rl_endpoint_in.get((SUITE, "ep_a"))
            if cs != [ep_b, pin_b]:
                raise AssertionError(
                    f"endpoint IN-set must be [endpoint_in, plugin_in] (exact "
                    f"objects, pinned order); got {cs!r}"
                )
            # Unconfigured endpoint_in -> the IN-set skips it (only plugin_in).
            self._apply({(DIM_PLUGIN_IN, SUITE): {"max": 100, "window": 1}})
            await px._rebuild_charge_sets()
            pin2 = px._rate_limiter.get(DIM_PLUGIN_IN, SUITE)
            cs2 = px._rl_endpoint_in.get((SUITE, "ep_a"))
            if cs2 != [pin2]:
                raise AssertionError(
                    f"unconfigured endpoint_in must be skipped -> [plugin_in]; got {cs2!r}"
                )
        await rec.run_case("ratelimit.endpoint_in_set", body, **kw)

    async def _case_event_out(self, rec, kw):
        async def body(c):
            px = self._plexus
            self._apply({(DIM_EVENT_OUT, event_key(SUITE, "ev_x")): {"max": 30, "window": 1}})
            await px._rebuild_charge_sets()
            b = px._rate_limiter.get(DIM_EVENT_OUT, event_key(SUITE, "ev_x"))
            stored = px._rl_event_out.get((SUITE, "ev_x"))
            if b is None or stored is not b:
                raise AssertionError(
                    f"event_out bucket must be stored by (plugin, event_id); got {stored!r}"
                )
        await rec.run_case("ratelimit.event_out", body, **kw)

    async def _case_cross_plugin_sub(self, rec, kw):
        async def body(c):
            px = self._plexus
            # TARGET's IN buckets + a Sub-IN limit staged by declared_id. The sub
            # is OWNED by the suite but TARGETS another plugin.
            self._apply(
                {
                    (DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink")): {"max": 10, "window": 1},
                    (DIM_PLUGIN_IN, TARGET): {"max": 50, "window": 1},
                },
                {(SUITE, "xsub"): {"max": 5, "window": 1}},
            )
            await px._rebuild_charge_sets()
            uuid = await self._xsub_uuid()
            sub_b = px._rate_limiter.get(DIM_SUB_IN, uuid)
            ep_b = px._rate_limiter.get(DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink"))
            pin_b = px._rate_limiter.get(DIM_PLUGIN_IN, TARGET)
            if sub_b is None:
                raise AssertionError("declared_id Sub-IN limit did not resolve to a sub_uuid bucket")
            cs = px._rl_sub_in.get(uuid)
            if cs != [sub_b, ep_b, pin_b]:
                raise AssertionError(
                    f"cross-plugin sub IN-set must be [sub_in, TARGET endpoint_in, "
                    f"TARGET plugin_in] (keyed on target, not owner); got {cs!r}"
                )
        await rec.run_case("ratelimit.cross_plugin_sub", body, **kw)

    async def _case_runtime_sub_fallback(self, rec, kw, runtime_subs):
        async def body(c):
            px = self._plexus
            # TARGET buckets configured, NO sub config. A runtime sub (no
            # declared_id) gets no Sub-IN -> IN-set falls back to [endpoint_in,
            # plugin_in]. subscribe_event builds the charge-set on the fly.
            self._apply({
                (DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink")): {"max": 10, "window": 1},
                (DIM_PLUGIN_IN, TARGET): {"max": 50, "window": 1},
            })
            await px._rebuild_charge_sets()
            su = await px.subscribe_event(
                topic="ratelimit/runtime", plugin_name=self.plugin_name,
                plugin_uuid=self.plugin_uuid, target_access_name="sink",
                target_plugin=TARGET, hosts="local",
            )
            runtime_subs.append(su)
            ep_b = px._rate_limiter.get(DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink"))
            pin_b = px._rate_limiter.get(DIM_PLUGIN_IN, TARGET)
            cs = px._rl_sub_in.get(su)
            if cs != [ep_b, pin_b]:
                raise AssertionError(
                    f"runtime sub (no declared_id) IN-set must fall back to "
                    f"[endpoint_in, plugin_in] (no sub_in); got {cs!r}"
                )
            # Teardown: unsubscribe drops the cached charge-set entry.
            await px.unsubscribe_event(su)
            runtime_subs.remove(su)
            if su in px._rl_sub_in:
                raise AssertionError("unsubscribe must drop the sub's charge-set entry")
        await rec.run_case("ratelimit.runtime_sub_fallback", body, **kw)

    async def _case_teardown_sub_bucket(self, rec, kw):
        async def body(c):
            px = self._plexus
            self._apply({}, {})
            # _rl_teardown_sub is gated on _rate_limits_active; force it on for
            # the fabricated bucket below.
            px._rate_limits_active = True
            px._rate_limiter.configure(DIM_SUB_IN, "fake-uuid", 5, 1)
            px._rl_sub_in["fake-uuid"] = [px._rate_limiter.get(DIM_SUB_IN, "fake-uuid")]
            px._rl_teardown_sub("fake-uuid")
            if px._rate_limiter.get(DIM_SUB_IN, "fake-uuid") is not None:
                raise AssertionError("teardown must remove the Sub-IN bucket")
            if "fake-uuid" in px._rl_sub_in:
                raise AssertionError("teardown must drop the cached charge-set entry")
        await rec.run_case("ratelimit.teardown_sub_bucket", body, **kw)

    async def _case_empty_config(self, rec, kw):
        async def body(c):
            px = self._plexus
            self._apply({}, {})
            await px._rebuild_charge_sets()
            if (px._rl_endpoint_in or px._rl_sub_in or px._rl_event_out
                    or px._rl_framework_in is not None):
                raise AssertionError("empty config must leave all side-tables empty")
            if px._rate_limits_active:
                raise AssertionError("empty config must leave _rate_limits_active False")
        await rec.run_case("ratelimit.empty_config", body, **kw)

    async def _case_idempotent(self, rec, kw):
        async def body(c):
            px = self._plexus
            self._apply({
                (DIM_ENDPOINT_IN, endpoint_key(SUITE, "ep_a")): {"max": 20, "window": 1},
                (DIM_PLUGIN_IN, SUITE): {"max": 100, "window": 1},
            })
            await px._rebuild_charge_sets()
            n1 = len(px._rl_endpoint_in)
            await px._rebuild_charge_sets()
            n2 = len(px._rl_endpoint_in)
            cs2 = px._rl_endpoint_in.get((SUITE, "ep_a"))
            if n1 != n2:
                raise AssertionError(f"rebuild not idempotent: counts {n1} -> {n2}")
            if len(cs2) != 2:
                raise AssertionError(f"rebuild doubled the IN-set: {cs2!r}")
        await rec.run_case("ratelimit.idempotent", body, **kw)

    async def _case_orphan_prune(self, rec, kw):
        async def body(c):
            px = self._plexus
            # A live plugin's bucket is configured; a bucket for a plugin that is
            # NOT loaded is pre-created as an orphan. The rebuild must prune the
            # orphan (it isn't re-configured) and keep the live one -- so
            # len(limiter), which drives _rate_limits_active, stays honest.
            self._apply({(DIM_PLUGIN_IN, SUITE): {"max": 100, "window": 1}})
            px._rate_limiter.configure(DIM_PLUGIN_IN, "GhostPlugin", 9, 1)
            await px._rebuild_charge_sets()
            if px._rate_limiter.get(DIM_PLUGIN_IN, "GhostPlugin") is not None:
                raise AssertionError(
                    "rebuild must prune a static bucket for a non-existent plugin"
                )
            if px._rate_limiter.get(DIM_PLUGIN_IN, SUITE) is None:
                raise AssertionError("rebuild must keep the live plugin's bucket")
        await rec.run_case("ratelimit.orphan_prune", body, **kw)
