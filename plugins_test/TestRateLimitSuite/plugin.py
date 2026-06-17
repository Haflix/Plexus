"""Rate-limit charge-set precompute (Step 3b) + OUT-admit (Step 3c) suite.

Step 3b proves that ``_rebuild_charge_sets`` attaches the CORRECT precomputed
buckets to the Plexus-owned side-tables, asserting exact ``Bucket`` OBJECT
IDENTITY. Step 3c drives the OUT (attempt) admit END-TO-END through real
``execute()`` / ``publish_event()`` dispatches, proving the wiring: the admit
fires at the dispatch sites, charges the right identity, raises
``RateLimitException``, and is skipped for exempt (lifecycle) frames.

Config is injected directly into ``_rate_limit_config`` /
``_rate_limit_sub_config`` (Step 4 will flatten the YAML ``rate_limits:`` section
into them). Each case starts from a FRESH limiter so prior test buckets don't
leak; ``run`` restores the boot limiter + config + flags in ``finally``. The
OUT cases use a large ``window`` so continuous refill is negligible across a
tight call loop (deterministic, no sleeps).

Cases (3b):
- endpoint_in_set: endpoint IN-set == [endpoint_in, plugin_in]; unconfigured dim skipped.
- event_out: the event_out bucket is stored by (plugin, event_id).
- cross_plugin_sub: a sub owned by the suite but targeting another plugin keys its
  IN-set on the TARGET (+ declared_id -> sub_uuid resolution).
- runtime_sub_fallback: a runtime sub (no declared_id) gets no Sub-IN and its
  charge-set is built on subscribe; unsubscribe tears it down.
- teardown_sub_bucket: _rl_teardown_sub removes the Sub-IN bucket + the entry.
- empty_config: a default node has empty side-tables and _rate_limits_active False.
- idempotent: rebuilding twice does not double the attachments.
- orphan_prune: a static bucket for a non-loaded plugin is pruned on rebuild.

Cases (3c, OUT admit):
- out_self_plugin_out: a self-call charges plugin_out keyed on the in-chain caller;
  rejects the (max+1)th with RateLimitException (raised at the real OUT site).
- out_framework_in: a direct dispatch charges the global framework_in bucket;
  rejects after max (RateLimitException surfaces as its real type to the caller).
- out_event_out: publish_event charges event_out(publisher, event); rejects after max.
- out_lifecycle_exempt: an exempt (lifecycle) caller frame skips the OUT admit even
  when the bucket is dry; a non-exempt frame hits it.
- out_asserted_attribution: an asserted (impersonation) identity wins the charge
  attribution over the chain caller (plugin_out keyed on the asserted name).
"""
import asyncio
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_gen_log_errors, async_log_errors, log_errors  # noqa: E402
from plexus.exceptions import RateLimitException, RequestException  # noqa: E402
from plexus.runtime import CallerIdentity, caller_chain_scope  # noqa: E402
from plexus.ratelimiter import (  # noqa: E402
    RateLimiter, endpoint_key, event_key,
    DIM_PLUGIN_IN, DIM_PLUGIN_OUT, DIM_ENDPOINT_IN, DIM_EVENT_OUT, DIM_SUB_IN,
    DIM_FRAMEWORK_IN, DIM_NODES_IN, FRAMEWORK_IN_KEY,
)

from _test_helpers import CaseRecorder  # noqa: E402

SUITE_VERSION = "0.4.0"
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

    @async_gen_log_errors
    async def ep_stream(self, value: Any = None):
        """Streaming probe (async generator) for the IN stream_weight case. Its
        manifest declares stream_weight=2, so one open costs 2 IN tokens."""
        yield "s1"
        yield "s2"

    @async_log_errors
    async def _rl_drive(self, target: str = None, method: str = None) -> Dict[str, Any]:
        """Perform ONE nested execute so a real caller frame (this suite) exists
        at the OUT admit -- the plugin_out / self-call charge keys on the
        in-chain caller, which only exists one dispatch level deep. Catch the
        RateLimitException HERE (it is raised as its real type at the OUT site,
        before the request is created) and report it; the outer dispatch would
        otherwise re-wrap a handler error as a plain RequestException."""
        try:
            await self.execute(target, method)
            return {"rate_limited": False}
        except RateLimitException as e:
            return {"rate_limited": True, "msg": str(e)}

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
        orig_nodes_cfg = px._rate_limit_nodes_in_config
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
            # Step 3c -- OUT admit (end-to-end through real dispatch).
            await self._case_out_self_plugin_out(rec, kw)
            await self._case_out_framework_in(rec, kw)
            await self._case_out_event_out(rec, kw)
            await self._case_out_lifecycle_exempt(rec, kw)
            await self._case_out_asserted_attribution(rec, kw)
            # Step 3d -- IN admit.
            await self._case_in_endpoint_in(rec, kw)
            await self._case_in_plugin_in(rec, kw)
            await self._case_in_self_plugin_in(rec, kw)
            await self._case_in_sub_in_selection(rec, kw)
            await self._case_in_stream_weight(rec, kw)
            await self._case_in_publish_skip(rec, kw)
            # Step 3e -- Nodes-IN inbound admit (white-box; the end-to-end
            # two-node throttle lives in the remote suite once Step 4 makes the
            # subnode's nodes_in config injectable).
            await self._case_nodes_in_admit(rec, kw)
        finally:
            for su in runtime_subs:
                try:
                    await px.unsubscribe_event(su)
                except Exception:
                    pass
            px._rate_limiter = orig_limiter
            px._rate_limit_config = orig_cfg
            px._rate_limit_sub_config = orig_subcfg
            px._rate_limit_nodes_in_config = orig_nodes_cfg
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

    async def _case_out_self_plugin_out(self, rec, kw):
        async def body(c):
            px = self._plexus
            # plugin_out(SUITE) only; framework_in unconfigured so plugin_out is
            # the sole binding dimension. Large window -> negligible refill.
            self._apply({(DIM_PLUGIN_OUT, SUITE): {"max": 3, "window": 1000}})
            await px._rebuild_charge_sets()
            # Each _rl_drive invocation runs ONE nested self-execute (SUITE.ep_a)
            # whose OUT admit charges plugin_out(SUITE) once. The OUTER dispatch
            # into _rl_drive is charged to the empty run() chain (-> None ->
            # plugin_out skipped), so it does not consume the budget. framework_in
            # is unconfigured, so plugin_out(SUITE) is the ONLY binding dimension.
            # Reaching a {"rate_limited": ...} marker on every iteration also
            # proves the OUTER call is never charged: if it were, the 4th outer
            # dispatch would raise RateLimitException uncaught (before entering
            # _rl_drive) and crash the loop instead of returning a marker.
            results = []
            for _ in range(4):
                m = await self.execute(
                    SUITE, "_rl_drive",
                    args={"target": SUITE, "method": "ep_a"},
                )
                results.append(m["rate_limited"])
            if results != [False, False, False, True]:
                raise AssertionError(
                    f"self-call must charge plugin_out(SUITE) on the in-chain "
                    f"caller and reject the 4th; got {results}"
                )
        await rec.run_case("ratelimit.out_self_plugin_out", body, **kw)

    async def _case_out_framework_in(self, rec, kw):
        async def body(c):
            px = self._plexus
            # framework_in only. The isolation relies on the dispatch being
            # framework-origin: a direct execute from run() has an empty caller
            # chain (-> charged None -> plugin_out skipped), so only the global
            # framework_in bucket binds. The RateLimitException is raised at the
            # OUT site before the request is created, so it reaches this await as
            # its real type (not re-wrapped).
            self._apply({(DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY): {"max": 3, "window": 1000}})
            await px._rebuild_charge_sets()
            oks = 0
            rejected = False
            for _ in range(4):
                try:
                    await self.execute(TARGET, "sink")
                    oks += 1
                except RateLimitException:
                    rejected = True
                    break
            if oks != 3 or not rejected:
                raise AssertionError(
                    f"framework_in must admit 3 then reject the 4th with "
                    f"RateLimitException; oks={oks} rejected={rejected}"
                )
        await rec.run_case("ratelimit.out_framework_in", body, **kw)

    async def _case_out_event_out(self, rec, kw):
        async def body(c):
            px = self._plexus
            # event_out(SUITE, ev_x) only; plugin_out + framework_in unconfigured.
            self._apply({(DIM_EVENT_OUT, event_key(SUITE, "ev_x")): {"max": 3, "window": 1000}})
            await px._rebuild_charge_sets()
            oks = 0
            rejected = False
            for _ in range(4):
                try:
                    await self.publish_event("ev_x", {"n": 1})
                    oks += 1
                except RateLimitException:
                    rejected = True
                    break
            if oks != 3 or not rejected:
                raise AssertionError(
                    f"event_out must admit 3 publishes then reject the 4th; "
                    f"oks={oks} rejected={rejected}"
                )
        await rec.run_case("ratelimit.out_event_out", body, **kw)

    async def _case_out_lifecycle_exempt(self, rec, kw):
        async def body(c):
            px = self._plexus
            # A dry plugin_out(SUITE) bucket: a non-exempt frame hits it, but an
            # exempt (lifecycle-origin) frame must skip the admit entirely. This
            # proves the admit RESPECTS an exempt frame; that the framework
            # actually stamps lifecycle entries exempt=True is proven end-to-end
            # by TestIdentitySuite (identity.lifecycle.exempt). caller_chain_scope
            # here is the same primitive core.py uses at those lifecycle entries.
            self._apply({(DIM_PLUGIN_OUT, SUITE): {"max": 1, "window": 1000}})
            await px._rebuild_charge_sets()
            b = px._rate_limiter.get(DIM_PLUGIN_OUT, SUITE)
            b.tokens = 0.0
            exempt = CallerIdentity(SUITE, self.plugin_uuid, exempt=True)
            with caller_chain_scope(exempt, True):
                dry_exempt = px._rl_admit_out(None, now=time.monotonic())
            charged = CallerIdentity(SUITE, self.plugin_uuid, exempt=False)
            with caller_chain_scope(charged, True):
                dry_charged = px._rl_admit_out(None, now=time.monotonic())
            if dry_exempt is not None:
                raise AssertionError(
                    "an exempt lifecycle frame must skip the OUT admit (no charge)"
                )
            if dry_charged is not b:
                raise AssertionError(
                    "a non-exempt frame must hit the dry plugin_out bucket"
                )
        await rec.run_case("ratelimit.out_lifecycle_exempt", body, **kw)

    async def _case_out_asserted_attribution(self, rec, kw):
        async def body(c):
            px = self._plexus
            # plugin_out keyed on an ASSERTED identity, not the chain caller. The
            # asserted identity must win the attribution (impersonation charges
            # the impersonated name). The impersonated name is NOT a loaded
            # plugin, so _rebuild_charge_sets would never configure (and would
            # prune) its bucket -- configure it directly on a cleared limiter and
            # force the master switch on. framework_in stays None so plugin_out
            # is the sole binding dimension.
            self._apply({})
            await px._rebuild_charge_sets()  # clears side-tables, _rl_framework_in=None
            b = px._rate_limiter.configure(DIM_PLUGIN_OUT, "ImpersonatedX", 1, 1000)
            b.tokens = 0.0
            px._rate_limits_active = True
            asserted = CallerIdentity("ImpersonatedX", "imp-uuid", exempt=False)
            with caller_chain_scope(CallerIdentity(SUITE, self.plugin_uuid), True):
                dry = px._rl_admit_out(asserted, now=time.monotonic())
            if dry is not b:
                raise AssertionError(
                    "impersonation must charge plugin_out(asserted), not the "
                    "chain caller"
                )
            if px._rl_charged_name(asserted) != "ImpersonatedX":
                raise AssertionError("_rl_charged_name must prefer the asserted identity")
            if px._rl_charged_name(None, fallback_name="Pub") != "Pub":
                raise AssertionError("_rl_charged_name must use fallback_name when no assertion")
        await rec.run_case("ratelimit.out_asserted_attribution", body, **kw)

    async def _case_in_endpoint_in(self, rec, kw):
        async def body(c):
            px = self._plexus
            # endpoint_in(TARGET:sink) only. A direct execute(TARGET, sink) charges
            # the IN-set at _call_endpoint (endpoint_in + plugin_in; plugin_in
            # unconfigured -> skipped). The IN reject is raised at _call_endpoint
            # and caught by _process_request, which stringifies it into the
            # request error -> the caller sees a plain RequestException, NOT
            # RateLimitException (the documented IN-local degrade).
            self._apply({
                (DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink")): {"max": 3, "window": 1000},
            })
            await px._rebuild_charge_sets()
            oks = 0
            outcome = None
            for _ in range(4):
                try:
                    await self.execute(TARGET, "sink")
                    oks += 1
                except RateLimitException:
                    outcome = "ratelimit"  # must NOT happen on the IN-local path
                    break
                except RequestException as e:
                    outcome = "req" if "endpoint_in" in str(e) else f"req?{e}"
                    break
            if oks != 3 or outcome != "req":
                raise AssertionError(
                    f"endpoint_in must admit 3 then reject the 4th as a plain "
                    f"RequestException naming endpoint_in; oks={oks} outcome={outcome!r}"
                )
        await rec.run_case("ratelimit.in_endpoint_in", body, **kw)

    async def _case_in_plugin_in(self, rec, kw):
        async def body(c):
            px = self._plexus
            # plugin_in(TARGET) only; endpoint_in skipped -> plugin_in is the sole
            # binding IN dimension.
            self._apply({(DIM_PLUGIN_IN, TARGET): {"max": 3, "window": 1000}})
            await px._rebuild_charge_sets()
            oks = 0
            named = False
            for _ in range(4):
                try:
                    await self.execute(TARGET, "sink")
                    oks += 1
                except RequestException as e:
                    named = "plugin_in" in str(e)
                    break
            if oks != 3 or not named:
                raise AssertionError(
                    f"plugin_in must admit 3 then reject naming plugin_in; "
                    f"oks={oks} named={named}"
                )
        await rec.run_case("ratelimit.in_plugin_in", body, **kw)

    async def _case_in_self_plugin_in(self, rec, kw):
        async def body(c):
            px = self._plexus
            # Section 4 self-call: a plugin executing its OWN endpoint charges
            # plugin_out(P) at OUT (proven in 3c) AND plugin_in(P) at IN. Here a
            # direct execute(SUITE, ep_a) targets the suite itself; with only
            # plugin_in(SUITE) configured, the IN admit binds on it.
            self._apply({(DIM_PLUGIN_IN, SUITE): {"max": 3, "window": 1000}})
            await px._rebuild_charge_sets()
            oks = 0
            named = False
            for _ in range(4):
                try:
                    await self.execute(SUITE, "ep_a")
                    oks += 1
                except RequestException as e:
                    named = "plugin_in" in str(e)
                    break
            if oks != 3 or not named:
                raise AssertionError(
                    f"self-call must charge plugin_in(SUITE) at IN and reject the "
                    f"4th; oks={oks} named={named}"
                )
        await rec.run_case("ratelimit.in_self_plugin_in", body, **kw)

    async def _case_in_sub_in_selection(self, rec, kw):
        async def body(c):
            px = self._plexus
            # _rl_admit_in must select the SUB IN-set (_rl_sub_in[sub_uuid]) when a
            # sub_uuid is given, and the ENDPOINT IN-set otherwise. Drive the helper
            # directly (driving a real sub fan-out end-to-end needs a publisher
            # event whose topic matches the sub; the publish-1:N skip itself rides
            # the existing fire-and-forget swallow). Build a sub via the declared
            # xsub + a tight sub_in, then assert the charge-set selection + that a
            # dry sub_in binds, while an exempt frame skips.
            self._apply(
                {
                    (DIM_ENDPOINT_IN, endpoint_key(TARGET, "sink")): {"max": 50, "window": 1000},
                    (DIM_PLUGIN_IN, TARGET): {"max": 50, "window": 1000},
                },
                {(SUITE, "xsub"): {"max": 1, "window": 1000}},
            )
            await px._rebuild_charge_sets()
            uuid = await self._xsub_uuid()
            sub_b = px._rate_limiter.get(DIM_SUB_IN, uuid)
            if sub_b is None:
                raise AssertionError("sub_in bucket not configured for xsub")
            # sub_uuid path -> sub IN-set; drain the tight sub_in and expect a dry
            # bucket that IS the sub_in bucket.
            d1 = px._rl_admit_in(TARGET, "sink", uuid, 1.0, None)   # admits (1->0)
            d2 = px._rl_admit_in(TARGET, "sink", uuid, 1.0, None)   # sub_in dry
            if d1 is not None or d2 is not sub_b:
                raise AssertionError(
                    f"sub_uuid must select the sub IN-set and bind on sub_in; "
                    f"d1={d1!r} d2={d2!r}"
                )
            # sub_uuid=None -> endpoint IN-set (endpoint_in+plugin_in, both large)
            # -> admits.
            if px._rl_admit_in(TARGET, "sink", None, 1.0, None) is not None:
                raise AssertionError("endpoint IN-set (no sub_uuid) should admit")
            # exempt frame -> skip regardless of dry sub_in.
            from plexus.runtime import CallerIdentity, caller_chain_scope
            with caller_chain_scope(CallerIdentity(SUITE, self.plugin_uuid, exempt=True), True):
                if px._rl_admit_in(TARGET, "sink", uuid, 1.0, None) is not None:
                    raise AssertionError("an exempt frame must skip the IN admit")
        await rec.run_case("ratelimit.in_sub_in_selection", body, **kw)

    async def _case_in_stream_weight(self, rec, kw):
        async def body(c):
            px = self._plexus
            # ep_stream declares stream_weight=2. With endpoint_in(SUITE:ep_stream)
            # max=2, one stream open costs 2 (drains to 0) and the next open is
            # IN-rejected at _process_request_stream -> the gen-request resolves
            # with an error -> consuming raises a RequestException naming
            # endpoint_in. Proves the stream IN site + cost=stream_weight.
            self._apply({
                (DIM_ENDPOINT_IN, endpoint_key(SUITE, "ep_stream")): {"max": 2, "window": 1000},
            })
            await px._rebuild_charge_sets()
            # first open admits (cost 2 -> 0) and yields.
            chunks = []
            async for x in self.execute_stream(SUITE, "ep_stream"):
                chunks.append(x)
            if chunks != ["s1", "s2"]:
                raise AssertionError(f"first stream open should yield fully; got {chunks}")
            # second open: cost 2, bucket 0 -> reject before the first chunk.
            named = False
            try:
                async for _ in self.execute_stream(SUITE, "ep_stream"):
                    pass
            except RequestException as e:
                named = "endpoint_in" in str(e)
            if not named:
                raise AssertionError(
                    "second stream open must reject (cost=stream_weight=2 vs 0 "
                    "tokens) naming endpoint_in"
                )
        await rec.run_case("ratelimit.in_stream_weight", body, **kw)

    async def _case_in_publish_skip(self, rec, kw):
        async def body(c):
            px = self._plexus
            # End-to-end 1:N fan-out skip: publishing ev_sub (topic matches the
            # declared xsub sub) fans out to TestRateLimitTarget.sink. With a tight
            # sub_in(SUITE,xsub) the FIRST delivery lands and the SECOND is
            # IN-rejected at _call_endpoint -> the per-sub fire-and-forget Request
            # errors and is SWALLOWED (publish still returns its scheduled count;
            # the handler is NOT invoked for the throttled delivery). This also
            # pins the origin_sub_uuid wiring: the fan-out must stamp sub.sub_uuid
            # for the sub IN-set lookup to bind.
            target = px.plugins.get(TARGET)
            target._sink_calls = 0
            # sub_in(xsub) only -> the sub IN-set is [sub_in] (endpoint_in /
            # plugin_in unconfigured -> skipped). max=1: one delivery, then dry.
            self._apply({}, {(SUITE, "xsub"): {"max": 1, "window": 1000}})
            await px._rebuild_charge_sets()

            async def _wait_until(pred, ticks):
                for _ in range(ticks):
                    if pred():
                        return True
                    await asyncio.sleep(0.005)
                return pred()

            n1 = await self.publish_event("ev_sub", {"n": 1})
            # Let the first fan-out delivery land (sink_calls -> 1).
            await _wait_until(lambda: target._sink_calls >= 1, 200)
            n2 = await self.publish_event("ev_sub", {"n": 2})
            # Give the second delivery a chance to (NOT) land; it must stay at 1.
            await _wait_until(lambda: target._sink_calls >= 2, 60)

            if target._sink_calls != 1:
                raise AssertionError(
                    f"the IN-throttled second sub delivery must be skipped "
                    f"(handler not invoked); sink_calls={target._sink_calls}"
                )
            if n1 != 1 or n2 != 1:
                raise AssertionError(
                    f"publish must return its SCHEDULED count (1 matched sub) "
                    f"regardless of the per-sub IN reject; n1={n1} n2={n2}"
                )
        await rec.run_case("ratelimit.in_publish_skip", body, **kw)

    async def _case_nodes_in_admit(self, rec, kw):
        async def body(c):
            px = self._plexus
            # White-box exercise of _rl_admit_inbound (the networking inbound
            # admit). Drives the helper directly: a real two-node throttle (the
            # handlers calling it) lives in the remote suite -- the subnode is a
            # separate process whose nodes_in config is not injectable until
            # Step 4's YAML plumbing lands. Start from a fresh limiter; the
            # sideband + framework_in are restored by run()'s finally.
            px._rate_limiter = RateLimiter()
            px._rate_limit_config = {}
            px._rate_limit_sub_config = {}
            px._rate_limit_nodes_in_config = {
                "default": {"max": 2, "window": 1000},
                "peerB": {"max": 1, "window": 1000},   # per-peer override
            }
            # framework_in for the include_framework path.
            px._rate_limit_config = {(DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY): {"max": 3, "window": 1000}}
            await px._rebuild_charge_sets()  # builds _rl_framework_in
            now = time.monotonic()

            # peer=None -> no-op (defensive direct-call path).
            if px._rl_admit_inbound(None, False, now) is not None:
                raise AssertionError("peer=None must no-op the Nodes-IN admit")

            # Lazy get-or-create from "default" (max 2) for peerA; 3rd rejects.
            r1 = px._rl_admit_inbound("peerA", False, now)
            r2 = px._rl_admit_inbound("peerA", False, now)
            nb_a = px._rate_limiter.get(DIM_NODES_IN, "peerA")
            r3 = px._rl_admit_inbound("peerA", False, now)
            if nb_a is None:
                raise AssertionError("first contact must lazily create the peer bucket")
            if r1 is not None or r2 is not None or r3 is not nb_a:
                raise AssertionError(
                    f"default max=2 -> admit 2 then reject on nodes_in(peerA); "
                    f"r1={r1!r} r2={r2!r} r3={r3!r}"
                )

            # Per-peer ISOLATION + override: peerB has its own bucket (override
            # max=1), unaffected by peerA being dry.
            rb1 = px._rl_admit_inbound("peerB", False, now)
            rb2 = px._rl_admit_inbound("peerB", False, now)
            nb_b = px._rate_limiter.get(DIM_NODES_IN, "peerB")
            if rb1 is not None or rb2 is not nb_b:
                raise AssertionError(
                    f"peerB override max=1 -> admit 1 then reject; isolated from "
                    f"peerA; rb1={rb1!r} rb2={rb2!r}"
                )
            if nb_b is nb_a:
                raise AssertionError("each peer must get a DISTINCT Nodes-IN bucket")

            # include_framework=True -> atomic [nodes_in, framework_in]. Drain
            # framework_in (max 3) via a fresh peer so nodes_in is not the binder.
            fb = px._rl_framework_in
            if fb is None:
                raise AssertionError("framework_in bucket must be built")
            fb.tokens = 0.0  # force framework_in dry
            dry = px._rl_admit_inbound("peerC", True, now)
            loc = px._rate_limiter.locate(dry) if dry is not None else None
            if dry is not fb:
                raise AssertionError(
                    f"include_framework must charge framework_in; bound bucket "
                    f"should be framework_in, got loc={loc!r}"
                )

            # Empty sideband -> no-op (zero-overhead-off for Nodes-IN).
            px._rate_limiter = RateLimiter()
            px._rate_limit_nodes_in_config = {}
            px._rate_limit_config = {}
            await px._rebuild_charge_sets()
            if px._rl_admit_inbound("peerA", True, now) is not None:
                raise AssertionError("empty nodes_in + no framework_in must no-op")
        await rec.run_case("ratelimit.nodes_in_admit", body, **kw)
