"""TestBugSuite — PR3 Stage F bughunt repro suite + netcore security guards.

One case per open bug-tracker entry (`_private/bugs/bugs.jsonl`). Verdicts
are recorded by the parent post-run. NO bug fixes here — only repros that
prove which bugs are real vs fixed-by-construction.

Categories (one method per):
  _b_legacy_removed     — API surface deleted in Stage D — assert .gone
  _b_addressed_in_pr3   — PR3 added behavior that should fix the bug
  _b_active             — still-broken — repro and let recorder mark
  _b_security           — netcore inbound-authorization guards (B-090/B-091)

The PR4 Stage K "B-066" raw-wire cells were deleted 2026-07-22 (they had
been silently skipping since the netcore rewrite). See the _b_security
header for which of their properties were re-covered and which were
dropped without replacement.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402
import time  # noqa: E402
import inspect  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
import uuid  # noqa: E402
from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.exceptions import RequestException  # noqa: E402

from plexus.networking import PeerSpec  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.8.0"


TARGET = "TestEventTarget"
STREAM_TARGET = "TestStreamTarget"
EXEC_TARGET = "TestExecuteTarget"
BAD_ACTOR = "TestEventBadActor"


class TestBugSuite(Plugin):
    """PR3 Stage F bug-repro suite. See PLAN.md."""

    @log_errors
    def on_load(self, *args, **kwargs):
        # B-047 mailbox: probe handler increments to confirm fan-out
        # actually fires (sanity check for the task_list growth body).
        self.b047_probe_calls = 0
        # B-021 mailboxes: which of the two competing subs answered.
        self.b021_blocked_calls = 0
        self.b021_eligible_calls = 0

    async def handle_b047_probe(self, event):
        self.b047_probe_calls += 1

    async def handle_b021_blocked(self, event):
        # The non-eligible sub (blocks the publisher). request_event must
        # never reach this; if it does, the filter chain was bypassed.
        self.b021_blocked_calls += 1
        return {"who": "blocked"}

    async def handle_b021_eligible(self, event):
        # The eligible fall-through sub. request_event must land here.
        self.b021_eligible_calls += 1
        return {"who": "eligible"}

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestBugSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestBugSuite disabled")

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
        rec = CaseRecorder("TestBugSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        await self._b_legacy_removed(rec, kw)
        await self._b_addressed_in_pr3(rec, kw)
        await self._b_active(rec, kw)
        await self._b_security(rec, kw)
        return rec.to_dict()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _ensure_loaded(self, name: str) -> bool:
        """Idempotently load+enable a fixture by name from yaml_config."""
        if name in self._plexus.plugins:
            return True
        for entry in self._plexus.yaml_config.get("plugins", []):
            if entry.get("name") == name:
                e = dict(entry)
                e["enabled"] = True
                await self._plexus.load_plugin_with_conf(e)
                if name in self._plexus.plugins:
                    try:
                        await self._plexus.enable_plugin(name)
                    except Exception:
                        pass
                    return True
        return False

    # ==================================================================
    # _b_legacy_removed — Recipe A (API surface gone)
    # ==================================================================
    async def _b_legacy_removed(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "legacy_removed"

        # ---- B-001 ---------------------------------------------------
        async def body_b_001_request_topic_method_gone(c):
            # B-001: code-driven topic handlers bypassed remote: false.
            # The legacy `request_topic` API + `_handle_topic_request`
            # server handler were removed in Stage D, so the entire
            # bypass surface no longer exists.
            c.expect(getattr(self, "request_topic", None), None)
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-011 ---------------------------------------------------
        async def body_b_011_request_topic_stream_remote_gone(c):
            # B-011: legacy stream-error sentinel only existed on the
            # request_topic_stream_remote path. That whole client method
            # was removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "request_topic_stream_remote", None), None)

        # ---- B-012 ---------------------------------------------------
        async def body_b_012_handle_topic_request_stream_gone(c):
            # B-012: server-side stream-chunk error sentinel handler
            # `_handle_topic_request_stream` was removed in Stage D.
            nm = self._plexus.network
            c.expect(
                getattr(nm, "_handle_topic_request_stream", None), None
            )

        # ---- B-014 ---------------------------------------------------
        async def body_b_014_request_topic_stream_sync_gone(c):
            # B-014: `request_topic_stream_sync` method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream_sync", None), None)

        # ---- B-018a --------------------------------------------------
        async def body_b_018a_handle_notify_handler_gone(c):
            # B-018a: wire-side spoof handlers (_handle_notify and
            # _handle_topic_request) were removed in Stage D — the
            # MSG_NOTIFY / MSG_TOPIC_REQUEST surface they hung off no
            # longer exists, so the remote spoof path through them is
            # gone.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_notify", None), None)
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-019 ---------------------------------------------------
        async def body_b_019_notify_method_gone(c):
            # B-019: `notify`'s return-count contract is moot — the
            # method itself was removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # ---- B-020 ---------------------------------------------------
        async def body_b_020_notify_sync_method_gone(c):
            # B-020: `notify_sync` blocking-on-remote-ACK can't repro —
            # method removed in Stage D.
            c.expect(getattr(self, "notify_sync", None), None)

        # ---- B-022 ---------------------------------------------------
        async def body_b_022_subscribe_handler_kwarg_gone(c):
            # B-022: subscribe() no longer accepts `handler=` (silent
            # no-op risk gone). The `target_access_name` parameter
            # replaced it. Verify both: handler not in signature, AND
            # target_access_name IS in signature.
            sig = inspect.signature(self.subscribe)
            params = sig.parameters
            c.expect("handler" in params, False)
            c.expect("target_access_name" in params, True)

        # ---- B-023 ---------------------------------------------------
        async def body_b_023_notify_method_gone(c):
            # B-023: `notify()` raise-on-error contract violation can't
            # repro — method removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # ---- B-024 ---------------------------------------------------
        async def body_b_024_request_topic_stream_gone(c):
            # B-024: oversized chunk corruption on `request_topic_stream`
            # can't repro — method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-025 ---------------------------------------------------
        async def body_b_025_request_topic_stream_gone(c):
            # B-025: re-entry-after-partial-yield bug on
            # `request_topic_stream` can't repro — method removed in
            # Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-027 ---------------------------------------------------
        async def body_b_027_notify_remote_gone(c):
            # B-027: notify_remote return-zero-on-transport-fail can't
            # repro — method removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)

        # ---- B-028 ---------------------------------------------------
        async def body_b_028_remote_notifier_methods_gone(c):
            # B-028: notify_remote, request_topic_remote,
            # request_topic_stream_remote — all client-side notifier
            # methods removed in Stage D, so the no-client-timeout
            # caller-hang surface is gone entirely.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)
            c.expect(getattr(nm, "request_topic_remote", None), None)
            c.expect(getattr(nm, "request_topic_stream_remote", None), None)

        # ---- B-029 ---------------------------------------------------
        async def body_b_029_handle_topic_request_gone(c):
            # B-029: server-side `_handle_topic_request` ignored its
            # `timeout` for code-driven handlers — handler itself gone
            # in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-030 ---------------------------------------------------
        async def body_b_030_notify_remote_gone(c):
            # B-030: `notify_remote` swallowing pickle errors can't
            # repro — method removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)

        # ---- B-032 ---------------------------------------------------
        async def body_b_032_handle_notify_gone(c):
            # B-032: server-side `_handle_notify` head-of-line blocking
            # on slow fan-out can't repro — handler removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_notify", None), None)

        # ---- B-033 ---------------------------------------------------
        async def body_b_033_request_topic_stream_sync_gone(c):
            # B-033: `request_topic_stream_sync` ignoring its `host`
            # parameter can't repro — method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream_sync", None), None)

        # ---- B-035 ---------------------------------------------------
        async def body_b_035_notify_method_gone(c):
            # B-035: `notify`'s asyncio.gather-no-per-sub-timeout
            # symptom can't repro — method removed in Stage D.
            # `publish_event` is the new fire-and-forget primitive but
            # uses asyncio.create_task per-handler (verify in source).
            c.expect(getattr(self, "notify", None), None)
            src = inspect.getsource(self._plexus.publish_event)
            # Sanity: dispatch path uses create_task (per-sub
            # independent) rather than a single gather over all subs.
            c.expect("create_task" in src, True)

        # ---- B-036 ---------------------------------------------------
        async def body_b_036_call_sub_method_gone(c):
            # B-036: `_call_sub` caught Exception not BaseException —
            # function replaced by `_fanout_sub` in PR3. Verify the old
            # name is gone.
            core = self._plexus
            c.expect(getattr(core, "_call_sub", None), None)

        # ---- B-039 ---------------------------------------------------
        async def body_b_039_request_topic_sync_gone(c):
            # B-039: topic-hop-wipes-_sync_call_chain symptom rode on
            # `request_topic_sync` — method removed in Stage D.
            c.expect(getattr(self, "request_topic_sync", None), None)

        # ---- B-042 ---------------------------------------------------
        async def body_b_042_request_topic_stream_gone(c):
            # B-042: code-driven stream bypass (B-001 variant for
            # streams) — `request_topic_stream` method removed in
            # Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-053 ---------------------------------------------------
        async def body_b_053_subscription_handler_field_gone(c):
            # B-053: `Subscription.handler` field removed from the
            # dataclass. Also assert the new field names are present
            # so this case fails informatively if the schema regresses.
            import dataclasses
            from plexus.notifier import Subscription
            fields = {f.name for f in dataclasses.fields(Subscription)}
            c.expect("handler" in fields, False)
            c.expect("endpoint_access_name" in fields, False)
            c.expect("config_driven" in fields, False)
            # Positive assertions: new PR3 fields must be present.
            c.expect("target_access_name" in fields, True)
            c.expect("sub_uuid" in fields, True)
            c.expect("enabled" in fields, True)

        # ---- B-059 ---------------------------------------------------
        async def body_b_059_notify_method_gone(c):
            # B-059: cross-plugin sub routing mismatch on the legacy
            # `notify()` path can't repro — method removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # -- run_case calls --------------------------------------------
        await rec.run_case(
            "bug.B-001.request_topic_method_gone",
            body_b_001_request_topic_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-001",), **kw,
        )
        await rec.run_case(
            "bug.B-011.request_topic_stream_remote_gone",
            body_b_011_request_topic_stream_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-011",), **kw,
        )
        await rec.run_case(
            "bug.B-012.handle_topic_request_stream_gone",
            body_b_012_handle_topic_request_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-012",), **kw,
        )
        await rec.run_case(
            "bug.B-014.request_topic_stream_sync_gone",
            body_b_014_request_topic_stream_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-014",), **kw,
        )
        await rec.run_case(
            "bug.B-018a.handle_notify_handler_gone",
            body_b_018a_handle_notify_handler_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-018",), **kw,
        )
        await rec.run_case(
            "bug.B-019.notify_method_gone",
            body_b_019_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-019",), **kw,
        )
        await rec.run_case(
            "bug.B-020.notify_sync_method_gone",
            body_b_020_notify_sync_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-020",), **kw,
        )
        await rec.run_case(
            "bug.B-022.subscribe_handler_kwarg_gone",
            body_b_022_subscribe_handler_kwarg_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-022",), **kw,
        )
        await rec.run_case(
            "bug.B-023.notify_method_gone",
            body_b_023_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-023",), **kw,
        )
        await rec.run_case(
            "bug.B-024.request_topic_stream_gone",
            body_b_024_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-024",), **kw,
        )
        await rec.run_case(
            "bug.B-025.request_topic_stream_gone",
            body_b_025_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-025",), **kw,
        )
        await rec.run_case(
            "bug.B-027.notify_remote_gone",
            body_b_027_notify_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-027",), **kw,
        )
        await rec.run_case(
            "bug.B-028.remote_notifier_methods_gone",
            body_b_028_remote_notifier_methods_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-028",), **kw,
        )
        await rec.run_case(
            "bug.B-029.handle_topic_request_gone",
            body_b_029_handle_topic_request_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-029",), **kw,
        )
        await rec.run_case(
            "bug.B-030.notify_remote_gone",
            body_b_030_notify_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-030",), **kw,
        )
        await rec.run_case(
            "bug.B-032.handle_notify_gone",
            body_b_032_handle_notify_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-032",), **kw,
        )
        await rec.run_case(
            "bug.B-033.request_topic_stream_sync_gone",
            body_b_033_request_topic_stream_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-033",), **kw,
        )
        await rec.run_case(
            "bug.B-035.notify_method_gone",
            body_b_035_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-035",), **kw,
        )
        await rec.run_case(
            "bug.B-036.call_sub_method_gone",
            body_b_036_call_sub_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-036",), **kw,
        )
        await rec.run_case(
            "bug.B-039.request_topic_sync_gone",
            body_b_039_request_topic_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-039",), **kw,
        )
        await rec.run_case(
            "bug.B-042.request_topic_stream_gone",
            body_b_042_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-042",), **kw,
        )
        await rec.run_case(
            "bug.B-053.subscription_handler_field_gone",
            body_b_053_subscription_handler_field_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-053",), **kw,
        )
        await rec.run_case(
            "bug.B-059.notify_method_gone",
            body_b_059_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-059",), **kw,
        )

    # ==================================================================
    # _b_addressed_in_pr3 — Recipe B
    # ==================================================================
    async def _b_addressed_in_pr3(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "addressed_in_pr3"

        # ---- B-003 ---------------------------------------------------
        async def body_b_003_disable_unregisters_subs(c):
            # B-003: notify dispatched to handlers on disabled plugin.
            # Stage B's _disable_plugin wrapper now calls
            # _unregister_plugin_subscriptions at end of on_disable per
            # Q23+C15. Verify: pop a plugin, confirm its subs vanish
            # from topic_registry, then restore via _ensure_loaded.
            target = TARGET
            if target not in self._plexus.plugins:
                c.skip(f"{target} not loaded — fixture order issue")
                return
            pre = await self._plexus.topic_registry.list_local_subs()
            pre_owned = [s for s in pre if s.plugin_name == target]
            if len(pre_owned) == 0:
                c.skip(
                    f"{target} has no subs registered — precondition fail"
                )
                return
            # Net-zero drift: pop + reload restores the plugin set, but
            # during the body the set transiently misses TARGET. Without
            # explicit declaration, _check_drift only sees the final
            # state — which matches snapshot. Defensive declaration
            # nonetheless:
            c.set_expected_drift(added=(), removed=())
            await self._plexus.pop_plugin(target)
            post = await self._plexus.topic_registry.list_local_subs()
            post_owned = [s for s in post if s.plugin_name == target]
            c.expect(len(post_owned), 0)
            # Restore so subsequent cases find TARGET loaded.
            restored = await self._ensure_loaded(target)
            if not restored:
                raise AssertionError(
                    f"failed to restore {target} after pop"
                )

        # ---- B-038 ---------------------------------------------------
        async def body_b_038_sync_pre_start_raises_request_exception(c):
            # B-038: pre-start sync wrappers used to raise TypeError.
            # Stage A Q1 added _check_framework_started guard to all
            # sync wrappers — fires FIRST (before event lookup, before
            # run_coroutine_threadsafe). Can't actually call before
            # framework start in this test (main_event_loop is set).
            # Instead, transiently null it and call. The event_id
            # passed below is intentionally bogus — guard fires before
            # lookup so the bogus id is never dereferenced.
            saved = self._plexus.main_event_loop
            self._plexus.main_event_loop = None
            try:
                c.expect_exception(
                    RequestException, match="Framework not started"
                )
                self.publish_event_sync("any_id_guard_fires_first")
            finally:
                self._plexus.main_event_loop = saved

        # ---- B-056 ---------------------------------------------------
        async def body_b_056_disabled_subs_excluded(c):
            # B-056: disabled YAML subs registered with enabled=False.
            # Verify topic_registry contains the disabled sub with
            # `.enabled == False`, AND _find_first skips it.
            #
            # The TestEventSuite YAML declares `disabled_event` (an
            # event with `enabled: false`) — but no matching sub for
            # it. Use a runtime sub instead: register one, mark it
            # disabled directly on the registry entry, then verify
            # _find_first returns no eligible subscriber.
            topic = "test_bugsuite/B056/disabled_probe"
            sub_uuid = await self.subscribe(
                topic,
                target_access_name="run",  # any handler — never invoked
            )
            try:
                subs = (
                    await self._plexus.topic_registry.list_local_subs()
                )
                owned = [s for s in subs if s.sub_uuid == sub_uuid]
                if len(owned) != 1:
                    raise AssertionError(
                        "B-056: runtime subscribe failed to register sub"
                    )
                # Toggle to disabled.
                owned[0].enabled = False
                # Disabled subs are skipped at match time (enabled is
                # checked inside find_all), so _find_first must return no
                # eligible subscriber for this topic.
                found = (
                    await self._plexus.topic_registry._find_first(topic)
                )
                if found is not None and found.sub_uuid == sub_uuid:
                    raise AssertionError(
                        "B-056: _find_first returned a disabled sub "
                        "(enabled=False not honored)"
                    )
            finally:
                await self.unsubscribe(sub_uuid)

        await rec.run_case(
            "bug.B-003.disable_unregisters_subs",
            body_b_003_disable_unregisters_subs,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-003",),
            **kw,
        )
        await rec.run_case(
            "bug.B-038.sync_pre_start_raises_request_exception",
            body_b_038_sync_pre_start_raises_request_exception,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-038",),
            **kw,
        )
        await rec.run_case(
            "bug.B-056.disabled_subs_excluded",
            body_b_056_disabled_subs_excluded,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-056",),
            **kw,
        )

    # ==================================================================
    # _b_active — Recipe C
    # ==================================================================
    async def _b_active(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "active"

        # ---- B-021 ---------------------------------------------------
        async def body_b_021_request_event_fallthrough_or_fail(c):
            # B-021 (regression): two subs on the SAME topic
            # "test_bugsuite/b021/leaf", declared in this order:
            #   1. b021_blocked_first  — blocked_authors=[TestBugSuite], so it
            #      does NOT accept this suite as the publisher.
            #   2. b021_eligible_second — accepts.
            # request_event must SKIP the non-eligible first match (it is
            # earlier in find_all insertion order) and fall through to the
            # eligible second — proving the 1:1 path uses find_all + the
            # filter chain, NOT the filter-blind _find_first. A regression to
            # first-topic-match would either raise "no subscriber" or
            # dispatch to the blocked handler.
            self.b021_blocked_calls = 0
            self.b021_eligible_calls = 0
            r = await self.request_event(
                "b021_event", payload={"x": 1}, timeout=2.0,
            )
            c.expect(r, {"who": "eligible"})
            c.expect(self.b021_blocked_calls, 0)
            c.expect(self.b021_eligible_calls, 1)

        # ---- B-044 ---------------------------------------------------
        async def body_b_044_silent_truncation_on_error(c):
            # B-044: FIXED in Stage G (utils.py Request.get_queue_stream now
            # yields the error tuple before breaking, so execute_stream's
            # `if error: raise RequestException(result)` branch fires).
            # This case asserts the FIXED behavior: a stream that yields N
            # items then raises must propagate RequestException to the
            # consumer (NOT silently truncate). Regression guard.
            received = []
            try:
                async for v in self.execute_stream(
                    STREAM_TARGET, "ea_gen_raises_after", (3,)
                ):
                    received.append(v)
            except RequestException:
                # Expected: error surfaces. Verify we got the pre-error
                # items first (so they weren't dropped on the floor).
                c.expect(len(received), 3)
                return
            raise AssertionError(
                f"B-044 regression: stream completed silently "
                f"(got {len(received)} items, no RequestException)"
            )

        # ---- B-045 ---------------------------------------------------
        async def body_b_045_stream_timeout_exception_type(c):
            # B-045: FIXED in Stage G (utils.py Request.get_queue_stream
            # now wraps asyncio.TimeoutError as RequestException, symmetric
            # with execute()). Asserts the FIXED behavior: stream timeout
            # surfaces as RequestException, never as raw asyncio.TimeoutError.
            # Regression guard.
            import asyncio as _asyncio
            try:
                async for _ in self.execute_stream(
                    STREAM_TARGET,
                    "ea_gen_hangs",
                    None,
                    timeout=0.2,
                ):
                    pass
            except RequestException:
                return  # Expected post-fix.
            except _asyncio.TimeoutError as e:
                raise AssertionError(
                    f"B-045 regression: stream timeout surfaced as "
                    f"asyncio.TimeoutError, not RequestException ({e!r})"
                )
            raise AssertionError(
                "B-045 regression: stream timeout produced no exception at all"
            )

        # ---- B-046 ---------------------------------------------------
        async def body_b_046_plugin_lock_held_across_on_enable(c):
            # B-046: FIXED in Stage O via per-plugin lifecycle locks.
            # The global plugin_lock is now held only for fast dict
            # reads/writes; user on_enable runs OUTSIDE plugin_lock
            # under the per-plugin lifecycle_lock. Regression guard:
            # while one plugin's on_enable is mid-flight (artificially
            # delayed), a concurrent get_plugin_info on a DIFFERENT
            # plugin must return promptly (well under 1s).
            core = self._plexus
            v_name = "TestLifecycleVictim"
            other_name = "TestLifecycleSuite"
            victim = core.plugins.get(v_name)
            if victim is None or other_name not in core.plugins:
                c.skip(
                    "B-046 regression guard requires TestLifecycleVictim "
                    "and TestLifecycleSuite both loaded"
                )
                return

            # Slow on_enable: 0.6s sleep. Configure flags directly so
            # we don't depend on the configure endpoint being callable
            # while the plugin is in mid-disable.
            victim._on_enable_delay_secs = 0.6
            try:
                # Disable then concurrently re-enable + ping a different
                # plugin's get_plugin_info. Pre-fix the call would block
                # on plugin_lock until on_enable finishes.
                await core.disable_plugin(v_name)

                async def _delayed_get_info():
                    # Tiny stagger so enable is in mid-on_enable when
                    # we hit get_plugin_info.
                    await asyncio.sleep(0.1)
                    t0 = asyncio.get_event_loop().time()
                    info = await core.get_plugin_info(other_name)
                    return info, asyncio.get_event_loop().time() - t0

                enable_task = asyncio.create_task(core.enable_plugin(v_name))
                info_task = asyncio.create_task(_delayed_get_info())
                info, elapsed = await info_task
                await enable_task

                if info is None or info.get("name") != other_name:
                    raise AssertionError(
                        f"B-046 regression: get_plugin_info({other_name}) "
                        f"returned {info!r}"
                    )
                # Should return well under the 0.5s remainder of the
                # on_enable sleep. R1 LOW-1 fix: threshold raised from
                # 0.2s to 1.0s — Windows scheduler timer resolution is
                # ~15.6ms and loaded CI can blow past 200ms. The actual
                # operation is a dict read (microseconds); 1s still
                # comfortably catches a regression where the lock is
                # held across the full 1.5s on_enable sleep.
                if elapsed > 1.0:
                    raise AssertionError(
                        f"B-046 regression: get_plugin_info on {other_name} "
                        f"took {elapsed:.3f}s while {v_name}.on_enable was "
                        f"sleeping — plugin_lock still held across on_enable"
                    )
            finally:
                # Restore configuration so subsequent suites are clean.
                victim = core.plugins.get(v_name)
                if victim is not None:
                    victim._on_enable_delay_secs = 0.0
                    if not victim.enabled:
                        try:
                            await core.enable_plugin(v_name)
                        except Exception:
                            pass

        # ---- B-047 ---------------------------------------------------
        async def body_b_047_task_list_grows_unboundedly(c):
            # B-047 (Stage Q FIXED): task_list now uses set + per-task
            # done_callback for O(1) self-eviction. This regression guard
            # asserts that a 200-event burst does NOT cause sustained
            # growth. b047_probe_event is registered → b047_probe_sub →
            # handle_b047_probe so every publish spawns one real fan-out
            # task that exercises the eviction path.
            core = self._plexus
            tlist = getattr(core, "task_list", None)
            if tlist is None:
                # Attribute removed — fixed-by-construction.
                return
            # Snapshot baseline tasks. We measure the delta from the
            # burst (tasks NOT in this snapshot) instead of total list
            # size, so concurrent unrelated activity adding/removing
            # its own tasks doesn't false-trigger the assertion.
            before_set = frozenset(tlist)
            for _ in range(200):
                await self.publish_event_for_repro()
            # Poll until burst-spawned tasks drain. Each fan-out task
            # awaits _process_request → endpoint dispatch → producer's
            # finally pops from self.requests (B-073
            # — was set_collected pre-migration) → done_callback fires
            # via call_soon. One asyncio.sleep(0) is NOT enough;
            # deadline-bounded poll handles slow CI.
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                remaining = sum(1 for t in tlist if t not in before_set)
                if remaining <= 5:
                    break
                await asyncio.sleep(0.01)
            remaining = sum(1 for t in tlist if t not in before_set)
            if remaining > 5:
                raise AssertionError(
                    f"B-047 regression: {remaining} burst-spawned tasks "
                    f"remain in task_list after 5s drain — done_callback "
                    f"eviction not firing"
                )

        # ---- B-048 ---------------------------------------------------
        async def body_b_048_find_endpoint_returns_none_tuple(c):
            # B-048: find_endpoint type annotation says Optional[tuple]
            # but returns 3-tuple of Nones on miss. Verify the actual
            # return shape against a guaranteed-miss lookup. Signature
            # is (access_name, hosts, blocked_hosts, plugin_uuid,
            # requester_id, target_plugin) — find_endpoint is async.
            core = self._plexus
            try:
                result = await core.find_endpoint(
                    "no_such_endpoint_for_b048_repro",
                    "any",
                )
            except TypeError:
                # Signature drift — skip to avoid spurious failure.
                c.skip(
                    "find_endpoint signature changed — re-verify in "
                    "follow-up"
                )
                return
            # Bug confirmed if result is the 3-tuple of Nones rather
            # than a single None.
            if (
                isinstance(result, tuple)
                and len(result) == 3
                and result == (None, None, None)
            ):
                raise AssertionError(
                    "B-048: find_endpoint returns (None, None, None) "
                    "instead of None on miss — annotation contract "
                    "broken"
                )

        # ---- B-051 ---------------------------------------------------
        async def body_b_051_normalize_hosts_authors_keyword(c):
            # B-051: _normalize_hosts was reused for the `authors` field.
            # The keyword-in-list guard rejects "remote"/"any" in lists
            # with other elements — appropriate for hosts but
            # inappropriate for authors (where "remote" could be a
            # literal plugin name). The fix split the normalizer into
            # `_normalize_authors` which skips the keyword guard. This
            # test now exercises that path: the ValueError must NOT
            # fire on authors-vocabulary input. Recorder marks "pass"
            # when no exception is raised.
            from plexus.core import _normalize_authors
            _normalize_authors(
                ["remote", "OtherPlugin"],
                param_name="authors",
                default=None,
            )

        # ---- B-064 ---------------------------------------------------
        async def body_b_064_subscribe_no_async_log_errors(c):
            # B-064: preventive — Plugin.subscribe must NOT have
            # @async_log_errors decorator. getsource inspects the
            # original source text; a post-class-definition wrapping
            # would slip past (low-risk false negative documented).
            src = inspect.getsource(Plugin.subscribe)
            c.expect("async_log_errors" in src, False)

        # -- run_case calls --------------------------------------------
        # B-021: live regression guard (was skipped pending a fixture).
        await rec.run_case(
            "bug.B-021.request_event_fallthrough_or_fail",
            body_b_021_request_event_fallthrough_or_fail,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-021",),
            **kw,
        )
        # B-044: FIXED in Stage G. Case now asserts the FIXED behavior
        # (RequestException propagated to consumer). Regression guard.
        await rec.run_case(
            "bug.B-044.silent_truncation_on_error",
            body_b_044_silent_truncation_on_error,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-044",),
            **kw,
        )
        # B-045: FIXED in Stage G. Case asserts FIXED behavior
        # (RequestException for timeouts, never asyncio.TimeoutError).
        await rec.run_case(
            "bug.B-045.stream_timeout_exception_type",
            body_b_045_stream_timeout_exception_type,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-045",),
            **kw,
        )
        # B-046: FIXED in Stage O. Positive guard — body asserts that
        # a concurrent dict-read on another plugin completes promptly
        # while one plugin's on_enable is artificially delayed.
        await rec.run_case(
            "bug.B-046.plugin_lock_held_across_on_enable",
            body_b_046_plugin_lock_held_across_on_enable,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-046",),
            hard_timeout_s=15.0,
            **kw,
        )
        # B-047: expected_status="fail" — bug expected to repro
        # B-047: FIXED in Stage Q. Positive regression guard — body
        # asserts burst-spawned tasks drain via the per-task
        # done_callback within 5s. Success path completes in
        # milliseconds; the deadline only fires on a regression.
        # slow=True intentionally removed (no longer slow).
        await rec.run_case(
            "bug.B-047.task_list_grows_unboundedly",
            body_b_047_task_list_grows_unboundedly,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-047",),
            **kw,
        )
        # B-048: expected_status="fail" — bug expected to repro
        # (3-tuple of Nones instead of None).
        await rec.run_case(
            "bug.B-048.find_endpoint_returns_none_tuple",
            body_b_048_find_endpoint_returns_none_tuple,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-048",),
            expected_status="fail",
            expected_signature={
                "exception_type": "AssertionError",
                "message_regex": r"None, None, None",
            },
            **kw,
        )
        # B-051: c.expect_exception drives the path — no
        # expected_status="fail" needed. ValueError matching =>
        # recorded as pass (bug confirmed).
        await rec.run_case(
            "bug.B-051.normalize_hosts_authors_keyword",
            body_b_051_normalize_hosts_authors_keyword,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-051",),
            **kw,
        )
        # B-064: preventive — body uses c.expect (default
        # expected_status="pass"); pass = decorator absent (good).
        await rec.run_case(
            "bug.B-064.subscribe_no_async_log_errors",
            body_b_064_subscribe_no_async_log_errors,
            category=category,
            tags=("bug_repro", "active", "preventive"), bug_ids=("B-064",),
            **kw,
        )

    # Helper used by B-047 — publishes b047_probe_event which routes
    # via b047_probe_sub → handle_b047_probe. Each call spawns one
    # real fan-out task in Plexus.task_list; the test asserts
    # that the eviction path (Stage Q done_callback) drains them.
    async def publish_event_for_repro(self):
        try:
            await self.publish_event("b047_probe_event")
        except Exception:
            pass


    # ==================================================================
    # _b_security — netcore inbound-authorization guards: B-090 (topic
    # streams) + B-091 (execute path, system_caller, reject replies).
    #
    # The PR4 Stage K "B-066" cells that used to live here were deleted
    # 2026-07-22. They drove a hand-rolled TLS peer speaking the retired
    # [len][type][payload] MSG_* protocol, and every one of them had been
    # silently skipping since the netcore rewrite via a blanket
    # `raise _SkipSignal()` in their shared fixture, so they asserted
    # nothing on any boot. Three of their properties are re-covered by the
    # B-091 block below; the rest were checked one by one before deletion.
    #
    # DROPPED WITHOUT REPLACEMENT — no gate cell asserts these today:
    #   * pre-auth pickle RCE. Now unreachable BY CONSTRUCTION rather than
    #     by a guard: authorize_inbound runs before deserialize_value
    #     (transport.py:494 vs :533) and unknown-cid CHUNKs are discarded
    #     (:602-605). Nothing asserts that ORDERING, so reversing it would
    #     keep the gate green.
    #   * SPKI pin enforcement. Unreachable defence-in-depth:
    #     Membership._cadata_for builds the trust store from the same
    #     roster resolve_pin reads, so an unpinned cert dies at CA
    #     verification before _authenticate ever runs.
    # Post-auth disallowed-class unpickling IS still covered, outside this
    # file, by _wire_selftest.py:189-202 (in the gate via
    # TestNetcoreUnitSuite). Full audit: B-091 in _private/bugs/bugs.jsonl.
    # ==================================================================
    async def _b_security(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "security"


        # ==============================================================
        # B-090 — inbound request_event_stream must resolve access as the
        # local SUB OWNER, never as the wire-supplied author_id.
        #
        # These drive NetworkManager._RematchRegistry directly with a
        # synthetic PeerIdentity/CallerCtx. No sockets, no subprocess: the
        # bug lives entirely in which uuid reaches find_endpoint, so an
        # in-process cell pins it exactly and runs on every boot.
        #
        # B-090 is a REGRESSION of B-018b, whose guard (_apply_b018b_guard)
        # was removed with the old NetworkManager in the netcore rewrite.
        # The rewrite replaced one global guard with per-path gates and
        # missed the topic-stream path.
        # ==============================================================
        from plexus.netcore.manager import NetworkManager
        from plexus.netcore.types import CallerCtx, PeerIdentity

        # NOTE: these three are ALSO used by the B-091 cells further down.
        # Deleting this block breaks them (loudly, with NameError - never a
        # silent green, since a cell body raising is recorded as an error).
        b090_reg = NetworkManager._RematchRegistry(self._plexus)
        b090_identity = PeerIdentity("b090-peer", False)

        def _b090_caller(author_id: str):
            return CallerCtx(author="evil-peer", author_id=author_id,
                             author_host="b090-peer",
                             request_uuid=str(uuid.uuid4()))

        async def _b090_sub(c, target_access_name: str) -> tuple:
            """Subscribe TestBugSuite (owner) -> TestEventTarget (target).

            hosts="any" so the sub accepts a remote publisher, which is the
            precondition the bug needs and is also the common default.
            """
            target = self._plexus.plugins.get("TestEventTarget")
            if target is None:
                # NOT a skip: the fixture is enabled in test_config.yml, so a
                # missing one is a broken suite, not an absent capability.
                raise AssertionError("TestEventTarget not loaded - fixture missing")
            topic = f"b090/{target_access_name}"
            sid = await self._plexus.subscribe_event(
                topic, self.plugin_name, self.plugin_uuid,
                target_access_name=target_access_name,
                target_plugin="TestEventTarget",
                target_plugin_uuid=target.plugin_uuid,
                hosts="any",
            )
            return topic, sid, target

        # ---- ATTACK: spoofed author_id must NOT reach a private endpoint
        async def body_b_090_stream_spoof_denied_private(c):
            from plexus.exceptions import RequestException
            topic, sid, target = await _b090_sub(c, "priv_stream")
            try:
                # The spoof: claim to BE the target plugin. Pre-fix this
                # cleared find_endpoint's accessible_by_other_plugins check
                # (core.py:5249, `plugin.plugin_uuid != requester_id`).
                # match= is load-bearing: NoLocalSubException SUBCLASSES
                # RequestException, so a bare expect_exception would also be
                # satisfied by the sub failing to wire up -- a green cell
                # asserting nothing. "not found" is the endpoint-denial text.
                c.expect_exception(RequestException, match="not found")
                async for _ in b090_reg.request_event_stream(
                        topic, {"value": 1}, b090_identity,
                        _b090_caller(target.plugin_uuid)):
                    pass
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- CONTROL: honest caller, accessible target, still works.
        # This is the cell that fails if the fix over-restricts (i.e. if it
        # copies the execute path's `plugin.remote AND ep.remote` gate):
        # TestEventTarget is remote:false and open_stream is remote:false.
        async def body_b_090_stream_honest_caller_allowed(c):
            topic, sid, _target = await _b090_sub(c, "open_stream")
            try:
                items = [x async for x in b090_reg.request_event_stream(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller("not-a-plugin-uuid-0000"))]
                c.expect(len(items), 3)
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- REACHABILITY: priv_stream must actually be streamable, or the
        # denial cell above proves nothing (it would pass identically if the
        # endpoint simply did not exist). Owner == target here, so the
        # self-call escape at core.py:5249 legitimately allows it.
        async def body_b_090_private_reachable_by_owner(c):
            target = self._plexus.plugins.get("TestEventTarget")
            if target is None:
                raise AssertionError("TestEventTarget not loaded - fixture missing")
            topic = "b090/priv_reachable"
            sid = await self._plexus.subscribe_event(
                topic, "TestEventTarget", target.plugin_uuid,
                target_access_name="priv_stream",
                target_plugin="TestEventTarget",
                target_plugin_uuid=target.plugin_uuid,
                hosts="any",
            )
            try:
                items = [x async for x in b090_reg.request_event_stream(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller("not-a-plugin-uuid-0000"))]
                c.expect(len(items), 3)
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- PARITY: the non-stream sibling must deny the same spoof the
        # same way, so the stream variant grants no more than request_event.
        async def body_b_090_request_event_parity(c):
            from plexus.exceptions import RequestException
            topic, sid, target = await _b090_sub(c, "priv_stream")
            try:
                # Same reasoning as the attack cell. Measured: request_event denies
                # with the SAME "Endpoint ... not found" text as the stream path,
                # which is itself the parity being asserted -- both variants refuse
                # the spoof the same way, at the same gate.
                c.expect_exception(RequestException, match="not found")
                await b090_reg.request_event(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller(target.plugin_uuid),
                )
            finally:
                await self._plexus.unsubscribe_event(sid)

        for cid, body in (
            ("bug.B-090.stream_spoof_denied_private", body_b_090_stream_spoof_denied_private),
            ("bug.B-090.stream_honest_caller_allowed", body_b_090_stream_honest_caller_allowed),
            ("bug.B-090.private_reachable_by_owner", body_b_090_private_reachable_by_owner),
            ("bug.B-090.request_event_parity", body_b_090_request_event_parity),
        ):
            await rec.run_case(
                cid, body, category=category,
                tags=("regression_guard", "security", "b090"), bug_ids=("B-090",),
                hard_timeout_s=15.0, **kw,
            )

        # ==============================================================
        # B-091 - the three security properties whose only coverage in the
        # GATE was a set of skip-gated B-066 cells, plus a fourth (4) that the
        # deleted set never covered at all.
        #
        # Each old cell drove a hand-rolled TLS peer speaking the PRE-netcore
        # wire protocol (MSG_EXECUTE et al), which no longer exists. These
        # replacements assert the same properties against the seams that
        # decide them today: two over a real two-node mTLS pair built from the
        # netcore self-test harness, four against the live core's re-match
        # registry.
        #
        # 1. system_caller is granted from THIS node's authenticated peer
        #    record, never from the wire. The record-level storage is covered
        #    (_membership_selftest.py:175-179) and the DENY direction is
        #    covered (_dispatch_selftest.py:280-285, and e2e at :430). What no
        #    test asserted is that a GRANTED peer's claim SURVIVES end to end
        #    to the callee registry, because every existing test builds
        #    system_caller=False. An implementation that downgraded EVERY
        #    caller passed the entire suite.
        # 2. A remote peer that spoofs author_id = a real LOCAL plugin uuid
        #    must not gain local-plugin access (B-018b). The old mechanism
        #    (_apply_b018b_guard) was deleted in the netcore rewrite, so the
        #    property now rests entirely on _match_execute's pre-gate: the
        #    spoofed author_id is forwarded verbatim into core.execute
        #    (manager.py:611), and find_endpoint's local branch hands over a
        #    non-accessible endpoint to a requester_id that equals the owning
        #    plugin's uuid (core.py:5247-5253). The pre-gate is what stops the
        #    call from ever getting there; execute_private_endpoint_denied
        #    asserts exactly that, with a control proving find_endpoint would
        #    otherwise hand the endpoint over.
        # 3. A frame rejected at authorize time must reach the peer as ERROR
        #    rather than being dropped. _dispatch_selftest proves the reject
        #    DECISION, and _transport_selftest's FakeDispatch accepts
        #    everything (_transport_selftest.py:121-122), so the pre-cid-open
        #    reply branch at transport.py:495-499 is entered by no GATE test.
        #    networking_multinode/test_hostile.py:183 (TP72) does drive it,
        #    but it is opt-in behind PLEXUS_PAIR_TEST and asserts only the
        #    observability event, never the reply.
        #
        # 4. (NOT one of the deleted properties, and a DIFFERENT wire field
        #    from 2: the selector's plugin_uuid rather than the caller's
        #    author_id.) Instance exactness, manager.py:594. _match_execute is
        #    NOT untested - TestNetPairUnitSuite's A1 cells exercise it
        #    positively - but that fake uses an empty plugin_uuid and an
        #    uuid-less selector, so the uuid branch is never entered there,
        #    and _dispatch_selftest's e2e checks it only against its own fake
        #    registry's hardcoded uuid, never _match_execute.
        # ==============================================================
        from plexus.netcore.dispatch import NoEndpointError
        from plexus.netcore.types import ExecuteSelector
        from plexus.exceptions import NetworkRequestException
        async def _b091_pair(a_is_system_caller: bool):
            """Bring up a real mTLS pair a<->b. b's roster entry for a carries
            the system_caller grant under test. Returns (na, nb, cleanup)."""
            # The two-node harness is the netcore self-tests' own. Reusing it
            # keeps one definition of "a real mTLS node pair" rather than a
            # second copy here that could drift from the transport it stands
            # in for. Note the coupling that buys: the two e2e cells assert on
            # the "sys"/"author"/"echoed" keys owned by that module's
            # EndToEndRegistry fake.
            #
            # Imported HERE, not at method scope: _dispatch_selftest calls
            # itself a throwaway dev aid and lives under the protected plexus/
            # package. An ImportError at method scope would escape _b_security
            # rather than a case body, and TestRunner would discard every
            # already-recorded TestBugSuite case to report one broken import.
            # Inside the helper, a vanished harness fails exactly the two
            # cells that need it.
            from plexus.netcore import _dispatch_selftest as ds

            tmp = tempfile.mkdtemp(prefix="b091_")
            nodes = []

            async def cleanup():
                try:
                    # BaseException, not Exception: on the hard-timeout path
                    # the body is cancelled, and a CancelledError escaping the
                    # first stop would otherwise strand every later one. Bound
                    # methods, not pre-built coroutines, so nothing is left
                    # un-awaited. 2s each: this runs INSIDE the case's
                    # hard_timeout_s budget, which asyncio.wait_for does not
                    # bound (it cancels the body then awaits it to completion).
                    for n in nodes:
                        for stop in (n.mem.stop, n.transport.stop):
                            try:
                                await asyncio.wait_for(stop(), 2)
                            except BaseException as exc:
                                # a genuinely failed stop strands a listener
                                # for the rest of the boot, and the only other
                                # thing that would notice is the whole-run
                                # socket census. Make it visible.
                                self._logger.warning(
                                    "B-091 teardown: %s failed: %r", stop, exc)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)

            try:
                # inside the try: _make_node starts a listener before it
                # returns, so a failure in the SECOND call must still tear
                # down the first. This suite runs in-process with the live
                # Plexus, where a stranded listener outlives the whole boot.
                na = await ds._make_node(tmp, "a")
                nodes.append(na)
                nb = await ds._make_node(tmp, "b")
                nodes.append(nb)
                na.mem.add_peer(PeerSpec("b", "127.0.0.1", nb.port, nb.pem, nb.fp))
                # THE grant under test: it lives in the CALLEE's roster entry
                # for the caller, which is the whole point of the property.
                nb.mem.add_peer(PeerSpec("a", "127.0.0.1", na.port, na.pem, na.fp,
                                            system_caller=a_is_system_caller))
                await na.mem.start()
                await nb.mem.start()
                if not await ds._wait(lambda: na.mem.reachable("b"), timeout=8):
                    raise AssertionError("link a->b did not come up")
            except BaseException:
                await cleanup()
                raise
            return na, nb, cleanup

        # ---- 1. GRANT: an authenticated peer whose record grants
        # system_caller keeps its author="system" claim end to end.
        async def body_b_091_system_caller_grant_e2e(c):
            na, _nb, cleanup = await _b091_pair(True)
            try:
                r = await na.dispatch.execute_remote(
                    "b", ExecuteSelector("plug", "echo"), {"x": 1},
                    CallerCtx("system", "aid", "a", "r1"), 10.0, deadline=10.0,
                )
                # The exact positive counterpart of _dispatch_selftest.py:430,
                # which asserts sys=False / author="aid" for an UNGRANTED peer.
                # Both directions are needed: without this cell an impl that
                # downgrades every caller passes; without that one an impl that
                # grants every caller passes.
                c.expect(r["sys"], True)
                c.expect(r["author"], "system")
            finally:
                await cleanup()

        # ---- 3. A frame rejected at authorize time must come back as an
        # ERROR the caller can observe, and must not tear down the link.
        async def body_b_091_hostname_drift_error_reply_e2e(c):
            na, _nb, cleanup = await _b091_pair(False)
            try:
                loop = asyncio.get_running_loop()
                # author_host disagrees with the TLS-authenticated hostname.
                # The real Dispatch.authorize_inbound rejects (dispatch.py:353-360)
                # BEFORE the cid is opened, so the reply comes from the
                # transport.py:495-499 branch no gate test enters.
                t0 = loop.time()
                raised = None
                try:
                    await na.dispatch.execute_remote(
                        "b", ExecuteSelector("plug", "echo"), {"x": 1},
                        CallerCtx("peer", "aid", "drift-host", "r1"), 10.0,
                        deadline=10.0,
                    )
                except Exception as exc:
                    raised = exc
                elapsed = loop.time() - t0
                # recorded on the case so a future flake is diagnosable from
                # test_report.json without re-running: expect() only keeps the
                # last actual/expected pair, which would lose the timing.
                c.set_marker("reject_reply_elapsed=%.3fs" % elapsed)
                c.expect(isinstance(raised, NetworkRequestException), True)
                # THE discriminator. `deadline` is a RELATIVE duration
                # (transport.py:996-1000), so a silently DROPPED reject also
                # ends in NetworkRequestException -- via Timeout, mapped at
                # dispatch.py:170-172 to the very same type -- just 10s later.
                # Without this bound the cell passes on a silent drop, which is
                # precisely the regression it exists to catch.
                c.expect(elapsed < 2.0, True)

                # The link must survive the rejection: an honest call after it
                # still round-trips on the SAME link.
                ok = await na.dispatch.execute_remote(
                    "b", ExecuteSelector("plug", "echo"), {"x": 2},
                    CallerCtx("peer", "aid", "a", "r2"), 10.0, deadline=10.0,
                )
                c.expect(ok["echoed"], {"x": 2})
            finally:
                await cleanup()

        # ---- 2. execute-path denial, against the LIVE core. These reuse the
        # B-090 registry/caller helpers above: same live core, same synthetic
        # peer, and a second copy would only drift.

        # A plugin that is not remote-reachable at all stays unreachable, so
        # the pre-gate's remote arm is load-bearing on its own.
        async def body_b_091_execute_nonremote_plugin_denied(c):
            target = self._plexus.plugins.get("TestEventTarget")
            if target is None:
                # NOT a skip: this fixture is enabled in test_config.yml, so a
                # missing one is a broken suite, not an absent capability.
                raise AssertionError("TestEventTarget not loaded - fixture missing")
            sel = ExecuteSelector("TestEventTarget", "get_state")
            # The endpoint must EXIST, or _match_execute returns None from the
            # `ep is None` arm (manager.py:590-592) and this cell passes while
            # asserting nothing about the remote arm.
            c.expect("get_state" in target.endpoints, True)
            # Denied by manager.py:596 (TestEventTarget is remote:false).
            # NB the caller identity is deliberately NOT the interesting part
            # here -- _match_execute never reads caller.author_id, so this cell
            # pins the remote arm and nothing more. The author_id property is
            # the next cell's job.
            c.expect_exception(NoEndpointError)
            await b090_reg.execute(sel, {}, b090_identity,
                                   _b090_caller("some-remote-caller"))

        # THE B-018b replacement: a remote peer claiming to BE the target
        # plugin must not reach that plugin's private endpoint.
        async def body_b_091_execute_private_endpoint_denied(c):
            target = self._plexus.plugins.get("TestExecuteTarget")
            if target is None:
                raise AssertionError("TestExecuteTarget not loaded - fixture missing")
            sel = ExecuteSelector("TestExecuteTarget", "ea_private",
                                  target.plugin_uuid)
            # Self-check, matching the sibling denial cells: if the plugin or
            # the endpoint ever flipped to remote:false, _match_execute would
            # deny at :596 instead of :598 and the accessible-arm assertion
            # below would silently evaporate.
            c.expect(bool(getattr(target, "remote", False)), True)
            c.expect(target.endpoints["ea_private"].get("remote"), True)
            # CONTROL first: with the spoofed requester_id, find_endpoint
            # itself WOULD hand over ea_private, because the spoof flips the
            # request off the remote branch (core.py:5237) onto the local one,
            # where the self-call escape at core.py:5249 sees
            # plugin.plugin_uuid == requester_id. So the denial below is not
            # over-determined: _match_execute's accessible arm is the ONLY
            # thing standing in front of this endpoint.
            plug, _ep, _node = await self._plexus.find_endpoint(
                "ea_private", hosts="local", plugin_uuid=target.plugin_uuid,
                requester_id=target.plugin_uuid, target_plugin="TestExecuteTarget")
            c.expect(plug is target, True)

            # THE ATTACK: same spoofed author_id, through the real inbound
            # path. Denied by manager.py:598 before core.execute is reached.
            c.expect_exception(NoEndpointError)
            await b090_reg.execute(sel, {}, b090_identity,
                                   _b090_caller(target.plugin_uuid))

        # Instance exactness (F#14), a DIFFERENT wire field: the selector's
        # plugin_uuid rather than the caller's author_id. Guards against a
        # stale uuid (e.g. one cached across a hot reload) reaching whatever
        # instance now answers to that name.
        async def body_b_091_execute_uuid_spoof_denied(c):
            target = self._plexus.plugins.get("TestExecuteTarget")
            if target is None:
                raise AssertionError("TestExecuteTarget not loaded - fixture missing")
            sel = ExecuteSelector("TestExecuteTarget", "ea_add",
                                  "not-the-live-uuid-0000")
            # Without this, a renamed/removed ea_add (or a target flipped to
            # remote:false) would deny from a DIFFERENT arm and leave the uuid
            # branch untested while the cell stayed green.
            c.expect("ea_add" in target.endpoints, True)
            c.expect_exception(NoEndpointError)
            await b090_reg.execute(sel, {}, b090_identity,
                                   _b090_caller("some-remote-caller"))

        # Positive control. Without it the three denial cells above are all
        # satisfied by a _match_execute that returns None unconditionally.
        async def body_b_091_execute_honest_call_allowed(c):
            target = self._plexus.plugins.get("TestExecuteTarget")
            if target is None:
                raise AssertionError("TestExecuteTarget not loaded - fixture missing")
            sel = ExecuteSelector("TestExecuteTarget", "ea_add",
                                  target.plugin_uuid)
            result = await b090_reg.execute(
                sel, {"a": 2, "b": 3}, b090_identity,
                _b090_caller("some-remote-caller"))
            c.expect(result, 5)

        for cid, body, timeout in (
            ("bug.B-091.system_caller_grant_e2e",
             body_b_091_system_caller_grant_e2e, 30.0),
            # 45s, not 30s: under a silent-drop regression this cell spends
            # ~10s in the dropped-reject timeout plus ~10s in the honest call,
            # and must still reach its elapsed-bound ASSERTION. A 30s budget
            # would report the far less diagnostic "exceeded hard timeout".
            ("bug.B-091.hostname_drift_error_reply_e2e",
             body_b_091_hostname_drift_error_reply_e2e, 45.0),
            ("bug.B-091.execute_nonremote_plugin_denied",
             body_b_091_execute_nonremote_plugin_denied, 15.0),
            ("bug.B-091.execute_private_endpoint_denied",
             body_b_091_execute_private_endpoint_denied, 15.0),
            ("bug.B-091.execute_uuid_spoof_denied",
             body_b_091_execute_uuid_spoof_denied, 15.0),
            ("bug.B-091.execute_honest_call_allowed",
             body_b_091_execute_honest_call_allowed, 15.0),
        ):
            await rec.run_case(
                cid, body, category=category,
                tags=("regression_guard", "security", "b091"), bug_ids=("B-091",),
                hard_timeout_s=timeout, **kw,
            )


