"""Event / topic / subscription orchestration for Plexus.

These methods are mixed into the Plexus class via ``class Plexus(EventMixin)``.
EventMixin holds no state of its own: every ``self.*`` attribute it
touches (topic_registry, network, plugins, requests, the observer registry,
etc.) is created in ``Plexus.__init__``, and every non-event method it calls
(``self._spawn_tracked``, ``self._process_request``, ...) lives on Plexus and
resolves through the MRO at runtime. The split is a pure relocation; call
sites are unchanged. See _private/plans/core_extraction_plan.md.

Imports are limited to the names the moved bodies use, sourced from the same
real modules core.py imports them from, so events.py never imports core and
no circular dependency is introduced.
"""

import asyncio
import concurrent.futures
import inspect
import re
import threading
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)
from .decorators import (
    async_gen_log_errors,
    async_log_errors,
    gen_log_errors,
    log_errors,
)
from .exceptions import (
    ConfigException,
    NetworkRequestException,
    NoLocalSubException,
    RequestException,
)
from .helpers.config import (
    _RESERVED_TEMPLATE_VARS,
    _TEMPLATE_VAR_RE,
    _normalize_authors,
    _normalize_hosts,
    _validate_subscription_topic,
    _validate_topic_static,
    _warn_redundant_host_combos,
)
from .notifier import Subscription
from .runtime import (
    DEFAULT_PLUGIN_READY_TIMEOUT,
    _EMIT_DEPTH,
    _MAX_EMIT_DEPTH,
    _bridge_wait,
    _held_permit,
    _sync_call_chain,
    current_caller_chain,
)
from .utils import (
    Event,
    GeneratorRequest,
    Plugin,
    Request,
)


class EventMixin:
    """Event-orchestration methods mixed into Plexus (see module docstring)."""

    def internal_observe(
        self,
        plugin_uuid: str,
        topic: str,
        callback: Callable[[str, dict], None],
    ) -> None:
        """Register a sync observer for a ``_core/...`` framework topic.

        Thread-safe (C-003): may be called from the loop thread or from a
        worker thread (e.g. a sync endpoint dispatched via the plugin
        executor pool) — mutations on ``_internal_observers`` and
        ``_observer_owners`` are protected by ``self._observer_lock``.
        Plugin authors call via ``Plugin.internal_observe`` (utils.py)
        which auto-fills ``plugin_uuid``; direct callers (test code,
        framework-internal) must pass ``plugin_uuid`` explicitly.

        Observers are called sync from the loop thread inside
        ``_internal_emit``; must return quickly (< 1ms). Heavy work goes
        to caller-spawned tasks. ``Exception`` subclasses raised by a
        callback are logged + swallowed (do not propagate to other
        observers). ``BaseException`` subclasses (``CancelledError``,
        ``KeyboardInterrupt``, ``SystemExit``) propagate up to the
        framework caller — observer authors must NOT raise those.

        Auto-cleanup: every observer registration owned by ``plugin_uuid``
        is removed on BOTH ``_disable_plugin_under_lock`` (so a
        disable→enable cycle does not accumulate duplicates when
        ``on_enable`` re-registers observers) and
        ``_pop_plugin_under_lock`` (idempotent — owners-set already
        cleared by disable in the normal pop-while-enabled path).
        Mirrors ``topic_registry.unsubscribe_plugin`` cleanup which
        is symmetric across both lifecycle paths.

        Idempotent: registering the same ``(topic, callback)`` pair twice
        for the same ``plugin_uuid`` is a no-op — single registration per
        pair, single dispatch per emit. This keeps ``_internal_observers``
        (per-topic list) and ``_observer_owners`` (per-plugin set) in
        symmetric step so ``_unobserve_plugin`` cleans up exactly what
        was registered.

        Worker-thread safety: C-003. Mutations on ``_internal_observers``
        and ``_observer_owners`` are protected by ``self._observer_lock``
        (threading.Lock) so a sync endpoint dispatched via the plugin
        executor pool can safely call this while the loop thread is
        mid-emit. Hold is brief — one dict insert.

        Ghost-observer guard: C-139. ``plugin_uuid`` is rejected if it
        already appears in ``self._observer_unobserved`` (populated by
        ``_unobserve_plugin``). This blocks a sync ``on_disable``
        still running in the worker pool past its ``wait_for`` timeout
        from re-registering observers that would otherwise leak forever
        — the disable path has already cleared the owners-set, so any
        subsequent ``internal_observe`` for that uuid is by definition
        a post-teardown ghost. New plugin instances get a fresh uuid4
        hex on each ``__init__`` so re-enable cycles aren't affected.
        The quarantine check runs INSIDE ``_observer_lock`` (mirroring
        the matching writer in ``_unobserve_plugin``) so a check-then-
        insert sequence cannot interleave with a concurrent
        unobserve-then-quarantine sequence and leak a ghost observer.

        R2-HH-3: internal_observe matches topics by EXACT string
        equality (``_internal_emit`` does a plain dict-key lookup).
        Wildcards (``*`` / ``#``) supported by ``subscribe_event`` are
        NOT supported here — a topic argument containing either
        character is rejected with ``ValueError`` rather than silently
        registering an observer that will never fire. Use
        ``subscribe_event`` for wildcard topic patterns.
        """
        # R2-GG-4: reject async callbacks at registration. _internal_emit
        # dispatches observers synchronously; an `async def` callback
        # would return a coroutine that is silently dropped (never
        # awaited) — guaranteed data loss. Detect via
        # inspect.iscoroutinefunction so the failure is loud at
        # registration instead of silent at emit time.
        if inspect.iscoroutinefunction(callback):
            raise TypeError(
                "internal_observe requires a sync callback; got async def. "
                "Use subscribe_event for async handlers."
            )
        # R2-HH-3: reject wildcard topic patterns up-front. Internal
        # observer dispatch is exact-match only; silently accepting a
        # wildcard registration would mislead plugin authors who
        # expect subscribe_event-like semantics.
        if "*" in topic or "#" in topic:
            raise ValueError(
                f"internal_observe does not support wildcards; "
                f"got topic={topic!r}. Use subscribe_event for wildcard "
                f"topics — internal_observe matches exact topic strings only."
            )
        lock = getattr(self, "_observer_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._observer_lock = lock
        with lock:
            unobserved = getattr(self, "_observer_unobserved", None)
            if unobserved is not None and plugin_uuid in unobserved:
                self._logger.warning(
                    "[OBSERVER] rejecting post-teardown internal_observe: "
                    "plugin_uuid=%r in quarantine (plugin already unloaded). "
                    "topic=%r. Re-enable allocates a fresh uuid. (C-139)",
                    plugin_uuid, topic,
                )
                return
            owned = self._observer_owners.setdefault(plugin_uuid, set())
            pair = (topic, callback)
            if pair in owned:
                return  # idempotent — already registered
            owned.add(pair)
            self._internal_observers.setdefault(topic, []).append(callback)

    def internal_unobserve(
        self,
        plugin_uuid: str,
        topic: str,
        callback: Callable[[str, dict], None],
    ) -> bool:
        """Remove an observer registration. Returns ``True`` if removed.

        Removes the FIRST matching ``(topic, callback)`` pair owned by
        ``plugin_uuid`` via ``list.remove`` (equality-based; bound methods
        compare by ``(func, instance)`` identity). Silent no-op if the
        registration is absent (returns ``False``). Idempotent.

        Cleans up empty topic lists and empty owner sets so the dicts
        don't grow indefinitely under register/unregister churn.

        C-003: protected by ``self._observer_lock``.
        """
        lock = getattr(self, "_observer_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._observer_lock = lock
        with lock:
            lst = self._internal_observers.get(topic)
            if not lst:
                return False
            try:
                lst.remove(callback)
            except ValueError:
                return False
            if not lst:
                self._internal_observers.pop(topic, None)
            owned = self._observer_owners.get(plugin_uuid)
            if owned is not None:
                owned.discard((topic, callback))
                if not owned:
                    self._observer_owners.pop(plugin_uuid, None)
            return True

    def _unobserve_plugin(self, plugin_uuid: str, *, quarantine: bool = False) -> int:
        """Remove all observer registrations owned by ``plugin_uuid``.

        Called from both ``_disable_plugin_under_lock`` (so a
        disable→enable cycle does not accumulate duplicate observers
        when on_enable re-registers them) and ``_pop_plugin_under_lock``
        alongside ``topic_registry.unsubscribe_plugin`` so observer
        state mirrors topic-sub state on plugin removal. The pop call
        is idempotent — disable already cleared the owners-set, so the
        re-call simply finds nothing to remove. Without this, a
        popped plugin's bound-method observers keep the Plugin
        instance alive in ``_internal_observers`` indefinitely (memory
        leak) AND continue firing against a torn-down plugin instance.

        Returns count removed. Cleans up empty topic lists.

        C-003: protected by ``self._observer_lock`` so a worker-thread
        ``internal_observe`` cannot race with this cleanup.

        C-139: marks ``plugin_uuid`` in ``self._observer_unobserved``
        (set, grows monotonically with disabled plugin uuids; bounded
        by the number of distinct uuids ever loaded). Subsequent
        ``internal_observe`` calls for the same uuid no-op rather than
        re-creating ghost entries. Re-enable cycles get a fresh uuid
        per Plugin instance so the quarantine doesn't block them.
        """
        lock = getattr(self, "_observer_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._observer_lock = lock
        with lock:
            # C-139 quarantine: mark INSIDE the lock so a concurrent
            # internal_observe that's blocked on the same lock sees the
            # quarantine on its next iteration. Marking outside the lock
            # opened a window where internal_observe could pass the
            # check, then acquire the lock AFTER unobserve, and insert
            # a ghost observer.
            #
            # W3-L1: ``quarantine`` defaults to False (cleanup-only). The
            # SAME instance + uuid is reused on re-enable, so
            # quarantining by default would silently reject every
            # ``internal_observe`` made during the next ``on_enable``
            # cycle. ``pop_plugin`` passes ``quarantine=True`` because
            # the instance is going away for good and future
            # ``internal_observe`` calls for this uuid (e.g. from a
            # cancelled-but-still-running async task) MUST be rejected
            # to prevent ghost observers against a torn-down plugin.
            if quarantine:
                unobserved = getattr(self, "_observer_unobserved", None)
                if unobserved is None:
                    unobserved = set()
                    self._observer_unobserved = unobserved
                unobserved.add(plugin_uuid)
            owned = self._observer_owners.pop(plugin_uuid, set())
            count = 0
            for topic, callback in owned:
                lst = self._internal_observers.get(topic)
                if not lst:
                    continue
                try:
                    lst.remove(callback)
                    count += 1
                    # Cleanup empty list inside the try so it only runs on a
                    # successful remove. Outside the try, a ValueError (callback
                    # absent) would still hit the cleanup against the unmodified
                    # non-empty list — harmless today but a latent footgun under
                    # future refactor.
                    if not lst:
                        self._internal_observers.pop(topic, None)
                except ValueError:
                    pass
            return count

    def _internal_emit(self, topic: str, /, **payload: Any) -> None:
        """Fire ``topic`` to all registered observers synchronously.

        Module-level ``_EMIT_DEPTH`` ContextVar guards against pathological
        recursive emits (depth >= ``_MAX_EMIT_DEPTH = 5`` aborts + logs).
        ``token = _EMIT_DEPTH.set(...)`` + ``_EMIT_DEPTH.reset(token)``
        restores parent-task state correctly under
        ``asyncio.create_task`` context inheritance — naive
        ``set(get() - 1)`` corrupts the parent slot.

        Snapshots the observer list before iteration so unregister-during-
        emit (e.g. an observer calling ``internal_unobserve`` on itself)
        is safe. ``Exception`` subclasses raised by an observer are logged
        + swallowed; never propagate to other observers or up to the
        caller. ``BaseException`` subclasses (``CancelledError``,
        ``KeyboardInterrupt``, ``SystemExit``) DO propagate — observer
        authors must NOT raise those.

        No-op fast path when no observer is registered for ``topic``
        (~50ns dict lookup). Per-event cost negligible at any reasonable
        load.

        Framework-internal: bypasses the leading-underscore validator
        that rejects plugin-author topics starting with ``_`` (Step 9).

        **Observer contract — payload is a plain dict, NOT unpacked
        kwargs.** Even though this method takes ``**payload`` kwargs at
        the emitter side, the observer is called as ``cb(topic, payload)``
        where ``payload`` is the captured-kwargs ``dict``. Observer
        signature is ``Callable[[str, dict], None]``:

            # emitter (framework code):
            self._internal_emit("_core/request/started", request_id="abc", plugin="X")

            # observer (plugin code):
            def my_observer(topic: str, payload: dict) -> None:
                request_id = payload["request_id"]
                plugin_name = payload["plugin"]

        Writing ``def my_observer(topic, **payload)`` would receive the
        dict as a single positional arg ``payload``, NOT the unpacked
        kwargs — TypeError on first key access.
        """
        # C-003: hold _observer_lock just long enough to snapshot the
        # listener list. Iteration runs outside the lock so observers
        # that re-enter (e.g. register a new observer in their callback)
        # cannot deadlock on the lock. The snapshot guarantees a
        # consistent view even if another thread mutates the underlying
        # list concurrently. The defensive getattr+lazy-init covers
        # test scaffolds that bypass __init__ via object.__new__.
        lock = getattr(self, "_observer_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._observer_lock = lock
        with lock:
            listeners = self._internal_observers.get(topic)
            if not listeners:
                return
            snapshot = list(listeners)
        depth = _EMIT_DEPTH.get()
        if depth >= _MAX_EMIT_DEPTH:
            self._logger.warning(
                "B-073 RECURSIVE EMIT DEPTH EXCEEDED at %d for topic %r — "
                "dropping event. Observer fan-out exceeded max depth %d; "
                "check observers for re-entrant framework calls.",
                depth,
                topic,
                _MAX_EMIT_DEPTH,
            )
            return
        token = _EMIT_DEPTH.set(depth + 1)
        try:
            for cb in snapshot:
                try:
                    cb(topic, payload)
                except Exception:
                    self._logger.exception(
                        "B-073 internal observer raised on topic %r; "
                        "swallowed and continuing to next observer",
                        topic,
                    )
        finally:
            _EMIT_DEPTH.reset(token)

    async def _register_yaml_subscriptions(self, plugin: Plugin) -> List[str]:
        """Register every YAML-declared subscription for ``plugin`` per
        Q23 + C15 + LOCKED A subscriptions: shape. Returns the list of
        newly-registered sub_uuids — caller is responsible for invoking
        ``_broadcast_yaml_sub_added`` on each AFTER releasing
        ``plugin_lock``. This keeps network I/O out of the global lock
        per the lock-ordering rule documented at _get_lifecycle_lock.

        Subscription registration runs at on_enable-time (not load-time)
        so that disable -> re-enable cycles re-register subs naturally.

        Disabled subs (``enabled: false``) get a Subscription with
        ``enabled=False`` so they live in the registry (visible to
        introspection / future advertisement) but are skipped by
        find_all (and _find_first) matching.

        C-056: atomic — if any single subscribe() call raises mid-loop,
        roll back the subs already registered in this invocation so the
        caller sees an all-or-nothing outcome. Without this, the plugin
        ends up with a partial YAML sub set in topic_registry and on
        plugin._sub_uuids while the enable_plugin path bubbles the raise
        out before its rollback (which only runs after the ENABLING
        transition) can fire — leaving orphaned subs behind.
        """
        # PR3 subscriptions: section.
        new_sub_uuids: List[str] = []
        subs_dict = getattr(plugin, "subscriptions", {}) or {}
        if isinstance(subs_dict, dict):
            try:
                for declared_id, entry in subs_dict.items():
                    # W5-Q5: cross-plugin YAML subs targeting a private
                    # endpoint would silently drop at dispatch time
                    # (find_endpoint rejects non-accessible cross-plugin
                    # calls). Catch the misconfiguration at on_enable
                    # time so operators see a clear ConfigException
                    # instead of mysterious silent drops.
                    target_plugin_name = entry.get(
                        "target_plugin", plugin.plugin_name
                    )
                    target_access_name = entry["target_access_name"]
                    if target_plugin_name != plugin.plugin_name:
                        target_plugin_obj = self.plugins.get(target_plugin_name)
                        if target_plugin_obj is None:
                            # S6 follow-up: load order races. If the target
                            # plugin hasn't been instantiated yet (dependent
                            # is enabling first), defer validation to first
                            # dispatch (find_endpoint covers that path).
                            # WARN so the load-order misconfig is visible
                            # in logs even when load completes.
                            self._logger.warning(
                                "_register_yaml_subscriptions: cross-plugin "
                                "YAML subscription %r on plugin %r targets "
                                "%r.%r — target plugin not yet loaded; "
                                "accessibility check deferred to dispatch "
                                "(W5-Q5).",
                                declared_id,
                                plugin.plugin_name,
                                target_plugin_name,
                                target_access_name,
                            )
                        else:
                            endpoints = getattr(
                                target_plugin_obj, "endpoints", {}
                            ) or {}
                            endpoint = endpoints.get(target_access_name)
                            if endpoint is None:
                                raise ConfigException(
                                    f"Plugin {plugin.plugin_name!r} YAML "
                                    f"subscription {declared_id!r} targets "
                                    f"{target_plugin_name!r}.{target_access_name!r} "
                                    f"which is not a declared endpoint "
                                    f"(W5-Q5)."
                                )
                            if not endpoint.get(
                                "accessible_by_other_plugins", False
                            ):
                                raise ConfigException(
                                    f"Plugin {plugin.plugin_name!r} YAML "
                                    f"subscription {declared_id!r} targets "
                                    f"{target_plugin_name!r}.{target_access_name!r} "
                                    f"which is not "
                                    f"accessible_by_other_plugins "
                                    f"(W5-Q5)."
                                )
                    sub_uuid = await self.topic_registry.subscribe(
                        topic_pattern=entry["topic"],
                        plugin_name=plugin.plugin_name,
                        plugin_uuid=plugin.plugin_uuid,
                        target_plugin=target_plugin_name,
                        target_access_name=target_access_name,
                        target_plugin_uuid=entry.get("target_plugin_uuid"),
                        hosts=entry.get("hosts", "any"),
                        blocked_hosts=entry.get("blocked_hosts"),
                        authors=entry.get("authors"),
                        blocked_authors=entry.get("blocked_authors"),
                        declared_id=declared_id,
                        enabled=bool(entry.get("enabled", True)),
                    )
                    plugin._sub_uuids.append(sub_uuid)
                    new_sub_uuids.append(sub_uuid)
            except BaseException:
                for sub_uuid in new_sub_uuids:
                    try:
                        await self.topic_registry.unsubscribe(sub_uuid)
                    except Exception:
                        self._logger.debug(
                            "_register_yaml_subscriptions rollback: "
                            "unsubscribe(%s) raised for plugin %r",
                            sub_uuid, plugin.plugin_name, exc_info=True,
                        )
                    try:
                        plugin._sub_uuids.remove(sub_uuid)
                    except ValueError:
                        pass
                raise
        return new_sub_uuids

    def _publisher_targets_local(
        self,
        eff_hosts: Union[str, list, None],
        eff_blocked: Union[str, list, None],
    ) -> bool:
        """Decide whether the publisher's hosts/blocked_hosts kwargs
        permit LOCAL fan-out at all (LOCKED IN — PUBLISHER hosts).

        Per spec: ``hosts`` defaults to "local". ``hosts="remote"``
        means peer-only — local subs are skipped. ``hosts=[<list>]``
        excluding "local"/own hostname also skips local. ``blocked_hosts``
        with "local"/own hostname/"any" also skips.

        Returns True if local fan-out should proceed; False to skip.
        """
        # Default per spec: hosts not provided → "local".
        if eff_hosts is None:
            eff_hosts = "local"

        def _hosts_allows_local(val) -> bool:
            if val == "any":
                return True
            if isinstance(val, str):
                return val in ("local", self.hostname)
            if isinstance(val, list):
                return "local" in val or self.hostname in val
            return False

        def _blocked_excludes_local(val) -> bool:
            if val is None:
                return False
            if isinstance(val, str):
                return val in ("local", self.hostname, "any")
            if isinstance(val, list):
                # Match _sub_accepts_local: "any" inside a list is
                # technically invalid per spec but defensively treated
                # as a wildcard block when present (consistent with
                # subscriber-side _sub_accepts_local)._
                return "local" in val or self.hostname in val or "any" in val
            return False

        return _hosts_allows_local(eff_hosts) and not _blocked_excludes_local(
            eff_blocked
        )

    def _sub_accepts_local(self, sub: Subscription) -> bool:
        """Stage B sub-level host filter for LOCAL fan-out.

        Sub's ``hosts``/``blocked_hosts`` interpreted against the
        framework's own hostname. Used by publish_event /
        request_event / request_event_stream alike (LOCKED H).
        """
        sub_hosts = sub.hosts
        sub_blocked = sub.blocked_hosts

        def _hosts_accepts(val) -> bool:
            if val is None or val == "any":
                return True
            if isinstance(val, str):
                return val in ("local", self.hostname)
            if isinstance(val, list):
                return "local" in val or self.hostname in val or "any" in val
            return False

        def _blocked(val) -> bool:
            if val is None:
                return False
            if isinstance(val, str):
                return val in ("local", self.hostname, "any")
            if isinstance(val, list):
                return "local" in val or self.hostname in val or "any" in val
            return False

        return _hosts_accepts(sub_hosts) and not _blocked(sub_blocked)

    def _sub_accepts_remote_publisher(
        self,
        sub,
        author_host: Optional[str],
        author: Optional[str],
    ) -> bool:
        """PR3 Stage C receiver-gate (locked #18 item 1). True iff this
        local sub should receive a publish_event/request_event coming
        from a peer at ``author_host`` published by ``author``.

        Distinct from `_sub_accepts_local` which gates LOCAL fan-out
        against our own hostname. Receiver-gate logic:
          - hosts="local"          → REJECT (sub opted out of remote)
          - hosts="any"/"remote"   → ACCEPT (then check blocked_hosts)
          - hosts=<str>            → ACCEPT iff str==author_host
                                     (the "any"/"remote" cases are
                                     intercepted by the preceding guard)
          - hosts=[list]           → ACCEPT iff author_host in list, or
                                     "any"/"remote" in list
        blocked_hosts: REJECT iff blocked names author_host, "any", or
        "remote". Authors filter is applied separately via
        `_sub_accepts_author`.
        """
        sub_hosts = getattr(sub, "hosts", None)
        if sub_hosts == "local":
            return False

        if sub_hosts is None or sub_hosts in ("any", "remote"):
            accepts = True
        elif isinstance(sub_hosts, str):
            # "any"/"remote" already handled by the preceding guard, so the
            # str branch is only entered with a plain hostname.
            accepts = (sub_hosts == author_host)
        elif isinstance(sub_hosts, list):
            accepts = (
                (author_host is not None and author_host in sub_hosts)
                or "any" in sub_hosts
                or "remote" in sub_hosts
            )
        else:
            return False

        if not accepts:
            return False

        sub_blocked = getattr(sub, "blocked_hosts", None)
        if sub_blocked is None:
            return True
        if isinstance(sub_blocked, str):
            if sub_blocked in ("any", "remote") or sub_blocked == author_host:
                return False
        elif isinstance(sub_blocked, list):
            if (
                "any" in sub_blocked
                or "remote" in sub_blocked
                or (author_host is not None and author_host in sub_blocked)
            ):
                return False

        return True

    def _sub_accepts_author(self, sub: Subscription, author: str) -> bool:
        """Stage B sub-level author filter (LOCKED H + Q4).

        Q4: system-originated events are implicitly trusted — they pass
        any explicit ``authors`` whitelist UNLESS ``blocked_authors``
        explicitly names "system".
        """
        authors = sub.authors
        blocked_authors = sub.blocked_authors

        def _accepts(val) -> bool:
            if val is None:
                return True
            if isinstance(val, str):
                return val == author or val == "any"
            if isinstance(val, list):
                return author in val or "any" in val
            return False

        def _blocked(val) -> bool:
            if val is None:
                return False
            if isinstance(val, str):
                return val == author or val == "any"
            if isinstance(val, list):
                return author in val or "any" in val
            return False

        # Q4: system bypasses authors whitelist (but blocked_authors
        # can still name "system" explicitly to lock it out).
        # W1-C2: ``blocked_authors='any'`` must NOT match 'system'.
        # 'any' is a wildcard for non-privileged authors; only an
        # explicit ``'system'`` entry can lock out the system author.
        if author == "system":
            val = blocked_authors
            if val is None:
                return True
            if isinstance(val, str):
                return val != "system"
            if isinstance(val, list):
                return "system" not in val
            return True

        return _accepts(authors) and not _blocked(blocked_authors)

    def _lookup_event(self, plugin: Plugin, event_id: str) -> dict:
        """Look up event_entry by event_id (C1 step 1).

        Separated from topic_vars validation + template resolution so
        callers can do the ``enabled: false`` check (C2) BEFORE running
        the more expensive validation pass. Per C1 ORDER OF OPERATIONS:
        step 1 lookup → step 2 enabled check → ... → topic_vars validate.
        """
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("event_id must be a non-empty string")

        events_dict = getattr(plugin, "events", {}) or {}
        event_entry = events_dict.get(event_id)
        if event_entry is None:
            raise ValueError(
                f"Event {event_id!r} not declared in events: section "
                f"of plugin {plugin.plugin_name!r} (LOCKED L #10)"
            )
        return event_entry

    def _resolve_topic_for_event(
        self,
        plugin: Plugin,
        event_id: str,
        topic_vars: Optional[Dict[str, str]],
        event_entry: Optional[dict] = None,
    ) -> tuple:
        """Look up event_id, validate topic_vars, resolve template.

        Returns (resolved_topic, event_entry). Raises ValueError on
        spec violations (LOCKED L #3-9 + Q15/Q16). The caller is
        expected to handle ``enabled: false`` semantics — this helper
        validates and resolves but does NOT decide whether to dispatch.

        ``event_entry`` may be passed by callers that already did
        ``_lookup_event`` (avoids double-lookup); when None, this helper
        does the lookup itself.
        """
        if event_entry is None:
            event_entry = self._lookup_event(plugin, event_id)

        # Validate topic_vars shape (LOCKED L #3-9).
        if topic_vars is None:
            tv: Dict[str, str] = {}
        elif isinstance(topic_vars, dict):
            tv = topic_vars
        else:
            raise TypeError(
                f"topic_vars must be a Dict[str, str] or None; "
                f"got {type(topic_vars).__name__} (LOCKED L #3)"
            )

        for k, v in tv.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"topic_vars keys must be str; got {type(k).__name__} "
                    f"(LOCKED L #3)"
                )
            if k in _RESERVED_TEMPLATE_VARS:
                raise ValueError(
                    f"topic_vars key {k!r} is reserved (LOCKED L #6); "
                    f"reserved names: {sorted(_RESERVED_TEMPLATE_VARS)}"
                )
            if not isinstance(v, str):
                raise TypeError(
                    f"topic_vars[{k!r}] must be str; got {type(v).__name__} "
                    f"(LOCKED L #3)"
                )
            if "/" in v:
                raise ValueError(
                    f"topic_vars[{k!r}]={v!r} contains '/'; would inject "
                    f"extra topic segments (LOCKED L #4)"
                )
            if "*" in v:
                # W1-C3: wildcards are subscriber-side only. A "*" in a
                # topic_vars VALUE would inject a wildcard segment into
                # the published topic, corrupting it for all subscribers.
                raise ValueError(
                    f"topic_vars[{k!r}]={v!r} contains '*'; wildcards are "
                    f"subscriber-side only (LOCKED L #1)"
                )
            if not v:
                raise ValueError(f"topic_vars[{k!r}] is empty string (LOCKED L #5)")
            stripped = v.strip()
            if not stripped:
                # Whitespace-only collapses to an empty segment per
                # LOCKED L #5; report it under the same rule for clarity.
                raise ValueError(
                    f"topic_vars[{k!r}]={v!r} is whitespace-only — "
                    f"collapses to empty segment (LOCKED L #5)"
                )
            if stripped != v:
                raise ValueError(
                    f"topic_vars[{k!r}]={v!r} has leading/trailing "
                    f"whitespace (LOCKED L)"
                )

        # Resolve {var} placeholders in the topic template.
        topic_template = event_entry["topic"]
        placeholders = set(_TEMPLATE_VAR_RE.findall(topic_template))

        if not placeholders and tv:
            self._logger.warning(
                "publish_event/request_event %s: topic %r is static but "
                "topic_vars=%r passed (LOCKED L #9 — likely confused "
                "payload vs topic_vars)",
                event_id,
                topic_template,
                tv,
            )

        # Check missing keys for {var} placeholders (LOCKED L #7).
        missing = placeholders - set(tv.keys())
        if missing:
            raise ValueError(
                f"event {event_id!r} topic {topic_template!r} requires "
                f"topic_vars keys {sorted(missing)} (LOCKED L #7)"
            )

        # Check extra topic_vars keys (LOCKED L #8 — WARN, not error).
        extra = set(tv.keys()) - placeholders
        if extra:
            self._logger.warning(
                "publish_event/request_event %s: topic_vars keys %r not "
                "used in topic %r (LOCKED L #8 — probably caller mistake)",
                event_id,
                sorted(extra),
                topic_template,
            )

        # Substitute. Use the same regex helper to keep behavior consistent.
        def _sub(match: re.Match) -> str:
            name = match.group(1)
            if name in tv:
                return tv[name]
            # Should be unreachable given the missing-key check above —
            # defensive guard.
            raise ValueError(f"event {event_id!r} unresolved placeholder {{{name}}}")

        resolved = _TEMPLATE_VAR_RE.sub(_sub, topic_template)

        # Post-resolution checks (Q15 reject empty + Q16 strip slashes).
        stripped_topic = resolved.strip("/")
        if not stripped_topic.strip():
            raise ValueError(f"event {event_id!r} resolved topic empty (Q15)")

        # Re-validate post-resolution (no embedded * mid-segment, no
        # empty middle segments). Wildcards forbidden in events. Per
        # LOCKED L's "ORDER OF OPERATIONS" + "FILTER LOOKUP" step 6.
        stripped_topic = _validate_topic_static(
            stripped_topic,
            context=f"event {event_id!r} resolved topic",
            allow_wildcards=False,
        )

        # Case-insensitive topics: canonicalize the resolved topic to
        # lowercase here (the single publisher funnel for publish_event /
        # request_event / request_event_stream), AFTER topic_vars
        # substitution so a var value like "Alice" is folded too. The
        # subscriber side lowercases topic_pattern in
        # TopicRegistry.register, so matching is case-insensitive without
        # any change to the matcher.
        return stripped_topic.lower(), event_entry

    @async_log_errors
    async def publish_event(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
        *,
        _caller_chain: Optional[tuple] = None,
    ) -> int:
        """Publish an event (1:N fire-and-forget).

        Per PR3 PLAN F + LOCKED L FILTER LOOKUP. Returns the count of
        subscribers the dispatch was SCHEDULED for (local + remote,
        post-filter) — NOT a guarantee of delivery. Each per-sub
        fan-out runs as a fire-and-forget task; the count is computed
        and returned BEFORE those tasks execute. Subs whose target
        plugin is missing, whose handler signature is wrong, or whose
        handler raises mid-execution all count toward the return
        value (the per-sub Request resolves with error=True in those
        cases, but the publisher does not see it). Use ``request_event``
        when you need an actual delivery confirmation.

        Pure declaration model: ``event_id`` MUST exist in
        ``publisher.events``. Disabled events (``enabled: false``)
        silently drop and return 0 (C2).
        """
        # C1 ORDER OF OPERATIONS:
        # Step 1: event_id lookup.
        event_entry = self._lookup_event(publisher, event_id)

        # Step 2: enabled flag (C2 — silent drop on publish_event).
        # MUST precede topic_vars validation so disabled events with
        # malformed topic_vars don't raise ValueError.
        if not event_entry.get("enabled", True):
            self._logger.debug(
                "publish_event %s: event disabled, silent drop", event_id
            )
            return 0

        # Step 3: payload normalization (Q7).
        # Q7 coercion: None payload becomes empty dict so subscribers can
        # rely on receiving a dict.
        if payload is None:
            payload = {}

        # Step 4-5: topic_vars validation + template resolution +
        # post-resolution checks (Q15/Q16 + LOCKED L #3-9).
        resolved_topic, _ = self._resolve_topic_for_event(
            publisher, event_id, topic_vars, event_entry=event_entry
        )

        # Step 7: hosts/blocked_hosts default-and-override.
        # Validate caller-supplied values via _normalize_hosts (events:
        # defaults already normalized at YAML load). default=None so a
        # caller-None falls through to the event_entry's value cleanly;
        # an actual "local" default is then applied by
        # _publisher_targets_local. This catches malformed forms like
        # `hosts=[]` (empty list) at call time instead of silently
        # mishandling them downstream.
        if hosts is not None:
            hosts = _normalize_hosts(
                hosts,
                param_name="publish_event hosts",
                default=None,
            )
        if blocked_hosts is not None:
            blocked_hosts = _normalize_hosts(
                blocked_hosts,
                param_name="publish_event blocked_hosts",
                default=None,
                is_blocked=True,
            )
        eff_hosts = hosts if hosts is not None else event_entry.get("hosts")
        eff_blocked = (
            blocked_hosts
            if blocked_hosts is not None
            else event_entry.get("blocked_hosts")
        )
        # LOCKED IN — PUBLISHER hosts: emit WARNING for redundant combos
        # (e.g. hosts="any" + blocked_hosts="local" → equivalent to
        # hosts="remote", nudge caller toward the cleaner form).
        _warn_redundant_host_combos(eff_hosts, eff_blocked, self._logger)
        # Stage C will read eff_hosts/eff_blocked for the peer-level
        # filter (PR3 PLAN F step 5a). Stage B uses them ONLY to gate
        # whether local fan-out happens at all (e.g. hosts="remote"
        # means peer-only, no local delivery).

        # Publisher-level gate: skip local fan-out if publisher's
        # hosts/blocked_hosts exclude local delivery. PR3 Stage C still
        # runs remote dispatch even when local is skipped.
        local_targets = self._publisher_targets_local(eff_hosts, eff_blocked)
        now_ts = time.time()
        survivors: list = []

        if local_targets:
            # Step 4: local fan-out — find all local subs matching resolved
            # topic. find_all returns insertion order (LOCKED C).
            all_subs = await self.topic_registry.find_all(resolved_topic)
            local_subs = [s for s in all_subs if self._sub_owner_active(s)]

            survivors = [
                s
                for s in local_subs
                if self._sub_accepts_local(s)
                and self._sub_accepts_author(s, publisher.plugin_name)
            ]

            if publisher.verbose_notifier:
                self._logger.debug(
                    "publish_event %s topic=%r matched %d local sub(s) "
                    "(of %d total subs)",
                    event_id,
                    resolved_topic,
                    len(survivors),
                    len(local_subs),
                )

            # Per-sub fan-out tasks. Each gets its own Request with
            # kind="publish_event", hosts="local" (C19), and
            # requester_id=sub.plugin_uuid (C18).
            for sub in survivors:
                await self._fanout_sub(
                    sub=sub,
                    publisher=publisher,
                    resolved_topic=resolved_topic,
                    payload=payload,
                    kind="publish_event",
                    timestamp=now_ts,
                    caller_chain=_caller_chain,
                    timeout=None,
                )
        else:
            if publisher.verbose_notifier:
                self._logger.debug(
                    "publish_event %s topic=%r: publisher hosts=%r "
                    "blocked_hosts=%r excludes local fan-out",
                    event_id,
                    resolved_topic,
                    eff_hosts,
                    eff_blocked,
                )

        # PR3 Stage C step 18 — remote dispatch (locked #16). Fire-and-
        # forget per-peer publish tasks for every advertised sub on
        # every reachable peer that survived per-peer + sub-level
        # filters. Best-effort; return count is local + remote.
        # Snapshot ``nm = self.network`` once (Commit 2b cycle 2 MED-B):
        # mid-block hot-reload would otherwise leak calls onto a
        # stopped NM. cycle 4 HIGH-1: the ``_deregister`` closure below
        # MUST capture ``nm`` via default-arg so done-callbacks fired
        # AFTER a rebuild swap continue mutating the OLD NM's
        # ``_inflight_publishes`` (drain is ongoing on it) instead of
        # corrupting the NEW NM's accounting.
        local_count = len(survivors)
        remote_count = 0
        nm = self.network
        if (
            getattr(self, "networking_enabled", False)
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            try:
                from uuid import uuid4 as _uuid4

                request_uuid = _uuid4().hex
                per_peer = await nm._build_remote_dispatch(
                    topic=resolved_topic,
                    payload=payload,
                    author=publisher.plugin_name,
                    author_id=publisher.plugin_uuid,
                    author_host=self.hostname,
                    timestamp=now_ts,
                    request_uuid=request_uuid,
                    eff_hosts=eff_hosts,
                    eff_blocked_hosts=eff_blocked,
                )
                remote_count = sum(len(advs) for advs in per_peer.values())

                tasks = []
                for peer_hostname, advs in per_peer.items():
                    node = next(
                        (n for n in list(nm.nodes) if n.hostname == peer_hostname),
                        None,
                    )
                    if node is None:
                        continue
                    # locked #16: caller-acquires-_struct_lock-once;
                    # enabled recheck atomic with task creation.
                    async with nm._adverts_struct_lock:
                        if not node.enabled:
                            continue
                        t = asyncio.create_task(
                            nm.publish_event_remote(
                                node.IP,
                                resolved_topic,
                                payload,
                                publisher.plugin_name,
                                publisher.plugin_uuid,
                                self.hostname,
                                now_ts,
                                request_uuid,
                            )
                        )
                        # Append BEFORE the dict op so a raise in
                        # setdefault/add can't orphan `t` inside this
                        # lock window. Sub-lock-window protection only:
                        # once this function returns, ``tasks`` is
                        # GC'd. ``_inflight_publishes`` is the durable
                        # strong ref (consulted by _drain_for_rebuild).
                        tasks.append(t)
                        nm._inflight_publishes.setdefault(peer_hostname, set()).add(t)

                    # cycle 4 HIGH-1: capture ``nm`` via default-arg so
                    # the done-callback uses the OLD NM's accounting
                    # even if a hot-reload has swapped ``self.network``
                    # mid-flight. Reading ``self.network`` inside
                    # ``_drop`` would race with rebuild and corrupt
                    # the NEW NM's ``_inflight_publishes``.
                    #
                    # Note: ``_drop`` closes over ``_nm``; while it
                    # lives in ``Plexus._fire_and_forget``, the OLD NM
                    # is briefly retained past hot-reload. Harmless —
                    # _drop completes in microseconds and the OLD NM
                    # is already being torn down.
                    def _deregister(_t, ph=peer_hostname, _nm=nm):
                        async def _drop():
                            async with _nm._adverts_struct_lock:
                                s = _nm._inflight_publishes.get(ph)
                                if s is not None:
                                    s.discard(_t)
                                    if not s:
                                        _nm._inflight_publishes.pop(ph, None)

                        self._spawn_fire_and_forget(
                            _drop(), name=f"publish_dereg<-{ph}"
                        )

                    t.add_done_callback(_deregister)

                if tasks:
                    # POSS-W-A1-003 fix: register the outer gather
                    # wrapper through _spawn_tracked so a strong
                    # reference is kept in self.task_list (preventing
                    # GC mid-flight) and shutdown drain can wait on
                    # it. Individual per-peer ``t`` tasks remain
                    # tracked via nm._inflight_publishes; this wrapper
                    # only swallows their exceptions via
                    # return_exceptions=True.
                    self._spawn_tracked(
                        asyncio.gather(*tasks, return_exceptions=True),
                        name=f"publish_event_remote_fanout:{resolved_topic}",
                    )
            except Exception:
                self._logger.debug(
                    "publish_event remote dispatch failed", exc_info=True
                )

        # B-073 Step 8 emit: event published. ALWAYS emit even when
        # target_count=0 — useful for "publisher fired, nothing
        # listened" debugging.
        self._internal_emit(
            "_core/event/published",
            publisher=publisher.plugin_name,
            topic=resolved_topic,
            target_count=local_count + remote_count,
            ts=now_ts,
        )
        return local_count + remote_count

    def _sub_owner_active(self, sub) -> bool:
        """B-037: a subscription only delivers while its OWNER plugin is
        still active. The owner flips ENABLED -> DISABLING synchronously at
        the start of disable/pop (before on_disable yields control to the
        event loop), so gating local fan-out on the owner's state closes
        the publish/request-during-pop race BY CONSTRUCTION. A presence-only
        check (``sub.plugin_uuid in self.plugins_by_uuid``) does NOT: the
        dict pop happens late, after the on_disable await, so a concurrent
        publish can snapshot a sub whose owner is already tearing down.

        ``enabled`` is True for ENABLING as well as ENABLED, so a plugin's
        own on_enable self-publish still delivers; only DISABLING / INACTIVE
        / popped owners are filtered out.
        """
        owner = self.plugins_by_uuid.get(sub.plugin_uuid)
        return owner is not None and owner.enabled

    async def _fanout_sub(
        self,
        *,
        sub: Subscription,
        publisher: Optional[Plugin],
        resolved_topic: str,
        payload: Any,
        kind: str,
        timestamp: float,
        timeout: Optional[float],
        caller_chain: Optional[tuple] = None,
        # PR3 Stage C — locked #3 + #15. When invoked from the
        # networking-side handler path, `publisher` is None and the
        # remote publisher metadata arrives via these kwargs.
        remote_publisher_name: Optional[str] = None,
        remote_publisher_uuid: Optional[str] = None,
        remote_publisher_host: Optional[str] = None,
        remote_verbose: bool = False,
    ) -> Optional[Request]:
        """Build a per-sub Request and spawn its dispatch task (publish
        path) or build + return without spawning (request path; caller
        awaits it).

        Stage B always returns the Request. publish_event ignores the
        return value (fire-and-forget). request_event awaits it.
        """
        # PR3 Stage C defense-in-depth (locked #15): reject any caller
        # path that hands us a remote_publisher_host claiming our own
        # hostname. The wire handler already gates this; defense-in-
        # depth covers tests + future direct callers that bypass
        # _handle_client.
        if remote_publisher_host is not None and remote_publisher_host == self.hostname:
            self._logger.warning(
                "fan-out gate: remote_publisher_host equals our hostname; rejecting"
            )
            return None

        # Resolve effective publisher metadata. Local path reads from
        # `publisher: Plugin`; remote path reads from kwargs.
        if publisher is not None:
            eff_author = publisher.plugin_name
            eff_author_id = publisher.plugin_uuid
            eff_author_host = self.hostname
        else:
            eff_author = remote_publisher_name or "remote"
            eff_author_id = remote_publisher_uuid or "remote"
            eff_author_host = remote_publisher_host or ""

        request = Request(
            author_host=eff_author_host,
            plugin=sub.target_plugin or sub.plugin_name,
            method=sub.target_access_name,
            args=payload,
            plugin_uuid=sub.target_plugin_uuid,
            target_hosts="local",  # C19
            blocked_hosts=None,
            author=eff_author,
            author_id=eff_author_id,
            timeout=timeout,
            request_id=None,
            event_loop=self.main_event_loop,
            kind=kind,
            topic=resolved_topic,
            # C4: declared_id (YAML key) for config subs, sub_uuid for
            # runtime. Use `is not None` instead of truthy `or` so an
            # empty-string declared_id (impossible from YAML loader, but
            # possible via direct topic_registry.subscribe(declared_id="")
            # calls) doesn't silently fall through to sub_uuid.
            origin_subscription_id=(
                sub.declared_id if sub.declared_id is not None else sub.sub_uuid
            ),
            timestamp=timestamp,
            requester_id=sub.plugin_uuid,  # C18
        )

        # C10: propagate the publisher's sync call chain through fan-out
        # so cross-pool cycle detection still works when a sync subscriber
        # handler eventually re-enters execute_sync / publish_event_sync /
        # etc. Stage A's _tracked_event wrapper reads request._call_chain.
        # Use the SAME flat-string format the execute path uses
        # (`f"{plugin}.{method}"`) — see _execute_sync_tracked at the
        # `chain + (target,)` site. Mismatched element shapes break the
        # `target in chain` membership test downstream and let real
        # cycles slip past detection.
        #
        # ``caller_chain`` is passed by sync entry points (publish_event_sync
        # etc.) which captured _sync_call_chain.chain on the WORKER thread
        # before scheduling onto the event loop. Threadlocal lookup here
        # would return () because the event loop thread never set it. If
        # not provided, fall back to threadlocal — covers the async-caller
        # path where _fanout_sub runs in the same task tree as the sync
        # wrapper that set the chain.
        if caller_chain is not None:
            existing_chain = caller_chain
        else:
            existing_chain = getattr(_sync_call_chain, "chain", ())
        target_for_chain = (
            f"{sub.target_plugin or sub.plugin_name}.{sub.target_access_name}"
        )
        request._call_chain = tuple(existing_chain) + (target_for_chain,)

        async with self.request_lock:
            self.requests[request.id] = request

        async def _run_and_collect():
            try:
                await self._process_request(request)
            finally:
                # B-073 Session 2 Step 3: done-callback eviction. Was
                # ``await request.set_collected()`` (Q12 fix); migrated
                # to direct sync pop. Idempotent — _process_request's
                # own finally already pops via the producer-side path.
                self.requests.pop(request.id, None)

        # Name uses `sub.target_plugin or sub.plugin_name` to mirror the
        # actual dispatch target (line ~3876 already applies that
        # fallback for the Request's `plugin` field).
        self._spawn_tracked(
            _run_and_collect(),
            name=f"sub:{sub.target_plugin or sub.plugin_name}.{sub.target_access_name}<-{resolved_topic}",
        )

        return request

    @log_errors
    def publish_event_sync(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
    ) -> int:
        """Sync variant of publish_event (C16). Schedules the async
        coroutine on main_event_loop via run_coroutine_threadsafe.
        Pre-start guard fires inside the Plugin wrapper (Q1).

        C10: capture _sync_call_chain.chain on the WORKER thread before
        scheduling onto the event loop. The coroutine running on the
        loop thread sees `_sync_call_chain.chain == ()` (different
        thread, different threadlocal), so the chain must be passed
        explicitly via _caller_chain to thread cycle detection through
        sync→fan-out→sync paths.
        """
        # Phase 2b: poison fail-fast (see Plexus.execute_sync).
        if getattr(_held_permit, "poisoned", False):
            raise RequestException(
                "sync bridge gave up its execution permit under "
                "saturation/shutdown; this call chain must unwind (do not "
                "make further sync-bridge calls)."
            )
        # C-004: same-thread deadlock guard.
        self._check_not_loop_thread("publish_event_sync")
        chain = getattr(_sync_call_chain, "chain", ())
        # Rate-limiter Step 2a: also carry the originating sync handler's
        # IDENTITY across the bridge (distinct from `chain`/`_caller_chain`
        # above, which is the flat cycle-detection chain). Captured worker-side
        # via current_caller_chain(), re-seated loop-side by _with_caller_chain.
        _pub_coro = self._with_caller_chain(
            current_caller_chain(),
            self.publish_event(
                publisher,
                event_id,
                payload,
                topic_vars,
                hosts,
                blocked_hosts,
                _caller_chain=chain,
            ),
        )
        future = asyncio.run_coroutine_threadsafe(
            _pub_coro,
            self.main_event_loop,
        )
        # R2-FF-1: bound the worker-thread wait so a stalled event loop
        # cannot block the publisher forever. publish_event has no
        # caller-supplied timeout, so use a generous fixed budget.
        # TODO: thread an explicit publisher timeout through if needed.
        # Phase 2b: _bridge_wait frees E while parked (the 60s hold would
        # otherwise starve the pool) and owns cancel-on-timeout.
        return _bridge_wait(future, 60.0)

    @async_log_errors
    async def request_event(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
        timeout: Optional[float] = None,
        *,
        _caller_chain: Optional[tuple] = None,
    ) -> Any:
        """Request an event (1:1 ask).

        Per PR3 PLAN F. Tie-break: insertion order on local subs (LOCKED
        C). No local match → RequestException (Stage B is LOCAL-only;
        remote dispatch lands in Stage C).
        """
        # C1 ORDER OF OPERATIONS: lookup → enabled → payload → resolve.
        event_entry = self._lookup_event(publisher, event_id)

        # C2: disabled events raise on request_event (caller awaits a
        # result, can't silently return None). MUST precede topic_vars
        # validation.
        if not event_entry.get("enabled", True):
            raise RequestException(f"event {event_id!r} disabled (C2)")

        if payload is None:
            payload = {}

        resolved_topic, _ = self._resolve_topic_for_event(
            publisher, event_id, topic_vars, event_entry=event_entry
        )

        # Validate caller-supplied hosts/blocked_hosts (events: defaults
        # already normalized at YAML load). Catches malformed forms at
        # call time. default=None so caller-None falls through.
        if hosts is not None:
            hosts = _normalize_hosts(
                hosts,
                param_name="request_event hosts",
                default=None,
            )
        if blocked_hosts is not None:
            blocked_hosts = _normalize_hosts(
                blocked_hosts,
                param_name="request_event blocked_hosts",
                default=None,
                is_blocked=True,
            )

        # Publisher-level hosts gate: when hosts="remote" or excludes
        # local, skip the local-match phase entirely and go straight to
        # Stage C remote dispatch (locked #18 item 7). Previously raised
        # here, which prevented hosts="remote" callers from ever reaching
        # the remote candidate iteration block.
        eff_hosts = hosts if hosts is not None else event_entry.get("hosts")
        eff_blocked = (
            blocked_hosts
            if blocked_hosts is not None
            else event_entry.get("blocked_hosts")
        )
        _warn_redundant_host_combos(eff_hosts, eff_blocked, self._logger)
        local_targets = self._publisher_targets_local(eff_hosts, eff_blocked)

        # Capture timestamp once so all per-sub Requests built off this
        # call see consistent epoch seconds (consistency with
        # publish_event).
        now_ts = time.time()

        # Find first matching LOCAL sub (insertion order) only when the
        # publisher's hosts filter actually targets local. Apply the
        # same sub-level host/author filter as publish_event so subs
        # with hosts="remote" or blocked_authors filtering us out are
        # skipped (LOCKED H).
        if local_targets:
            all_subs = await self.topic_registry.find_all(resolved_topic)
            local_match = next(
                (
                    s
                    for s in all_subs
                    if self._sub_owner_active(s)
                    and self._sub_accepts_local(s)
                    and self._sub_accepts_author(s, publisher.plugin_name)
                ),
                None,
            )
        else:
            local_match = None

        if local_match is None:
            # R2-KK-8: short-circuit when the publisher's effective
            # hosts filter is local-only. Without this guard we'd
            # iterate every remote candidate, apply filters, and emit
            # a "no subscriber matches" error that misleadingly
            # suggests the event system also searched network peers.
            if eff_hosts == "local":
                self._internal_emit(
                    "_core/event/requested",
                    publisher=publisher.plugin_name,
                    topic=resolved_topic,
                    target_count=0,
                    ts=now_ts,
                )
                raise RequestException(
                    f"request_event {event_id!r}: no local subscriber "
                    f"matches resolved topic {resolved_topic!r} "
                    f"(eff_hosts='local' — remote peers not searched)"
                )

            # PR3 Stage C step 19 — remote dispatch fall-through (locked
            # #6 + #13). Iterate _inbound_global_order in C11 insertion
            # order, apply ALL filters, try each surviving candidate.
            # Snapshot ``nm = self.network`` once (Commit 2b cycle 2
            # MED-B): mid-block hot-reload would otherwise leak calls
            # onto a stopped NM. None falls through to the bottom
            # ``raise RequestException("no subscriber matches...")``.
            #
            # B-073 Step 8: ``candidates`` + ``request_uuid`` initialized
            # OUTSIDE the networking sub-block so (a) the emit fires
            # even on the networking-disabled path with target_count=0,
            # and (b) ``request_uuid`` is bound for the second
            # networking guard's dispatch loop even if observer-driven
            # state flips networking between the two guards.
            from uuid import uuid4 as _uuid4
            from .notifier import TopicRegistry as _TR

            candidates: list = []
            request_uuid = _uuid4().hex
            nm = self.network
            if (
                getattr(self, "networking_enabled", False)
                and nm is not None
                and getattr(nm, "is_ready", False)
            ):
                async with nm._adverts_struct_lock:
                    cands_raw = list(nm._inbound_global_order.items())

                for (peer_hostname, _sub_uuid), advert in cands_raw:
                    node = next(
                        (n for n in list(nm.nodes) if n.hostname == peer_hostname),
                        None,
                    )
                    if node is None:
                        continue
                    try:
                        if not (node.enabled and await node.is_alive()):
                            continue
                    except Exception:
                        continue
                    if not nm._hosts_match(eff_hosts, eff_blocked, peer_hostname):
                        continue
                    if not self._sub_accepts_remote_publisher(
                        advert, self.hostname, publisher.plugin_name
                    ):
                        continue
                    if not self._sub_accepts_author(advert, publisher.plugin_name):
                        continue
                    if not _TR._topic_matches(advert.topic_pattern, resolved_topic):
                        continue
                    candidates.append((peer_hostname, advert, node))

            # B-073 Step 8 emit: event_requested on no-local-match path.
            # target_count covers all 3 sub-paths (networking disabled
            # → 0; networking on but no candidates → 0; networking on
            # with candidates → N).
            self._internal_emit(
                "_core/event/requested",
                publisher=publisher.plugin_name,
                topic=resolved_topic,
                target_count=len(candidates),
                ts=now_ts,
            )

            # B-074 Step 10 verbose log: no-local-match branch.
            if publisher.verbose_notifier:
                self._logger.debug(
                    "request_event %s topic=%r no local match, "
                    "falling through to %d remote candidates",
                    event_id,
                    resolved_topic,
                    len(candidates),
                )

            if (
                getattr(self, "networking_enabled", False)
                and nm is not None
                and getattr(nm, "is_ready", False)
            ):
                last_exc: Optional[BaseException] = None
                for peer_hostname, advert, node in candidates:
                    try:
                        return await nm.request_event_remote(
                            node.IP,
                            resolved_topic,
                            payload,
                            publisher.plugin_name,
                            publisher.plugin_uuid,
                            self.hostname,
                            now_ts,
                            request_uuid,
                            timeout=timeout,
                        )
                    except (NetworkRequestException, NoLocalSubException) as exc:
                        last_exc = exc
                        continue  # locked #6 fall-through
                    except RequestException:
                        raise

                # All candidates exhausted (or none) — propagate.
                if last_exc is not None:
                    raise RequestException(
                        f"request_event {event_id!r}: no handler found / all "
                        f"unreachable (last: {last_exc})"
                    )

            raise RequestException(
                f"request_event {event_id!r}: no subscriber matches resolved "
                f"topic {resolved_topic!r}"
            )

        # B-073 Step 8 emit: event_requested on local-match path.
        self._internal_emit(
            "_core/event/requested",
            publisher=publisher.plugin_name,
            topic=resolved_topic,
            target_count=1,
            ts=now_ts,
        )

        # B-074 Step 10 verbose log: local-match branch.
        if publisher.verbose_notifier:
            self._logger.debug(
                "request_event %s topic=%r matched local sub uuid=%s, " "dispatching",
                event_id,
                resolved_topic,
                local_match.sub_uuid,
            )

        request = await self._fanout_sub(
            sub=local_match,
            publisher=publisher,
            resolved_topic=resolved_topic,
            payload=payload,
            kind="request_event",
            timestamp=now_ts,
            timeout=timeout,
            caller_chain=_caller_chain,
        )

        try:
            result, error, _ = await request.wait_for_result_async()
            if error:
                raise RequestException(result)
            return result
        finally:
            # B-073 Session 2 Step 3: done-callback eviction. Was
            # ``await request.set_collected()``; migrated to direct sync
            # pop. Defensive — _process_request's producer-side finally
            # and _fanout_sub._run_and_collect's finally both also pop
            # the same Request id. All three pops are idempotent under
            # ``pop(key, None)``. Triple-pop is harmless.
            self.requests.pop(request.id, None)

    @log_errors
    def request_event_sync(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Sync variant of request_event (C16). C10: capture caller's
        _sync_call_chain on the WORKER thread before scheduling."""
        # Phase 2b: poison fail-fast (see Plexus.execute_sync).
        if getattr(_held_permit, "poisoned", False):
            raise RequestException(
                "sync bridge gave up its execution permit under "
                "saturation/shutdown; this call chain must unwind (do not "
                "make further sync-bridge calls)."
            )
        # C-004: same-thread deadlock guard.
        self._check_not_loop_thread("request_event_sync")
        chain = getattr(_sync_call_chain, "chain", ())
        # Rate-limiter Step 2a: carry the originating sync handler's IDENTITY
        # across the bridge (distinct from the flat cycle-detection `chain`).
        _req_coro = self._with_caller_chain(
            current_caller_chain(),
            self.request_event(
                publisher,
                event_id,
                payload,
                topic_vars,
                hosts,
                blocked_hosts,
                timeout,
                _caller_chain=chain,
            ),
        )
        future = asyncio.run_coroutine_threadsafe(
            _req_coro,
            self.main_event_loop,
        )
        # R2-FF-1: bound the worker-thread wait — derive from the
        # request timeout (+ 5s grace) or a generous default.
        wait_timeout = (timeout + 5.0) if isinstance(timeout, (int, float)) else 60.0
        # Phase 2b: free E while parked; _bridge_wait owns cancel-on-timeout.
        return _bridge_wait(future, wait_timeout)

    @async_gen_log_errors
    async def request_event_stream(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
        timeout: Optional[float] = None,
        *,
        _caller_chain: Optional[tuple] = None,
    ) -> Any:
        """Streaming variant of request_event. First yield is wrapped
        in Event metadata (LOCKED I); subsequent yields raw."""
        # C1 ORDER OF OPERATIONS: lookup → enabled → payload → resolve.
        event_entry = self._lookup_event(publisher, event_id)
        if not event_entry.get("enabled", True):
            raise RequestException(f"event {event_id!r} disabled (C2)")
        if payload is None:
            payload = {}
        resolved_topic, _ = self._resolve_topic_for_event(
            publisher, event_id, topic_vars, event_entry=event_entry
        )

        # Validate caller-supplied hosts/blocked_hosts (parity with
        # publish_event/request_event; events: defaults pre-normalized
        # at YAML load).
        if hosts is not None:
            hosts = _normalize_hosts(
                hosts,
                param_name="request_event_stream hosts",
                default=None,
            )
        if blocked_hosts is not None:
            blocked_hosts = _normalize_hosts(
                blocked_hosts,
                param_name="request_event_stream blocked_hosts",
                default=None,
                is_blocked=True,
            )

        # Publisher-level hosts gate (same as request_event): skip local
        # match entirely when publisher's hosts filter excludes local;
        # fall through directly to Stage C remote dispatch (locked #18
        # item 8).
        eff_hosts = hosts if hosts is not None else event_entry.get("hosts")
        eff_blocked = (
            blocked_hosts
            if blocked_hosts is not None
            else event_entry.get("blocked_hosts")
        )
        _warn_redundant_host_combos(eff_hosts, eff_blocked, self._logger)
        local_targets = self._publisher_targets_local(eff_hosts, eff_blocked)

        # Capture timestamp once (consistency with publish_event /
        # request_event).
        now_ts = time.time()

        # C-077: emit phase="started" so observers can build a complete
        # stream-lifecycle picture (started → first_chunk → ended) even
        # when the stream terminates early or fails before producing a
        # first chunk. target_count is the local+remote candidate count
        # at dispatch time. The full match set isn't known yet on the
        # local-match branch (we short-circuit to local), so emit the
        # count after the routing decision below — done here as a
        # pre-routing scaffold to capture the dispatch attempt itself.
        self._internal_emit(
            "_core/event/streamed",
            publisher=publisher.plugin_name,
            topic=resolved_topic,
            phase="started",
            ts=time.time(),
        )

        # Apply the same sub-level filter as publish_event /
        # request_event so subs with hosts="remote" or blocked_authors
        # filtering us out are skipped (LOCKED H). Only run local-match
        # when publisher actually targets local.
        if local_targets:
            all_subs = await self.topic_registry.find_all(resolved_topic)
            local_match = next(
                (
                    s
                    for s in all_subs
                    if self._sub_owner_active(s)
                    and self._sub_accepts_local(s)
                    and self._sub_accepts_author(s, publisher.plugin_name)
                ),
                None,
            )
        else:
            local_match = None
        if local_match is None:
            # PR3 Stage C step 20 — remote dispatch fall-through (locked
            # #6 + #13). Pre-first-chunk fall-through ONLY; mid-stream
            # NetworkRequestException terminates without fall-through to
            # preserve the Event-first invariant.
            # Snapshot ``nm = self.network`` once (Commit 2b cycle 2
            # MED-B): mid-block hot-reload would otherwise leak calls
            # onto a stopped NM. None falls through to the bottom
            # ``raise RequestException("no subscriber matches...")``.
            # C-077: wrap the whole remote-dispatch block in try/finally
            # so the ``phase="ended"`` emit fires regardless of which
            # exit path is taken (empty-stream return, successful
            # completion return, RequestException no-match raise,
            # all-peers-failed raise, NetworkRequestException reraise).
            # Without this, the local-only inner finally at the end of
            # this method only covers the local-match branch; remote
            # streams produced no ``ended`` emit and observers couldn't
            # close out the lifecycle.
            try:
                # R2-KK-8: short-circuit when the publisher's effective
                # hosts filter is local-only. Iterating remote candidates
                # is wasted work and emits a misleading "no subscriber"
                # error suggesting peers were searched. The raise inside
                # the try/finally keeps the ``phase="ended"`` emit.
                if eff_hosts == "local":
                    raise RequestException(
                        f"request_event_stream {event_id!r}: no local "
                        f"subscriber matches resolved topic "
                        f"{resolved_topic!r} (eff_hosts='local' — remote "
                        f"peers not searched)"
                    )

                nm = self.network
                if (
                    getattr(self, "networking_enabled", False)
                    and nm is not None
                    and getattr(nm, "is_ready", False)
                ):
                    from uuid import uuid4 as _uuid4
                    from .notifier import TopicRegistry as _TR

                    request_uuid = _uuid4().hex

                    async with nm._adverts_struct_lock:
                        cands_raw = list(nm._inbound_global_order.items())

                    candidates = []
                    for (peer_hostname, _sub_uuid), advert in cands_raw:
                        node = next(
                            (n for n in list(nm.nodes) if n.hostname == peer_hostname),
                            None,
                        )
                        if node is None:
                            continue
                        try:
                            if not (node.enabled and await node.is_alive()):
                                continue
                        except Exception:
                            continue
                        if not nm._hosts_match(eff_hosts, eff_blocked, peer_hostname):
                            continue
                        if not self._sub_accepts_remote_publisher(
                            advert, self.hostname, publisher.plugin_name
                        ):
                            continue
                        if not self._sub_accepts_author(advert, publisher.plugin_name):
                            continue
                        if not _TR._topic_matches(advert.topic_pattern, resolved_topic):
                            continue
                        candidates.append((peer_hostname, advert, node))

                    last_exc: Optional[BaseException] = None
                    for peer_hostname, advert, node in candidates:
                        agen = nm.request_event_stream_remote(
                            node.IP,
                            resolved_topic,
                            payload,
                            publisher.plugin_name,
                            publisher.plugin_uuid,
                            self.hostname,
                            now_ts,
                            request_uuid,
                            timeout=timeout,
                        )
                        # Tee first chunk in an isolated try/except so that
                        # ONLY pre-first-chunk failures fall through (locked
                        # #6 strict). Mid-stream errors propagate verbatim.
                        try:
                            first = await agen.__anext__()
                        except StopAsyncIteration:
                            # Empty stream — degenerate but legal. Treat as
                            # successful with zero items.
                            return
                        except (NetworkRequestException, NoLocalSubException) as exc:
                            last_exc = exc
                            continue
                        except RequestException:
                            raise

                        # First chunk yielded — committed to this peer; no
                        # fall-through past this point. C-077: emit
                        # phase="first_chunk" so observers see the
                        # commitment point on the remote path (the local
                        # path emits the equivalent inside
                        # _process_request_event_stream).
                        self._internal_emit(
                            "_core/event/streamed",
                            publisher=publisher.plugin_name,
                            topic=resolved_topic,
                            phase="first_chunk",
                            ts=time.time(),
                        )
                        yield first
                        async for chunk in agen:
                            yield chunk
                        return

                    if last_exc is not None:
                        raise RequestException(
                            f"request_event_stream {event_id!r}: no handler "
                            f"found / all unreachable (last: {last_exc})"
                        )

                raise RequestException(
                    f"request_event_stream {event_id!r}: no subscriber matches "
                    f"resolved topic {resolved_topic!r}"
                )
            finally:
                # C-077: phase="ended" emit covers all remote-path exits.
                self._internal_emit(
                    "_core/event/streamed",
                    publisher=publisher.plugin_name,
                    topic=resolved_topic,
                    phase="ended",
                    ts=time.time(),
                )

        # B-074 Step 10 verbose log: stream local-match opening.
        if publisher.verbose_notifier:
            self._logger.debug(
                "request_event_stream %s topic=%r matched local sub uuid=%s, "
                "opening stream",
                event_id,
                resolved_topic,
                local_match.sub_uuid,
            )

        # Route through find_endpoint so the C18 accessible_by_other_plugins
        # access check applies on the streaming path too. Pass
        # requester_id=local_match.plugin_uuid (the SUB OWNER's identity)
        # so cross-plugin subs to private endpoints are denied
        # consistently with the non-streaming request_event path.
        # NOTE: find_endpoint returns (None, None, None) on no-match
        # (NOT bare None), so check the unpacked plugin slot.
        target_plugin, endpoint, _node = await self.find_endpoint(
            access_name=local_match.target_access_name,
            hosts="local",
            plugin_uuid=local_match.target_plugin_uuid,
            requester_id=local_match.plugin_uuid,
            target_plugin=local_match.target_plugin,
        )
        if target_plugin is None or endpoint is None:
            raise RequestException(
                f"request_event_stream {event_id!r}: target endpoint "
                f"{local_match.target_access_name!r} not found on "
                f"{local_match.target_plugin!r} (or access denied per C18)"
            )

        # R1 HIGH-3 fix: Stage O readiness gate also applies on the
        # LOCAL request_event_stream path. Without this gate, fan-out
        # from a publisher to a subscriber that is mid-on_enable would
        # bypass _process_request_stream's gate entirely (this path
        # iterates the generator directly) and hit a not-yet-ready
        # handler. Same skip rules as _process_request_stream — remote
        # plugins (no readiness events) and self-calls (Q23 — avoid
        # gating against own _lifecycle_ready from inside on_enable).
        if (
            isinstance(target_plugin, Plugin)
            and target_plugin.plugin_uuid != publisher.plugin_uuid
        ):
            try:
                await self._wait_for_plugin_ready(target_plugin)
            except asyncio.TimeoutError as e:
                ready_timeout = getattr(
                    self,
                    "plugin_ready_timeout",
                    DEFAULT_PLUGIN_READY_TIMEOUT,
                )
                raise RequestException(
                    f"request_event_stream {event_id!r}: target plugin "
                    f"{target_plugin.plugin_name!r} not ready within "
                    f"{ready_timeout}s"
                ) from e

        internal = endpoint.get("internal_name") or local_match.target_access_name
        func = getattr(target_plugin, internal, None)
        if func is None or not (
            inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(func)
        ):
            raise RequestException(
                f"request_event_stream {event_id!r}: handler is not a "
                f"generator function (use request_event instead)"
            )

        # Build the Event metadata for first-chunk wrapping.
        event_meta = Event(
            topic=resolved_topic,
            payload=payload,
            author=publisher.plugin_name,
            author_id=publisher.plugin_uuid,
            author_host=self.hostname,
            subscription_id=(
                local_match.declared_id
                if local_match.declared_id is not None
                else local_match.sub_uuid
            ),
            timestamp=now_ts,
        )

        # B-054 fix: route through GeneratorRequest + _spawn_tracked
        # so close()'s 30s drain catches the in-flight stream and
        # pop_plugin's pending-request walk can fail the Request when
        # the target plugin is unloaded mid-stream.
        #
        # CRITICAL — pass timeout=None to GeneratorRequest. The
        # timeout we received is enforced by the producer's own
        # _residual() (loop.time() monotonic deadline). If we also
        # passed it here, get_queue_stream (utils.py:1999/2013)
        # would enforce it independently with wall-clock time.time(),
        # producing a double-trigger race. The current inline code
        # had NO consumer-side get_queue_stream timeout, so timeout=
        # None here preserves single-source-of-truth semantics.
        request = GeneratorRequest(
            author_host=self.hostname,
            plugin=local_match.target_plugin or local_match.plugin_name,
            method=local_match.target_access_name,
            args=payload,
            plugin_uuid=local_match.target_plugin_uuid,
            target_hosts="local",
            blocked_hosts=None,
            author=publisher.plugin_name,
            author_id=publisher.plugin_uuid,
            timeout=None,  # B-054: producer enforces, see above
            request_id=None,
            event_loop=self.main_event_loop,
            kind="request_event_stream",
            topic=resolved_topic,
            origin_subscription_id=event_meta.subscription_id,
            timestamp=now_ts,
            requester_id=local_match.plugin_uuid,
        )
        async with self.request_lock:
            self.requests[request.id] = request

        producer_task = self._spawn_tracked(
            self._process_request_event_stream(
                request,
                target_plugin,
                endpoint,
                event_meta,
                timeout=timeout,
                caller_chain=_caller_chain,
                verbose_notifier=publisher.verbose_notifier,
            ),
            name=f"event_stream:{request.target_plugin}.{request.target_method}<-{resolved_topic}",
        )
        request._producer_task = producer_task

        # B-074 Step 10: stream-end tracking for verbose log L5.
        chunk_count = 0
        exit_reason = "normal"
        try:
            try:
                async for result, error, _ in request.get_queue_stream():
                    if error:
                        self._logger.warning(
                            f"Error in request_event_stream {event_id!r} "
                            f"(GenReq-ID: {request.id}): {result}. You can "
                            f"check the logs for this Req-ID."
                        )
                        exit_reason = "exception"
                        raise RequestException(result)
                    chunk_count += 1
                    yield result
            except GeneratorExit:
                # Consumer broke out of `async for chunk in ...:` early.
                exit_reason = "consumer_break"
                raise
            except BaseException:
                if exit_reason == "normal":
                    exit_reason = "exception"
                raise
        finally:
            # B-073 Step 8 emit: event streamed ended. Captures all 3
            # exit paths (natural exhaustion, consumer break, exception).
            self._internal_emit(
                "_core/event/streamed",
                publisher=publisher.plugin_name,
                topic=resolved_topic,
                phase="ended",
                ts=time.time(),
            )
            # B-074 Step 10 verbose log: stream ended.
            if publisher.verbose_notifier:
                self._logger.debug(
                    "request_event_stream %s topic=%r stream ended " "(chunks=%d, %s)",
                    event_id,
                    resolved_topic,
                    chunk_count,
                    exit_reason,
                )
            # Mark for cleanup. Cancels the producer task on early
            # break (B-002 pattern). Mirrors execute_stream's pattern.
            await request.set_collected()

    @gen_log_errors
    def request_event_stream_sync(
        self,
        publisher: Plugin,
        event_id: str,
        payload: Any = None,
        topic_vars: Optional[Dict[str, str]] = None,
        hosts: Union[str, list, None] = None,
        blocked_hosts: Union[str, list, None] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Sync variant of request_event_stream (C16). Iterates the
        async generator on main_event_loop and yields chunks back to
        the caller thread.

        C10: capture _sync_call_chain.chain on the WORKER thread before
        scheduling the async generator on the loop. The loop thread can't
        see this threadlocal; sync-gen handler invocations inside the
        stream re-set the chain on each next() call (see
        request_event_stream sync branch).
        """
        # Phase 2b: poison fail-fast (see Plexus.execute_sync). Fires on the
        # first next() of this generator.
        if getattr(_held_permit, "poisoned", False):
            raise RequestException(
                "sync bridge gave up its execution permit under "
                "saturation/shutdown; this call chain must unwind (do not "
                "make further sync-bridge calls)."
            )
        # C-004: same-thread deadlock guard.
        self._check_not_loop_thread("request_event_stream_sync")
        chain = getattr(_sync_call_chain, "chain", ())
        async_gen = self.request_event_stream(
            publisher,
            event_id,
            payload,
            topic_vars,
            hosts,
            blocked_hosts,
            timeout,
            _caller_chain=chain,
        )
        # Rate-limiter Step 2a: capture the originating sync handler's IDENTITY
        # once (constant across the stream); re-seated loop-side on each pull
        # below so the open-charge (first __anext__) attributes to the right
        # caller. Distinct from the flat cycle-detection `chain` above.
        _es_cap = current_caller_chain()

        try:
            while True:
                # R4-YY-3: mirror the aclose() bounded-wait pattern below.
                # Without a timeout a stalled handler blocks the caller's
                # worker thread forever. Use timeout+5s slack when the
                # caller passed a per-stream budget, else a 60s default
                # so a runaway handler can't deadlock the worker.
                next_fut = asyncio.run_coroutine_threadsafe(
                    self._with_caller_chain(_es_cap, async_gen.__anext__()),
                    self.main_event_loop,
                )
                next_timeout = (
                    timeout + 5.0
                    if isinstance(timeout, (int, float))
                    else 60.0
                )
                # Phase 2b: free E around each per-chunk park, HELD during
                # the yield (the body runs when it yields). _bridge_wait owns
                # cancel-on-timeout; StopAsyncIteration still propagates.
                try:
                    chunk = _bridge_wait(next_fut, next_timeout)
                except StopAsyncIteration:
                    break
                yield chunk
        finally:
            # Close the underlying async generator if the caller breaks
            # out of the for loop early (without exhausting it). Without
            # this aclose() the async gen's try/finally / async with
            # blocks never run, leaking resources.
            #
            # B-055 fix: bound the wait with a 5s timeout so a hanging
            # handler `finally`/`async with` cleanup can't block this
            # caller's worker thread forever. On expiry, cancel the
            # orphaned aclose task so it doesn't leak on the event loop;
            # CancelledError propagates into the handler's hung await
            # and unblocks the cleanup eventually.
            # concurrent.futures.TimeoutError is what
            # Future.result(timeout=...) raises on expiry (a separate
            # class from asyncio.TimeoutError, even though they alias to
            # builtins.TimeoutError on Python 3.11+).
            fut = asyncio.run_coroutine_threadsafe(
                async_gen.aclose(), self.main_event_loop
            )
            try:
                # Phase 2b: free E during aclose cleanup; _bridge_wait owns
                # cancel-on-timeout.
                _bridge_wait(fut, 5.0)
            except concurrent.futures.TimeoutError:
                self._logger.warning(
                    "request_event_stream_sync: aclose() exceeded 5s — "
                    "underlying handler's finally/async-with cleanup may "
                    "be blocked; cancelled orphan task"
                )
            except Exception:
                pass

    async def subscribe_event(
        self,
        topic: str,
        plugin_name: str,
        plugin_uuid: str,
        target_access_name: str,
        target_plugin: Optional[str] = None,
        target_plugin_uuid: Optional[str] = None,
        hosts: Union[str, list, None] = "any",
        blocked_hosts: Union[str, list, None] = None,
        authors: Union[str, list, None] = None,
        blocked_authors: Union[str, list, None] = None,
        declared_id: Optional[str] = None,
        enabled: bool = True,
    ) -> str:
        """Register a runtime subscription (NEW PR3 API). Returns sub_uuid.

        W5-Q3 / W5-Q1: ``enabled`` and ``declared_id`` are now first-class
        parameters. Callers (including the legacy ``Plexus.subscribe``
        alias) forward them through; previously both were hardcoded
        (``enabled=True``, ``declared_id=None``) and a caller that passed
        non-default values via the shim silently lost them.
        Adds the sub_uuid to the owning plugin's _sub_uuids list so the
        on_disable wrapper can include it in the unregister sweep.

        Topic + filter values are validated with the same rules YAML
        load applies (LOCKED L #2 + LOCKED IN — PUBLISHER hosts) so a
        runtime ``subscribe(\"sensor/abc*\", ...)`` (embedded `*`) or
        ``subscribe(\"\", ...)`` (empty) doesn't silently produce a
        permanently dead subscription.
        """
        topic = _validate_subscription_topic(
            topic, context=f"runtime subscribe ({plugin_name})"
        )
        # Defensive: target_access_name must be a non-empty identifier-style
        # string. The Plugin.subscribe wrapper already checks this for the
        # standard call path, but direct Plexus.subscribe_event calls
        # (test code, future internal callers) bypass the wrapper. Without
        # this guard, an empty string silently produces a permanently dead
        # subscription — find_endpoint(access_name="") returns
        # (None,None,None) every time with a confusing "endpoint not found"
        # error far from the bad subscribe call.
        if not isinstance(target_access_name, str) or not target_access_name.strip():
            raise ValueError(
                f"runtime subscribe ({plugin_name}): target_access_name "
                f"must be a non-empty string; got "
                f"{type(target_access_name).__name__}={target_access_name!r}"
            )
        hosts = _normalize_hosts(
            hosts,
            param_name=f"runtime subscribe ({plugin_name}).hosts",
            default="any",
        )
        blocked_hosts = _normalize_hosts(
            blocked_hosts,
            param_name=f"runtime subscribe ({plugin_name}).blocked_hosts",
            default=None,
            is_blocked=True,
        )
        authors = _normalize_authors(
            authors,
            param_name=f"runtime subscribe ({plugin_name}).authors",
            default=None,
        )
        blocked_authors = _normalize_authors(
            blocked_authors,
            param_name=f"runtime subscribe ({plugin_name}).blocked_authors",
            default=None,
        )

        sub_uuid = await self.topic_registry.subscribe(
            topic_pattern=topic,
            plugin_name=plugin_name,
            plugin_uuid=plugin_uuid,
            target_plugin=target_plugin or plugin_name,
            target_access_name=target_access_name,
            target_plugin_uuid=target_plugin_uuid,
            hosts=hosts,
            blocked_hosts=blocked_hosts,
            authors=authors,
            blocked_authors=blocked_authors,
            declared_id=declared_id,
            enabled=enabled,
        )

        owner = self.plugins_by_uuid.get(plugin_uuid)
        if owner is not None and hasattr(owner, "_sub_uuids"):
            owner._sub_uuids.append(sub_uuid)

        # PR3 Stage C add-delta hook (locked #18 item 3). No-op when
        # networking is disabled or not yet ready.
        # Snapshot nm (Commit 2b cycle 2 MED-B): single-call site;
        # snapshotting matches the loop-site pattern for consistency
        # and tightens the guard-vs-call window in case of mid-block
        # hot-reload.
        nm = self.network
        if (
            getattr(self, "networking_enabled", False)
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            sub = await self.topic_registry.get_subscription(sub_uuid)
            if sub is not None:
                try:
                    await nm.broadcast_local_sub_added(sub)
                except Exception:
                    self._logger.debug(
                        "subscribe_event: broadcast add-delta failed",
                        exc_info=True,
                    )

        return sub_uuid

    async def unsubscribe_event(self, sub_uuid: str) -> bool:
        """Remove a runtime subscription (NEW PR3 API).

        Returns True if found and removed. Cleans up the owning plugin's
        _sub_uuids list as a side-effect (best-effort lookup).
        """
        sub = await self.topic_registry.get_subscription(sub_uuid)

        # PR3 Stage C remove-delta hook (locked #18 item 4). Send BEFORE
        # the registry drop so the broadcast still has access to the
        # sub object and our peers see the remove cleanly.
        # Snapshot nm (Commit 2b cycle 2 MED-B): single-call site,
        # snapshotting for consistency with the loop-site pattern.
        nm = self.network
        if (
            sub is not None
            and getattr(self, "networking_enabled", False)
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            try:
                await nm.broadcast_local_sub_removed(sub)
            except Exception:
                self._logger.debug(
                    "unsubscribe_event: broadcast remove-delta failed",
                    exc_info=True,
                )

        ok = await self.topic_registry.unsubscribe(sub_uuid)
        if ok and sub is not None:
            owner = self.plugins_by_uuid.get(sub.plugin_uuid)
            if owner is not None and hasattr(owner, "_sub_uuids"):
                try:
                    owner._sub_uuids.remove(sub_uuid)
                except ValueError:
                    pass
        return ok

    async def set_subscription_enabled(self, sub_uuid: str, enabled: bool) -> bool:
        """Toggle a subscription's enabled flag at runtime.

        Mutation happens atomically inside ``topic_registry._lock`` via
        ``TopicRegistry.set_subscription_enabled`` (notifier.py) which
        returns ``(sub_or_None, changed)``. When networking is enabled
        and ready, this method then broadcasts an add-delta to peers
        on a True transition (peer starts advertising the sub) or a
        remove-delta on a False transition (peer stops). Broadcasts
        happen OUTSIDE the registry lock, per the framework's
        lock-ordering rule (mirrored from the
        ``subscribe_event``/``unsubscribe_event`` patterns in this
        module; see the lock-ordering comment block at
        ``_get_lifecycle_lock`` for the
        "no-network-I/O-under-registry-lock" invariant).

        After mutation + broadcast attempt, emits
        ``_core/subscription/state_changed`` so the Subscriptions
        browser + Live-stream can react. Emit fires ONLY when the flag
        actually changed (idempotent no-op call returns True without
        emitting — observers cannot distinguish "no-op-True" from
        "toggled-True" via the boolean return alone, but the absence of
        an emit on no-op lets them tell).

        Emit depth (per ``_internal_emit``'s ``_EMIT_DEPTH`` context
        var, ``_MAX_EMIT_DEPTH=5``): a single toggle call adds depth=1
        for the single ``_core/subscription/state_changed`` emit. If an
        observer of that topic chains back into this method, the
        nested emit observes depth=2. Any future fan-out that extends
        this chain MUST stay clear of the depth-5 cap.

        Returns:
            True if ``sub_uuid`` was found in the registry — covers both
                the "toggled successfully" path and the "no-op (already
                at target value)" path.
            False if ``sub_uuid`` was not in the registry (pop_plugin
                race or invalid uuid).

        Broadcast failure is logged at DEBUG and NOT propagated; local
        state mutated successfully, peer eventual-consistency via
        heartbeat handles any peer-side drift. Mirrors existing
        ``subscribe_event`` / ``unsubscribe_event`` semantics.
        """
        sub, changed = await self.topic_registry.set_subscription_enabled(
            sub_uuid, enabled
        )
        if sub is None:
            return False
        if not changed:
            return True  # no-op — no broadcast, no emit
        self._logger.info(
            "Subscription %s enabled=%s",
            sub_uuid,
            enabled,
        )
        # Snapshot nm once. Mid-call hot-reload would otherwise leak the
        # broadcast onto a stopped NM; consistent with the pattern used
        # by subscribe_event / unsubscribe_event for the same reason.
        nm = self.network
        if (
            getattr(self, "networking_enabled", False)
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            try:
                if enabled:
                    await nm.broadcast_local_sub_added(sub)
                else:
                    await nm.broadcast_local_sub_removed(sub)
            except Exception:
                self._logger.debug(
                    "set_subscription_enabled: broadcast failed",
                    exc_info=True,
                )
        self._internal_emit(
            "_core/subscription/state_changed",
            sub_uuid=sub_uuid,
            enabled=enabled,
            ts=time.time(),
        )
        return True

    async def set_event_enabled(
        self, plugin_name: str, event_id: str, enabled: bool
    ) -> bool:
        """Toggle an event's ``enabled`` flag at runtime. Local-only —
        events are not advertised to peers (publishers don't advertise;
        only subscribers do).

        Async despite no awaited I/O: required so the ``_internal_emit``
        call runs on the loop thread per the observer contract
        (sync observers must NOT be dispatched from non-loop threads;
        see the ``internal_observe`` docstring). TUI
        callers bridge via ``_run_on_main`` like for set_subscription_enabled.

        Emits ``_core/event/state_changed`` so the Events catalogue +
        Live-stream can react. Emit fires only on actual state change
        (idempotent no-op returns True without emitting).

        Idempotency caveat — UNDER CONCURRENT TOGGLE: the
        read-modify-write sequence ``entry.get("enabled") != bool(enabled)``
        → ``entry["enabled"] = bool(enabled)`` is NOT atomic. Two
        concurrent calls with the same target value can both observe
        "needs change" between each other's writes and both emit. For
        the intended TUI single-actor use case this race is
        unobservable; high-concurrency callers should serialize.

        TOCTOU note: a concurrent ``_pop_plugin_under_lock`` between
        ``self.plugins.get`` and the mutation orphans the events dict.
        The mutation succeeds on the orphan but is invisible to future
        dispatch (``publish_event`` / ``request_event`` won't find the
        entry — the plugin's events dict has been GC'd from the
        framework's perspective). The emit fires correctly to other
        observers, but the popped plugin's own observers were already
        cleared by ``_unobserve_plugin`` at pop time, so they won't see
        the emit either. Accepted because: (a) operator clicked toggle
        on an event they could see — pop is rare in normal use,
        (b) guarding with plugin_lock would over-serialize a debug-only
        path.

        Returns:
            True if the ``(plugin, event_id)`` pair exists at call time
                (covers toggled + no-op paths).
            False if either the plugin is not loaded or the event_id is
                not declared on it.
        """
        plugin = self.plugins.get(plugin_name)
        if plugin is None:
            return False
        events = getattr(plugin, "events", None) or {}
        entry = events.get(event_id)
        if entry is None:
            return False
        if bool(entry.get("enabled", True)) == bool(enabled):
            return True  # no-op — no emit
        entry["enabled"] = bool(enabled)
        self._logger.info(
            "Event %s/%s enabled=%s",
            plugin_name,
            event_id,
            bool(enabled),
        )
        self._internal_emit(
            "_core/event/state_changed",
            plugin_name=plugin_name,
            event_id=event_id,
            enabled=bool(enabled),
            ts=time.time(),
        )
        return True
