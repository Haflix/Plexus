import os
import socket
import sys

os.environ.setdefault("PYTHONUTF8", "1")  # UTF-8 mode: all open() default to utf-8
if hasattr(sys.stdout, "reconfigure"):  # Reconfigure console streams to UTF-8
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import contextlib
import functools
import importlib
import inspect
import asyncio
import time
import threading
import traceback
from collections import deque
import concurrent.futures
from typing import Any, Optional, Callable, Union, Dict, List, Set, Tuple
import yaml

from .exceptions import (
    ConfigException,
    RequestException,
    CapabilityException,
    RateLimitException,
)
from .networking_classes import Node, RemotePlugin
from .utils import LogUtil, Request, Plugin, ConfigUtil, GeneratorRequest, Event
from .decorators import (
    log_errors,
    handle_errors,
    async_log_errors,
    async_handle_errors,
    async_gen_log_errors,
    async_gen_handle_errors,
    gen_log_errors,
    gen_handle_errors,
)
from .networking import NetworkManager
from .notifier import TopicRegistry, SyncDispatcher
from .plugin_state import State, Phase, ErrorRecord, PluginState
from . import __version__
from .dependencies import (
    DependencySpec,
    DepResolutionResult,
    PLEXUS_SELF_NAME,
    parse_dependencies,
    resolve as _resolve_deps,
)

# Config-load / validation helpers were extracted to helpers/config.py
# (pure, stateless, no Plexus dependency). Re-exported here so existing
# ``from plexus.core import <helper>`` call sites - and the bare-name
# references inside class Plexus methods - keep resolving unchanged.
from .helpers.config import (  # noqa: F401  (re-export shim)
    _RESERVED_IDENTIFIER_NAMES,
    _validate_identifier_name,
    _OVERRIDE_SECTIONS,
    _STRICT_OVERRIDE_SECTIONS,
    _PLUGIN_LEVEL_OVERRIDE_FIELDS,
    _RESERVED_TEMPLATE_VARS,
    _TEMPLATE_VAR_RE,
    _resolve_load_time_template,
    _validate_topic_static,
    _validate_subscription_topic,
    _deep_merge_args,
    apply_overrides,
    _normalize_str_or_list,
    _normalize_hosts,
    _normalize_authors,
    _warn_redundant_host_combos,
    parse_capabilities,
    parse_rate_limits,
    parse_plugin_rate_limits,
)

# Cross-cutting runtime primitives (sync-call-chain threadlocal, the
# emit/execute recursion-guard ContextVars, and the plugin lifecycle
# timeout defaults) were extracted to runtime.py. Re-exported here so
# existing ``from plexus.core import <name>`` imports (utils.py pulls the
# timeouts) and the bare-name references inside class Plexus methods keep
# resolving unchanged.
from .runtime import (  # noqa: F401  (re-export shim)
    _sync_call_chain,
    DEFAULT_PLUGIN_READY_TIMEOUT,
    DEFAULT_PLUGIN_DISABLE_TIMEOUT,
    DEFAULT_PLUGIN_ENABLE_TIMEOUT,
    _EMIT_DEPTH,
    _MAX_EMIT_DEPTH,
    _EXECUTE_DEPTH,
    _MAX_EXECUTE_DEPTH,
    GatedExecutor,
    _bridge_wait,
    _held_permit,
    PLUGIN_EXECUTOR_THREAD_CEILING,
    SYNC_DISPATCHER_THREAD_CEILING,
    SYNC_STREAM_THREAD_CEILING,
    # Caller identity: framework-stamped caller-identity primitives.
    CallerIdentity,
    _sync_identity_chain,
    caller_chain_scope,
    seeded_sync_chain,
    current_caller_chain,
    establish_caller_chain,
    # Capability gate: capability gate primitives.
    _asserted_identity,
    evaluate_capability,
    asserted_identity_scope,
)
from .ratelimiter import (
    RateLimiter,
    charge_set,
    endpoint_key,
    event_key,
    validate_stream_weight,
    FRAMEWORK_IN_KEY,
    DIM_FRAMEWORK_IN,
    DIM_PLUGIN_IN,
    DIM_PLUGIN_OUT,
    DIM_ENDPOINT_IN,
    DIM_EVENT_OUT,
    DIM_SUB_IN,
    DIM_NODES_IN,
)

# The STATIC bucket dimensions a full rebuild fully enumerates from config + the
# live plugin set. These are the only dims that can ORPHAN when a plugin is
# removed (configure only adds): the rebuild prunes any static bucket it did not
# re-configure. Sub-IN is torn down explicitly on unsubscribe/pop; Nodes-IN is a
# dynamic runtime get-or-create -- neither is pruned here.
_RL_STATIC_DIMS = frozenset({
    DIM_FRAMEWORK_IN, DIM_PLUGIN_IN, DIM_PLUGIN_OUT, DIM_ENDPOINT_IN, DIM_EVENT_OUT,
})

# Step 5: reject-log suppression window (seconds). A runaway caller hitting a cap
# at many times its rate would otherwise emit one WARNING per rejected call and
# make the logger itself the bottleneck. The first reject per (dim, key) per
# window logs at WARNING; further rejects in the window only bump the per-bucket
# counter (which carries the true volume); the next reject AFTER the window emits
# a one-line summary of what was suppressed, then a fresh WARNING. Config-tunable
# is deferred -- a module constant is the v1 contract.
RL_REJECT_LOG_WINDOW = 10.0

# Identity-assertion audit suppression window (seconds). The capability gate
# emits a `_core/security/identity_asserted` bus event on every allowed assertion
# or deny; a hot impersonation or a denied-assertion flood would otherwise spam
# the audit stream. First emit per (real, asserted, denied) per window fires;
# in-window repeats only bump a counter; the next emit after the window carries
# the suppressed count (Section 13, the audit half of the reject-log suppression).
IDENTITY_AUDIT_WINDOW = 10.0
# Soft cap on the identity-audit side-table. On the DENY path the asserted name is
# caller-supplied, so a local grant-holder rotating distinct fake names could grow
# the table without bound; past this size, stale (window-elapsed) entries are
# pruned on the next emit. Generous so a legitimate working set never trips it.
_IDENTITY_AUDIT_MAX_KEYS = 4096

from .events import EventMixin


class Plexus(EventMixin):
    """Manages all plugins and facilitates communication between them."""

    def __init__(self, config_path: str):
        self.config_path = config_path

        # Pre-read config for logger bootstrap so the filter system has its
        # thresholds in place from the very first record. quickget_config
        # handles integrity failures; the try/except handles file-missing /
        # YAML parse errors — neither emits a log line at this point because
        # no logger exists yet, but load_config_yaml below will surface a
        # useful error if the YAML is genuinely broken.
        try:
            bootstrap_cfg = (
                ConfigUtil.quickget_config(config_path, fallback_value={}) or {}
            )
        except Exception:
            bootstrap_cfg = {}
        if not isinstance(bootstrap_cfg, dict):
            bootstrap_cfg = {}
        bootstrap_general = bootstrap_cfg.get("general", {})
        if not isinstance(bootstrap_general, dict):
            bootstrap_general = {}
        self._logger = LogUtil.create(
            log_level=bootstrap_general.get("console_log_level", "DEBUG"),
            file_level=bootstrap_general.get("file_log_level", "DEBUG"),
            logger_levels=bootstrap_general.get("logger_levels", {}),
        )

        self.yaml_config = None
        self.load_config_yaml(self.config_path)
        # change_level / change_file_level / apply_logger_levels_config now
        # live inside load_config_yaml so hot-reload picks up changes too.

        self.requests = {}
        self.request_lock = asyncio.Lock()
        # B-047 fix (Stage Q): task_list is currently-in-flight tasks
        # only. Per-task done_callback in _spawn_tracked evicts on
        # completion (replaces the previous 10s polling sweep that
        # left the list growing in the gap between sweeps + never
        # reclaimed hung tasks). recent_completed is a bounded buffer
        # of (name, started, completed, error) records for TUI / log
        # introspection of recently-finished tasks; counters provide
        # exact aggregate dispatch numbers even when bursts overflow
        # the deque.
        self.task_list: set = set()
        self.recent_completed: deque = deque(maxlen=200)
        self.tasks_started_total: int = 0
        self.tasks_completed_total: int = 0

        # Strong-ref pool for short fire-and-forget tasks (per-peer
        # publish dereg, NM accounting cleanup, advert acks). Separate
        # from task_list — these are best-effort cleanup work that
        # races shutdown and is NOT covered by the 30s in-flight
        # drain. See _spawn_fire_and_forget for the contract.
        self._fire_and_forget: set = set()

        # Master switch for framework-stamped caller identity
        # (runtime._caller_chain / _sync_identity_chain). When False (the
        # default) every push/pop at a framework->plugin dispatch is skipped, so
        # a default node pays zero per dispatch. It is turned on whenever a rate
        # limit OR a capability grant is configured (see
        # _recompute_capability_active); otherwise the identity machinery is
        # wired but inert. Tests force it True to exercise the stamping.
        self._identity_active: bool = False

        # Capability gate: capability grants + master switch. Grants map a
        # plugin name -> {"system_caller": bool, "impersonation": "caller" |
        # "ancestor" | [names] | None}, populated from the main-config
        # ``capabilities:`` section. The gate (_gate_author) is INERT when no
        # grant exists (author stays a plain routing label, the historical
        # behaviour). When any grant is configured, identity stamping must be on
        # so the gate can read the real caller -- _recompute_capability_active
        # turns _identity_active on. Tests inject grants directly.
        self._capability_grants: Dict[str, dict] = {}
        self._capability_active: bool = False
        # Identity-assertion audit suppression (the audit half of the Step-5
        # reject-log suppression; Section 13). Keyed by (real.uuid, asserted_name,
        # denied); value {"last_emit": monotonic_ts, "suppressed": int}. First
        # emit of an assertion/deny per window fires the bus event; in-window
        # repeats only bump the counter; the next emit after the window carries
        # the suppressed count so a hot impersonation (or a denied-assertion
        # flood) cannot spam the audit stream while the volume is preserved across
        # the active window. (A burst that fully STOPS leaves its final count
        # unflushed until the next emit for that key -- the deferred background
        # sweep would flush it; same tail tradeoff as the reject-log suppression.)
        # This is the RELATIVE window-counter variant (a `suppressed` counter
        # reset to 0 at each emit), which reads differently from `_rl_reject_log`'s
        # `rejected_at_warn` difference-of-counters variant: the reject path has an
        # external running counter (`Bucket.rejected`) to anchor to and this path
        # does not. Loop-side only (`_gate_author` runs synchronously on the
        # dispatch loop). Only touched when capabilities are active (zero-off).
        self._identity_audit_log: Dict[tuple, dict] = {}
        # yaml_config was loaded above; parse the capabilities: section now so
        # the gate is live from the first dispatch when grants are configured.
        self._load_capability_grants()

        # Rate limiter (Step 3). The limiter owns the token buckets keyed by
        # (dimension, key). Section 12 charge sites: the OUT sites
        # _dispatch_request + _create_gen_request_gated + the publish_event /
        # request_event / request_event_stream entries are WIRED (Step 3c); the
        # IN sites _call_endpoint (Step 3d) and the networking inbound handler
        # (Step 3e, Nodes-IN) will consult it once those steps land.
        # ``_rate_limits_active`` is the zero-overhead-off master
        # switch: False while no bucket is configured, so the charge path
        # short-circuits before any work. Like the capability gate, an active
        # limit needs caller-identity stamping (to attribute a charge to the real
        # caller / asserted identity), so _recompute_rate_limits_active turns
        # _identity_active on. Config-driven bucket setup arrives in Step 4; tests
        # configure buckets directly via self._rate_limiter.configure(...) then
        # call _recompute_rate_limits_active().
        self._rate_limiter = RateLimiter()
        self._rate_limits_active: bool = False
        # Internal flat rate-limit config (Step 4 / tests populate it; Step 4
        # flattens the YAML `rate_limits:` section into these). Kept SEPARATE
        # from the YAML because Sub-IN cannot be keyed by sub_uuid at config-write
        # time (the uuid is minted at registration) -- so sub limits are staged by
        # (plugin_name, declared_id) and resolved to a sub_uuid bucket in
        # _rebuild_charge_sets. nodes_in.default + stream_weight are handled
        # outside these dicts (the networking handler / the endpoint manifest).
        self._rate_limit_config: Dict[tuple, dict] = {}        # (dim, key) -> {max, window}
        self._rate_limit_sub_config: Dict[tuple, dict] = {}    # (plugin, declared_id) -> {max, window}
        # Step 4 plugin-declared layer. A plugin manifest may self-declare its
        # own limits (a top-level `rate_limits:` block); those are recomputed
        # FROM SCRATCH at the top of every _rebuild_charge_sets (from the loaded
        # plugins' stored _declared_rate_limits), kept SEPARATE from the two
        # base dicts above. The base dicts are the MAIN-config + test-injected
        # source of truth and are NEVER mutated by a rebuild; _rl_configure /
        # _rl_build_sub consult BASE FIRST, DECLARED SECOND, so main wins by
        # precedence, a removed plugin's declared limits vanish on the next
        # rebuild, and direct test injection into the base dicts is never
        # clobbered. framework_in / nodes_in have no declared layer (they are
        # operator-global, main-config only).
        self._rate_limit_config_declared: Dict[tuple, dict] = {}
        self._rate_limit_sub_config_declared: Dict[tuple, dict] = {}
        # Nodes-IN SIDEBAND (Step 3e). Per-remote-peer intake limits, kept apart
        # from the flat dicts because Nodes-IN keys are dynamic peer hostnames
        # unknown at config-write time. `{"default": {max, window}}` + optional
        # per-peer `{"<hostname>": {max, window}}`. Step 4 flattens YAML
        # `nodes_in:` into it; tests inject it directly. The per-peer bucket is
        # lazily get-or-created on first contact in `_rl_admit_inbound`.
        self._rate_limit_nodes_in_config: Dict[str, dict] = {}  # "default" | "<hostname>" -> {max, window}
        # Precomputed charge-sets, stored in PLEXUS-OWNED SIDE-TABLES (never on
        # the endpoint dict / Subscription -- those are pickle-shipped to peers,
        # which would leak live Bucket state onto the wire). The hot path reads
        # one of these by a key it already knows (no dict walk, no key building).
        self._rl_endpoint_in: Dict[tuple, list] = {}           # (plugin, access) -> [endpoint_in, plugin_in]
        self._rl_sub_in: Dict[str, list] = {}                  # sub_uuid -> [sub_in, endpoint_in, plugin_in]
        self._rl_framework_in = None                           # the single global-intake bucket
        # Precomputed OUT (attempt) charge-sets, mirroring the IN side above so
        # the OUT admit is one dict lookup + admit with NO per-call list
        # allocation (S1; Section 11 "no allocation on the hot path"). Built in
        # _rebuild_charge_sets in pinned order plugin_out, event_out,
        # framework_in. The impersonation path (asserted identity) still builds
        # dynamically -- plugin_out keyed by the asserted name but event_out by
        # the real producer is a mix these per-producer sets cannot hold.
        self._rl_plugin_out: Dict[str, list] = {}              # caller plugin -> [plugin_out, framework_in]
        self._rl_event_out: Dict[tuple, list] = {}             # (plugin, event_id) -> [plugin_out, event_out, framework_in]
        self._rl_framework_out: list = []                      # [framework_in] -- empty/unknown-chain OUT
        # Step 5: reject-log suppression state, keyed by the dry bucket's
        # (dim, key). {"last_warn": monotonic_ts, "rejected_at_warn": int}. The
        # per-bucket Bucket.rejected counter carries the true volume; this only
        # gates how often a WARNING is emitted (RL_REJECT_LOG_WINDOW). Loop-side
        # only (every reject site runs on the event loop). Not pruned on bucket
        # removal, and that is safe because the keyspace is bounded by config:
        # the six static dims come from plugin config/registration, and Nodes-IN
        # keys are peer hostnames that can ONLY be a configured peer (an
        # unconfigured peer fails the mTLS fingerprint pin before peer_hostname is
        # set, so it never reaches the admit). No wire input can grow this dict.
        # A stale entry after a hot-swap re-create is benign (see _rl_log_reject).
        self._rl_reject_log: Dict[tuple, dict] = {}
        # Step 4: flatten the main-config `rate_limits:` section into the base
        # dicts now (yaml_config was loaded above; capabilities parse at ~217 in
        # the same window). Buckets are NOT built here -- _rebuild_charge_sets
        # builds them after plugins load (it also merges the plugin-declared
        # layer). A malformed section raises ValueError at load (fail loud).
        # Init-only, mirroring _load_capability_grants exactly: main-config live
        # reload of rate_limits: is not wired (deferred), but plugin-declared
        # limits DO hot-reload via _rebuild_charge_sets on plugin reload.
        self._load_rate_limits()
        self._recompute_rate_limits_active()

        self.main_event_loop = None
        self.plugins = {}
        self.plugins_by_uuid = {}
        # Plugin dependency state. Populated late inside
        # load_plugin_with_conf (under plugin_lock alongside
        # self.plugins[name] = plugin) so partial-load failures via
        # error_config -> pop_plugin don't leave ghost entries.
        # _resolve_dependencies (called once at boot between get_plugins
        # and start_plugins) writes _dep_topo_order which start_plugins
        # consumes for layered enable. _dep_topo_order is a boot-time
        # snapshot — pop_plugin does NOT clean it; start_plugins guards
        # via plugins.get(name) returning None for popped entries.
        self._plugin_deps: Dict[str, List[DependencySpec]] = {}
        self._dep_topo_order: List[str] = []
        # Session 3 (v0.26.0): plugin state machine. Read-only data
        # container; all mutations through plx._transition_plugin(name, state).
        # External readers MUST snapshot before iterating: dict(plx.plugin_states).
        self.plugin_states: Dict[str, PluginState] = {}
        # Multi-file plugin loader bookkeeping (2026-05-27): tracks sys.modules
        # entries + sys.path entry that load_plugin_with_conf added for each
        # plugin so _pop_plugin_under_lock can clean them up at unload time.
        # Without this cleanup, hot-reload sees stale code via sys.modules cache
        # (Python's import machinery caches by name; subsequent loads of the
        # same plugin would re-bind to the OLD module objects). Keyed by plugin
        # name; value is {'sys_modules_added': set[str], 'sys_path_added': str | None}.
        self._plugin_loader_cleanup: Dict[str, Dict[str, object]] = {}
        self.plugin_lock = asyncio.Lock()
        # Stage O: per-plugin lifecycle locks (B-046 fix). Each plugin
        # gets its own asyncio.Lock for serializing on_enable / on_disable
        # / pop_plugin / _reload_plugin on THAT plugin. plugin_lock
        # (global) is now used only for fast dict reads/writes
        # (plugins, plugins_by_uuid). Locks are leaked across the
        # process lifetime — bounded by the number of distinct plugin
        # names ever loaded; entries are not removed on pop_plugin so
        # a concurrent waiter on a popped-and-reloaded plugin keeps
        # lock identity.
        self._lifecycle_locks: Dict[str, asyncio.Lock] = {}
        # Dedicated thread pool for sync plugin endpoints — isolated from
        # Python's default executor to prevent deadlock under load.
        # See docs/configuration.md "Sync-bridge thread pools (E and M)".
        # Phase 2b: GatedExecutor splits the budget into E (execution
        # concurrency, the old worker count, released while a carrier parks
        # on a bridge wait) and M (a hard thread ceiling held the full
        # carrier lifetime). Both are config-tunable for this pool:
        # `general.sync_executor_workers` (E, default 32) and
        # `general.sync_executor_thread_ceiling` (M, default 128). yaml_config
        # is already populated (load_config_yaml above); malformed/absent
        # values fall back to the default with a warning (no startup hard
        # failure). GatedExecutor raises the ceiling to E if E exceeds it.
        boot_general = self.yaml_config.get("general", {}) or {}
        raw_exec_workers = boot_general.get("sync_executor_workers", 32)
        try:
            exec_workers = int(raw_exec_workers)
            if exec_workers < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_executor_workers=%r; defaulting to 32",
                raw_exec_workers,
            )
            exec_workers = 32
        raw_exec_ceiling = boot_general.get(
            "sync_executor_thread_ceiling", PLUGIN_EXECUTOR_THREAD_CEILING
        )
        try:
            exec_ceiling = int(raw_exec_ceiling)
            if exec_ceiling < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_executor_thread_ceiling=%r; defaulting to %d",
                raw_exec_ceiling, PLUGIN_EXECUTOR_THREAD_CEILING,
            )
            exec_ceiling = PLUGIN_EXECUTOR_THREAD_CEILING
        self._plugin_executor = GatedExecutor(
            "plugin",
            exec_permits=exec_workers,
            thread_ceiling=exec_ceiling,
        )
        self._init_tasks = []
        self.network = None
        # Hot-reload networking rebuild lock (Commit 2b). Acquired by
        # ``wait_until_ready()`` during boot AND by
        # ``_rebuild_networking`` (Step 7) during hot reload —
        # non-reentrant, held across NetworkManager construction +
        # ``network.start()`` so the two flows can't race. Per cycle 3
        # HIGH-α + Option A (one canonical construction site lives in
        # ``wait_until_ready``; ``start()`` is a thin shim).
        self._network_rebuild_lock: asyncio.Lock = asyncio.Lock()
        # R2-DD-4: signalled if a rebuild aborts mid-flight (cancelled or
        # raises after ``self.network`` has been nulled). Observers /
        # operator can poll ``is_set()`` to know networking entered a
        # known-bad terminal state during the most recent rebuild.
        # Cleared at the start of every ``_rebuild_networking`` call.
        self._rebuild_aborted: asyncio.Event = asyncio.Event()
        # B-073: Internal event bus state. Sync observer dispatch on the
        # loop thread; observers must return < 1ms (heavy work goes to
        # caller-spawned tasks). Topic prefix ``_core/`` reserved from
        # plugin author code by Step 9 validator change. Auto-cleanup on
        # pop_plugin via ``_unobserve_plugin`` called from
        # ``_pop_plugin_under_lock`` alongside
        # ``topic_registry.unsubscribe_plugin``. ``_observer_owners`` maps
        # plugin_uuid -> set of (topic, callback) for bulk-unobserve on
        # pop. Tuples are hashable because callables hash by identity
        # (bound methods hash by ``(func, instance)`` identity); set
        # membership and removal work correctly.
        self._internal_observers: Dict[str, List[Callable]] = {}
        self._observer_owners: Dict[str, Set[Tuple[str, Callable]]] = {}
        # C-003: threading.Lock so mutations + iteration on the
        # observer dicts are safe across the loop thread + any worker
        # thread that calls internal_observe / internal_unobserve from
        # a sync endpoint dispatched via _plugin_executor. The docstring
        # on internal_observe used to say "Worker-thread call ... not
        # supported"; this lock makes the no-deadlock contract explicit.
        # Hold is brief (dict insert/remove), so contention with the
        # loop's emit path is negligible.
        self._observer_lock: threading.Lock = threading.Lock()
        self.topic_registry = TopicRegistry(self._logger.getChild("notifier"))
        self._config_write_lock = threading.Lock()
        # R2-DD-5: atomic-apply guard. Held across the multi-write
        # block in ``_apply_yaml`` so a concurrent reader cannot
        # observe a half-applied state (e.g. new ``yaml_config`` but
        # stale ``hostname`` / ``networking_*`` attrs). Reads that
        # need a consistent snapshot may acquire the same lock; brief
        # uncoordinated reads (single attribute) remain unprotected
        # by design — the lock guarantees write-side atomicity only.
        # R3-NN-1: asyncio.Lock so async callers (async_load_config_yaml,
        # _rebuild_networking) can use ``async with`` without blocking the
        # event loop when another async waiter is queued. The synchronous
        # boot-time entry point (Plexus.__init__ -> load_config_yaml) runs
        # before the event loop exists and before any other thread / task
        # is alive, so it takes the lockless internal helper instead.
        self._config_lock: asyncio.Lock = asyncio.Lock()

        # PR3 Stage A: dedicated executor for sync subscriber handlers
        # (Q17 + C3 + C8). Default 4 workers, configurable via
        # `general.sync_dispatcher_workers`. Reads from the live yaml_config
        # which load_config_yaml has already populated above. Falls back to
        # 4 for any malformed/absent value (no config-time hard failure —
        # the framework never blocked startup on a bad sync-dispatcher
        # value before, so we keep that posture).
        general_cfg = self.yaml_config.get("general", {}) or {}
        raw_workers = general_cfg.get("sync_dispatcher_workers", 4)
        try:
            sync_workers = int(raw_workers)
            if sync_workers < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_dispatcher_workers=%r; defaulting to 4",
                raw_workers,
            )
            sync_workers = 4
        # Thread ceiling (M) — runaway backstop, configurable via
        # `general.sync_dispatcher_thread_ceiling` (default 32). Auto-raised
        # to the worker count by GatedExecutor if set lower.
        raw_sync_ceiling = general_cfg.get(
            "sync_dispatcher_thread_ceiling", SYNC_DISPATCHER_THREAD_CEILING
        )
        try:
            sync_ceiling = int(raw_sync_ceiling)
            if sync_ceiling < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_dispatcher_thread_ceiling=%r; defaulting to %d",
                raw_sync_ceiling, SYNC_DISPATCHER_THREAD_CEILING,
            )
            sync_ceiling = SYNC_DISPATCHER_THREAD_CEILING
        self.sync_dispatcher = SyncDispatcher(
            workers=sync_workers,
            thread_ceiling=sync_ceiling,
            logger=self._logger.getChild("sync_dispatcher"),
        )

        # C-072: separate worker pool for sync streaming generators so
        # one slow stream cannot saturate the RPC sync-subscriber pool.
        # Each next() of a sync stream generator submits to
        # sync_stream_dispatcher.executor; sync RPC subscribers go to
        # sync_dispatcher.executor (above). 4 stream workers is enough
        # for typical plugin counts; bump
        # `general.sync_stream_workers` for stream-heavy workloads.
        raw_stream_workers = general_cfg.get("sync_stream_workers", 4)
        try:
            stream_workers = int(raw_stream_workers)
            if stream_workers < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_stream_workers=%r; defaulting to 4",
                raw_stream_workers,
            )
            stream_workers = 4
        # Thread ceiling (M) — runaway backstop, configurable via
        # `general.sync_stream_thread_ceiling` (default 16). Auto-raised to
        # the worker count by GatedExecutor if set lower.
        raw_stream_ceiling = general_cfg.get(
            "sync_stream_thread_ceiling", SYNC_STREAM_THREAD_CEILING
        )
        try:
            stream_ceiling = int(raw_stream_ceiling)
            if stream_ceiling < 1:
                raise ValueError("must be >= 1")
        except (TypeError, ValueError):
            self._logger.warning(
                "Invalid general.sync_stream_thread_ceiling=%r; defaulting to %d",
                raw_stream_ceiling, SYNC_STREAM_THREAD_CEILING,
            )
            stream_ceiling = SYNC_STREAM_THREAD_CEILING
        self.sync_stream_dispatcher = SyncDispatcher(
            workers=stream_workers,
            thread_ceiling=stream_ceiling,
            name="sync-stream-notifier",
            logger=self._logger.getChild("sync_stream_dispatcher"),
        )

    async def wait_until_ready(self):
        """Ensure initialization tasks are started and await completion.

        Per Commit 2b Option A: this is the canonical NetworkManager
        construction site. ``start()`` delegates here. Construction is
        serialized via ``_network_rebuild_lock`` so a hot-reload
        triggered during boot waits cleanly until init completes
        (cycle 3 HIGH-α). The lock is held across both NM construction
        AND the ``await asyncio.gather(*self._init_tasks)`` so a
        rebuild triggered mid-``network.start()`` cannot race the
        in-progress startup.

        Idempotent — repeated calls re-await the existing init tasks
        rather than reconstructing.
        """
        # Ensure event loop and maintenance task
        if self.main_event_loop is None:
            self.main_event_loop = asyncio.get_running_loop()
            if self.yaml_config.get("general", {}).get("asyncio_debug", False):
                self.main_event_loop.set_debug(True)
                self.main_event_loop.slow_callback_duration = 0.5

        if not self._init_tasks:
            async with self._network_rebuild_lock:
                # Re-check under lock: another concurrent caller may
                # have constructed while we awaited the lock. Without
                # this guard, two parallel ``wait_until_ready`` callers
                # would both attempt construction; the second would
                # double-register tasks + duplicate the NM instance.
                if not self._init_tasks:
                    self._init_tasks.append(asyncio.create_task(self.load_plugins()))
                    if getattr(self, "networking_enabled", False):
                        if self.network is None:
                            self.network = self._build_network_manager(self.yaml_config)
                        self._init_tasks.append(
                            asyncio.create_task(self.network.start())
                        )
                    # Hold the lock until init tasks complete so a
                    # concurrent hot-reload can't fire mid-
                    # ``network.start()`` (cycle 3 HIGH-α).
                    await asyncio.gather(*self._init_tasks)
                    return

        # Tasks already created (and possibly already done) — just
        # await completion. Lock not needed: the construction-phase
        # holder released after its own gather, so we observe
        # post-construction state.
        if self._init_tasks:
            await asyncio.gather(*self._init_tasks)

    async def start(self):
        """Initialize background tasks, load plugins, and start networking.

        Thin shim that delegates to ``wait_until_ready()``. Per
        Commit 2b Option A: all NetworkManager construction lives in
        ``wait_until_ready()`` under ``_network_rebuild_lock`` so the
        boot path is serialized with concurrent hot-reload calls.

        Pre-Commit-2b, ``start()`` separately constructed NM, then
        called ``wait_until_ready()`` which would skip construction
        (NM was already non-None). Now: ``start()`` just initializes
        the loop reference + delegates. Behavior preserved on the
        happy path; concurrent hot-reload races are now serialized
        correctly.
        """
        await self.wait_until_ready()

    async def close(self):
        """Gracefully shutdown: drain requests, disable plugins in reverse order, stop networking.

        B-073 Session 2 Step 4: ``running_loop`` + ``cleanup_requests``
        + ``cleanup_request_interval`` knob removed entirely. Done-callback
        eviction (Step 2's producer-finally pops + Step 3's outer-finally
        pops at all 7 framework Request migration sites) replaces the
        polling reap. There is no maintenance loop to stop on shutdown.
        """
        # W4-M4: re-entry guard. close() is called from signal handlers,
        # framework teardown, and test fixtures. Concurrent or sequential
        # double-calls would re-iterate the disable-all-plugins sequence,
        # produce duplicate on_disable invocations, and risk deadlock on
        # plugin lifecycle_locks. The boolean is set BEFORE any await so
        # a re-entry on the same loop sees the flag and bails.
        if getattr(self, "_closed", False):
            self._logger.debug(
                "close() re-entered after first call completed — skipping."
            )
            return
        self._closed = True

        # 1. Wait for all in-flight request tasks to finish (up to 30s)
        # Snapshot via list() so concurrent done_callback eviction can't
        # mutate the set during iteration. (Single-threaded loop already
        # makes this safe but the snapshot keeps the intent explicit.)
        pending = [t for t in list(self.task_list) if not t.done()]
        if pending:
            self._logger.info(
                "Shutdown: waiting for %d in-flight request(s)...", len(pending)
            )
            # R2-AA-4: guard the wait+cancel block against a second
            # cancellation (e.g. second SIGINT during the 30s drain).
            # ``asyncio.wait`` is a suspension point; if close() itself
            # is cancelled between wait() and the t.cancel() loop the
            # still-pending tasks would be orphaned permanently. The
            # BaseException branch cancels every task in the snapshot
            # before re-raising so shutdown still propagates.
            try:
                done, still_pending = await asyncio.wait(pending, timeout=30)
                if still_pending:
                    self._logger.warning(
                        "Shutdown: %d request(s) still running after 30s, cancelling...",
                        len(still_pending),
                    )
                    for t in still_pending:
                        t.cancel()
                    await asyncio.gather(*still_pending, return_exceptions=True)
            except BaseException:
                for t in pending:
                    if not t.done():
                        t.cancel()
                raise
        # In-place clear so any callback firing after this still
        # operates on the same set object — discard() of an already-
        # absent key is a no-op.
        self.task_list.clear()

        # 1b. Tail-drain fire-and-forget tasks (per-peer publish
        # dereg, advert acks, etc.). Separate pool from task_list —
        # short cleanup work spawned by done-callbacks AFTER the
        # task_list snapshot above. 5s budget then cancel; these are
        # best-effort and the NM is going away anyway.
        ff_pending = [t for t in list(self._fire_and_forget) if not t.done()]
        if ff_pending:
            self._logger.info(
                "Shutdown: draining %d fire-and-forget task(s)...",
                len(ff_pending),
            )
            # R4-VV-12: mirror the BaseException guard the task_list drain
            # above uses (step 1a, lines ~1290-1304). Without this, a
            # second SIGINT during the 5s wait would propagate
            # CancelledError / KeyboardInterrupt out of close(), leaving
            # the fire-and-forget tasks un-cancelled and orphaned.
            try:
                _, ff_still = await asyncio.wait(ff_pending, timeout=5)
                if ff_still:
                    for t in ff_still:
                        t.cancel()
                    await asyncio.gather(*ff_still, return_exceptions=True)
            except BaseException:
                for t in ff_pending:
                    if not t.done():
                        t.cancel()
                raise
        self._fire_and_forget.clear()

        # 3. Disable plugins in REVERSE dependency-topo order.
        #    R3-RR-2: source the iteration from self._dep_topo_order
        #    (dependencies-before-dependents) reversed so dependents shut
        #    down before their dependencies. The previous use of
        #    list(self.plugins.keys()) reflected config insertion order,
        #    which is NOT guaranteed to be dependency order — a dependency
        #    (e.g. PostgreSQL) could be disabled before a dependent
        #    (e.g. DataCollection) finished its on_disable.
        #    e.g. Discord_Bot_Plugin → DataCollection → PostgreSQL
        #    R3-RR-6: the SyncDispatcher shutdown block (step 2) moved to
        #    AFTER this loop so on_disable callbacks can still emit
        #    synchronous events / submit to the executor.
        topo = list(self._dep_topo_order)
        # R4-WW-8: `extra` below uses dict insertion order, NOT dep order.
        # Runtime-add (post-boot) is not yet a public surface, so `extra`
        # is normally empty; when runtime-add becomes public, recompute
        # _dep_topo_order at add time so this list stays empty or
        # properly ordered. Accepted limitation for now.
        extra = [n for n in self.plugins.keys() if n not in topo]
        plugin_names = list(reversed(topo + extra))

        for name in plugin_names:
            plugin = self.plugins.get(name)
            if not plugin or not plugin.enabled:
                continue
            self._logger.info("Shutdown: disabling %s...", name)
            try:
                # Delegate to _disable_plugin_under_lock instead of
                # duplicating the lifecycle_ready.clear() + on_disable +
                # unregister + state-transition sequence inline. The 30s
                # on_disable timeout is hardcoded here (shutdown cap);
                # runtime callers (disable_plugin, _pop_plugin_under_lock)
                # use the configurable plugin_disable_timeout per the
                # B-009 fix.
                #
                # Stage O: each plugin's lifecycle_lock instead of the
                # global plugin_lock. Concurrent ops (e.g. an in-flight
                # request still using a not-yet-disabled plugin) on
                # OTHER names are not blocked by THIS plugin's shutdown.
                lifecycle_lock = self._get_lifecycle_lock(name)
                async with lifecycle_lock:
                    await self._disable_plugin_under_lock(name, on_disable_timeout=30.0)
                self._logger.info("Shutdown: %s disabled", name)
            except asyncio.TimeoutError:
                self._logger.warning(
                    "Shutdown: %s on_disable timed out after 30s", name
                )
            except Exception as e:
                self._logger.error(
                    "Shutdown: %s on_disable failed: %s", name, e, exc_info=True
                )

        # Sweep any plugin-source per-logger thresholds. Covers never-enabled
        # plugins (the disable loop above skips them via the `enabled` guard)
        # and is idempotent for plugins already cleaned via pop_plugin.
        for sweep_name, sweep_plugin in list(self.plugins.items()):
            sweep_uuid = getattr(sweep_plugin, "plugin_uuid", None)
            if sweep_uuid:
                LogUtil.clear_logger_levels_owned_by(sweep_name, sweep_uuid)

        # 3b. Shutdown the SyncDispatcher (PR3 Stage A, Q17 + C8).
        # MUST happen AFTER the in-flight drain AND after the plugin
        # disable loop above. R3-RR-6: previously this ran before the
        # plugin disable step, which meant on_disable callbacks that
        # called executor.submit() received a swallowed
        # RuntimeError("cannot schedule new futures after shutdown").
        # Per C8 spec: wrap executor.shutdown(wait=True) in
        # asyncio.wait_for with 30s timeout. On timeout, log and skip
        # the second shutdown call rather than racing the still-running
        # to_thread worker (R3-RR-1).
        # C-072: shut down BOTH sync dispatchers (RPC pool + stream
        # pool). Same 30s graceful budget each. Order is RPC-first then
        # stream because handlers in the RPC pool may schedule into the
        # stream pool, not the other way around — drain producer-side first.
        for attr in ("sync_dispatcher", "sync_stream_dispatcher"):
            disp = getattr(self, attr, None)
            if disp is None:
                continue
            self._logger.info("Shutdown: stopping %s...", attr)
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(disp.executor.shutdown, wait=True),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                # R3-RR-1: the to_thread task is still running the
                # graceful executor shutdown in a worker thread.
                # Calling a second shutdown from the loop thread
                # here would race the worker on the same
                # ThreadPoolExecutor internals (CPython's shutdown is
                # not safe for concurrent callers). Log and continue;
                # the background thread will finish when workers do.
                #
                # R3-RR-1 review follow-up: asyncio.wait_for already
                # cancelled the inner asyncio.Task wrapping to_thread,
                # so no "Task was destroyed but it is pending" warning
                # will surface. The underlying OS thread keeps running
                # the C-level executor.shutdown(wait=True) call; Python
                # cannot force-cancel a thread blocked in C code. The
                # process exits cleanly once the worker pool drains.
                self._logger.warning(
                    "%s graceful shutdown timed out after 30.0s; "
                    "in-flight shutdown task left running, continuing", attr,
                )
            except Exception:
                self._logger.exception("%s shutdown failed", attr)

        # 4. Stop networking. C-135: read self.network under
        # _network_rebuild_lock so a concurrent _rebuild_networking
        # cannot swap self.network mid-close (leading to either a
        # double-stop on the same NM or a missed-stop on a freshly
        # built one). Acquiring the lock here will wait for an
        # in-progress rebuild to finish; then we snapshot, null out
        # self.network (so any post-close caller sees None and bails),
        # and call stop() on the snapshot. NetworkManager.stop() is
        # already idempotent (sets is_ready=False first; subsequent
        # task-cancels / dict-drops are no-ops on the second call).
        # R3-RR-10: Plexus.__init__ always assigns self.network = None,
        # so the previous attribute-existence guard was unconditionally
        # True for any fully-constructed instance. Check for the actual
        # intended condition (non-None) instead. getattr() with default
        # guards against test scaffolds that bypass __init__ entirely.
        if getattr(self, "network", None) is not None:
            rebuild_lock = getattr(self, "_network_rebuild_lock", None)
            if rebuild_lock is not None:
                async with rebuild_lock:
                    nm_to_stop = self.network
                    self.network = None
            else:
                # Defensive for test scaffolds that bypass __init__.
                nm_to_stop = self.network
                self.network = None
            if nm_to_stop is not None:
                stop = getattr(nm_to_stop, "stop", None)
                if callable(stop):
                    self._logger.info("Shutdown: stopping networking...")
                    with contextlib.suppress(Exception):
                        await stop()

        # 5. Shutdown dedicated plugin executor
        if hasattr(self, "_plugin_executor") and self._plugin_executor:
            # W4-M2: shutdown(wait=True, cancel_futures=True) so any
            # in-flight sync on_disable / endpoint threads have their
            # pending submissions cancelled and existing threads are
            # joined before close() returns. wait=False would leave
            # zombie threads holding DB connections / file handles /
            # plugin_lock past process shutdown.
            #
            # Caveat (S5 follow-up): `cancel_futures` cancels pending
            # submissions but does NOT interrupt a thread already
            # running a sync callback. A truly hung sync `on_disable`
            # still blocks close() until the thread returns naturally.
            # The trade-off is conservative: prefer block-on-shutdown
            # over zombie-after-shutdown.
            self._plugin_executor.shutdown(wait=True, cancel_futures=True)

        self._logger.info("Shutdown complete")

    def _load_yaml_dict(self, config_path: str) -> dict:
        """Pure parse + integrity check. Does NOT mutate ``self``.

        Returns the parsed dict (or raises ConfigException on integrity
        failure / yaml.YAMLError on parse failure). The returned dict is
        the SAME object the caller will pass to ``_apply_yaml``;
        ``apply_configvalues`` (called from ``_apply_yaml``) mutates it
        in place, writing back resolved defaults (e.g. ``hostname``,
        ``port``, ``networking.enabled``). Callers wanting a stable
        pre-apply snapshot must deep-copy the dict before passing it on
        — Step 4's ``_normalize_networking_for_diff`` does exactly this.

        Split out so the hot-reload path can pre-validate a candidate
        config before any mutation hits self. Closes cycle 2 HIGH-3
        state-lie (``apply_configvalues`` used to mutate ``self`` before
        ``check_config_integrity`` completed; if integrity raised,
        ``self.networking_*`` already reflected the new yaml but
        ``self.network`` was old).

        NOT decorated with ``@log_errors`` — the public
        ``load_config_yaml`` wrapper carries the decorator, so failures
        are logged once at the public-API boundary instead of twice on
        the unwind.
        """
        self._logger.info(f"Loading config from config_path: {config_path}")
        yaml_dict = ConfigUtil.load_config(config_path)
        ConfigUtil.check_config_integrity(yaml_dict, self._logger)
        return yaml_dict

    def _apply_yaml_locked(self, yaml_dict: dict) -> None:
        """Apply parsed yaml to ``self`` state WITHOUT acquiring
        ``self._config_lock``. Callers are responsible for serializing
        access; in practice only the synchronous boot-time path
        (``Plexus.__init__`` -> ``load_config_yaml``) uses this directly,
        since at that point no event loop or other thread is alive.

        See ``_apply_yaml`` for the async wrapper used by all post-boot
        callers (``async_load_config_yaml`` / ``_rebuild_networking``).
        """
        general_pre = yaml_dict.get("general", {}) if isinstance(yaml_dict, dict) else {}
        if not isinstance(general_pre, dict):
            general_pre = {}
        console_level = general_pre.get("console_log_level", "DEBUG")
        file_level = general_pre.get("file_log_level", "DEBUG")
        logger_levels = general_pre.get("logger_levels", {})

        self.yaml_config = yaml_dict
        ConfigUtil.apply_configvalues(self)
        LogUtil.change_level(console_level)
        LogUtil.change_file_level(file_level)
        LogUtil.apply_logger_levels_config(logger_levels)

    async def _apply_yaml(self, yaml_dict: dict) -> None:
        """Apply parsed yaml to ``self`` state. Caller is responsible for
        having already integrity-checked ``yaml_dict`` via
        ``_load_yaml_dict``.

        Mutates ``self.yaml_config`` (assigned to the passed-in dict by
        reference — same object), then calls
        ``ConfigUtil.apply_configvalues`` which writes resolved defaults
        BACK into ``self.yaml_config`` in place (e.g. ``hostname``,
        ``port``, ``networking.enabled``). The dict the caller passed is
        therefore mutated as a side effect — see ``_load_yaml_dict``'s
        docstring for the implication.

        Also re-applies LogUtil thresholds so hot-reload picks up
        log-level changes.

        NOT decorated with ``@log_errors`` — see ``_load_yaml_dict``'s
        note.

        R2-DD-5: the multi-write block is wrapped in
        ``self._config_lock`` so a concurrent reader cannot observe a
        half-applied state (new ``yaml_config`` + stale ``hostname``
        / ``networking_*``).
        """
        # Apply logging-related config last so hot-reload picks up changes.
        # On first boot LogUtil.create() already used the same values from the
        # bootstrap pre-read; on async_load_config_yaml() this is the only
        # place that re-applies them.
        #
        # R3-NN-1: ``self._config_lock`` is an ``asyncio.Lock`` so we
        # ``async with`` it here. The actual mutation is delegated to
        # ``_apply_yaml_locked`` which is shared with the sync boot path.
        async with self._config_lock:
            self._apply_yaml_locked(yaml_dict)

    @log_errors
    def load_config_yaml(self, config_path: str):
        """Sync entry point — load + integrity check + apply.

        Behavior change vs pre-Step-1: integrity-check raises now leave
        ``self.yaml_config`` unmodified (was previously overwritten with
        the bad-but-parsed dict). Closes cycle 2 HIGH-3 state-lie.
        """
        # R3-NN-1: sync boot path. No event loop running, no other thread
        # alive yet -> call the lockless internal helper directly. Cannot
        # use ``await self._apply_yaml(...)`` because this method is sync
        # and is invoked from ``Plexus.__init__`` before any loop exists.
        self._apply_yaml_locked(self._load_yaml_dict(config_path))

    async def async_load_config_yaml(self, config_path: str):
        """Async config loader with hot-reload orchestration.

        Behavior matrix:

        * Bootstrap (``self.yaml_config is None``): apply new config
          directly. NO networking action — NetworkManager construction
          happens later in ``wait_until_ready()`` via Option A. NOTE:
          unreachable in practice — ``Plexus.__init__`` calls
          ``load_config_yaml`` synchronously, populating
          ``self.yaml_config`` before any caller reaches this method.
          Kept as a defensive guard.
        * No networking change (``_networking_config_changed=False``):
          apply new config + update live NM attrs in place via
          ``_update_networking_in_place``.
        * Networking change (rebuild-trigger field — peers / enabled /
          port / hostname / keys_dir; see ``_networking_config_changed``):
          pre-validate via ``_validate_networking_config`` (raises →
          abort, no state mutation), then ``_rebuild_networking``
          (which acquires the rebuild lock + does the ordered
          tear-down + rebuild).

        Rebuild orchestrator design per Commit 2b cycle 3 settled spec.

        R4-UU-10: Plugin list reconciliation is intentionally NOT
        performed here. To add / remove / reload a specific plugin,
        callers must use ``_reload_plugin`` or ``pop_plugin`` +
        ``load_plugin_with_conf`` explicitly. Changes to the
        ``plugins:`` array in the YAML are picked up only by those
        per-plugin paths, not by this method — added entries will
        not be loaded and removed entries will not be unloaded by
        this call alone.
        """
        # R4-UU-1: refuse to reload after close(). close() sets
        # _closed=True and then acquires _network_rebuild_lock to null
        # out self.network; without this guard, a reload coroutine that
        # was waiting on the lock would acquire it AFTER close()
        # releases it and construct a new NetworkManager on a fully
        # closed Plexus instance.
        if getattr(self, "_closed", False):
            self._logger.warning(
                "Refusing to reload/rebuild: Plexus is closed"
            )
            return

        new_yaml = self._load_yaml_dict(config_path)
        old_yaml = self.yaml_config

        if old_yaml is None:
            # Defensive path — unreachable under current __init__
            # ordering, but kept so a future change to construction
            # order doesn't silently bypass the rebuild orchestrator.
            await self._apply_yaml(new_yaml)
            return

        # R4-UU-5: short-circuit on no-op reload. Without this, every
        # call unconditionally re-applies LogUtil.change_level /
        # change_file_level / apply_logger_levels_config, producing
        # spurious side-effects (handler reconfiguration, log spam,
        # file-rotator restarts) when the config file is unchanged.
        if new_yaml == self.yaml_config:
            self._logger.debug(
                "Config reload: no-op (yaml unchanged)"
            )
            return

        if self._networking_config_changed(old_yaml, new_yaml):
            # Pre-validate before any state mutation. Bad config →
            # abort cleanly; old network keeps running.
            try:
                self._validate_networking_config(new_yaml)
            except Exception as e:
                self._logger.error(
                    "async_load_config_yaml: networking config "
                    "validation failed; reload aborted, old config "
                    "remains active. Error: %s",
                    e,
                    exc_info=True,
                )
                return
            await self._rebuild_networking(new_yaml)
        else:
            # W2-H3: hold _network_rebuild_lock so a concurrent
            # _rebuild_networking can't interleave its yaml_config
            # mutation with _apply_yaml's mutation here.
            #
            # R4-UU-4: also hold _config_lock around the snapshot read
            # so the non-networking-change branch is atomic against
            # concurrent readers (e.g. _reload_plugin) that need a
            # consistent yaml_config view. The actual write inside
            # _apply_yaml re-acquires _config_lock internally; an
            # asyncio.Lock is non-reentrant, so we read the snapshot
            # under the lock and release before calling _apply_yaml.
            async with self._network_rebuild_lock:
                async with self._config_lock:
                    plugin_entries = self.yaml_config.get("plugins", [])
                    # Snapshot kept for future plugin-list reconcile
                    # (R4-UU-10 path); intentionally unused today.
                    del plugin_entries
                await self._apply_yaml(new_yaml)
                self._update_networking_in_place(new_yaml)

    async def _rebuild_networking(self, new_yaml: dict) -> None:
        """Rebuild the NetworkManager for hot-reload of peers /
        enabled / port / hostname / keys_dir changes.

        Acquires ``_network_rebuild_lock`` so concurrent boot or other
        rebuild calls serialize. Per cycle 3 HIGH-α + Option A.

        Ordering (cycle 3 design — DO NOT REORDER):

        1. Build new NM via ``_build_network_manager(new_yaml)``. If
           raises, no state mutation; old keeps running. (Skipped if
           new yaml has ``networking.enabled=False`` — there's nothing
           to construct in that case.)
        2. ``_apply_yaml(new_yaml)`` — applies new config to
           ``self.yaml_config`` and ``self.networking_*``.
        3. Snapshot ``old_nm = self.network``.
        4. ``self.network = None`` — guards in 4 sites + 7 snapshot
           sites observe None from here. Held until end of rebuild.
        5. Drain in-flight remote requests (10s budget) +
           ``old_nm._inflight_publishes``. Pessimistic drain (per
           cycle 7 fix): includes any not-done request not explicitly
           stamped ``_is_remote=False``, since the stamp is set
           INSIDE ``_process_request*`` AFTER the request is already
           registered in ``self.requests``. Local requests resolve
           quickly so this is safe.
        6. ``await old_nm.stop()`` — try/except + log + continue. If
           ``stop()`` raises, the lock is still held; rebuild
           proceeds.
        7. ``await new_nm.start()`` — on raise: ``self.network = None``
           PERMANENTLY, log CRITICAL. Operator must reload-config to
           recover.
        8. ``self.network = new_nm`` — atomic assignment, end of gap.

        If new yaml has ``networking.enabled=False``, steps 1, 7, 8
        are skipped: ``self.network`` stays None permanently
        (network is now disabled by config).

        Cancellation: if this coroutine is cancelled between step 4
        and step 8, ``self.network`` stays None permanently —
        operator reload required to recover. Same terminal state as
        new-NM start failure. No try/finally restores old_nm because
        old has been stopped (step 6) and stopping a stopped NM is
        undefined.

        Documented imperfections (B-079):

        * Drain MISSES ``request_event_remote`` /
          ``request_event_stream_remote`` direct-await calls (no
          Request object → no ``_is_remote`` stamp + no
          ``self.requests`` registration). Caller may see
          ``ConnectionResetError`` mid-rebuild; retry on caller side.
        * Drain races against ``_drop_peer_advert_state`` cleanup —
          if a peer disconnect fires concurrent with rebuild, drain
          may miss tasks already cancelled by disconnect. Same
          retry-on-caller acceptable.
        * ``peer_stats`` counters reset (fresh NM = fresh dict).
          Per O7 acceptable.
        * Surviving tasks past the 10s drain timeout get cancelled
          silently by ``old_nm.stop()`` via
          ``_drop_peer_advert_state``. The drain warning fires first;
          no second log when stop() does the cancellation.
        """
        # R4-UU-1: refuse to rebuild after close(). Without this, a
        # reload coroutine that was waiting on _network_rebuild_lock
        # would acquire it AFTER close() releases it and proceed to
        # build a new NetworkManager onto a closed Plexus.
        if getattr(self, "_closed", False):
            self._logger.warning(
                "Refusing to reload/rebuild: Plexus is closed"
            )
            return

        async with self._network_rebuild_lock:
            # R2-DD-4: clear the abort signal at the start of every
            # rebuild attempt; it is set in the except branch below
            # only if a mid-flight failure (including cancellation)
            # leaves the framework in a degraded networking state.
            self._rebuild_aborted.clear()

            # Step 1: build new NM (no state mutation if this raises).
            nw_cfg = new_yaml.get("networking") or {}
            new_enabled = bool(nw_cfg.get("enabled", False))
            new_nm = None
            if new_enabled:
                try:
                    new_nm = self._build_network_manager(new_yaml)
                except Exception as e:
                    self._logger.error(
                        "_rebuild_networking: NetworkManager "
                        "construction failed; old network remains "
                        "active. Error: %s",
                        e,
                        exc_info=True,
                    )
                    return  # NO state mutation

            # R3-MM-6: snapshot the old yaml BEFORE _apply_yaml mutates
            # self.yaml_config / hostname / networking_* attributes so the
            # rollback branch below can revert config to match the restored
            # NetworkManager. Pre-fix the restore reinstated self.network =
            # old_nm but left config reflecting new yaml — operator saw
            # rollback succeed yet observed an inconsistent NM-vs-config
            # state until the next reload.
            old_yaml = self.yaml_config

            # Step 2: apply new yaml to self state.
            await self._apply_yaml(new_yaml)

            # R2-DD-4: snapshot old_nm BEFORE step 4 so the except
            # branch can restore it on mid-flight cancellation /
            # raise. The previous structure snapshotted inline at
            # step 3, then immediately nulled self.network, leaving
            # a window where a cancel between step 4 and step 8 left
            # self.network=None forever with no recovery path.
            old_nm = self.network
            old_nm_stopped = False  # set True only if step 6 completed

            try:
                # Step 3-4: null self.network for the gap. Guards in
                # the 4 + 7 sites observe None from here on.
                self.network = None

                # Step 5: drain in-flight remote requests + inflight
                # publishes (best-effort; surviving tasks log
                # warning + continue).
                await self._drain_for_rebuild(old_nm, timeout=10.0)

                # Step 6: stop old (best-effort; log on failure,
                # continue).
                if old_nm is not None:
                    try:
                        await old_nm.stop()
                    except Exception as e:
                        self._logger.warning(
                            "_rebuild_networking: old NetworkManager "
                            "stop() raised; continuing. Error: %s",
                            e,
                            exc_info=True,
                        )
                    old_nm_stopped = True

                # Step 7+8: start new NM and assign atomically.
                if new_nm is not None:
                    try:
                        await new_nm.start()
                    except Exception as e:
                        self._logger.critical(
                            "_rebuild_networking: new NetworkManager "
                            "start() failed; networking is DOWN "
                            "until next reload. Error: %s",
                            e,
                            exc_info=True,
                        )
                        # self.network stays None — operator-recovery
                        # via reload.
                        self._rebuild_aborted.set()
                        # R4-UU-9: emit a failure event so subscribers
                        # of "_core/network/rebuild_failed" don't have
                        # to poll _rebuild_aborted.
                        try:
                            self._internal_emit(
                                "_core/network/rebuild_failed",
                                aborted=True,
                                error="new_nm.start() failed",
                                restored=False,
                                ts=time.time(),
                            )
                        except Exception:
                            self._logger.debug(
                                "_rebuild_networking: rebuild_failed "
                                "emit raised",
                                exc_info=True,
                            )
                        return
                    self.network = new_nm
                # else: new yaml has networking.enabled=False → leave
                # self.network = None.
            except BaseException as exc:
                # R2-DD-4: mid-flight failure (cancellation,
                # SystemExit, KeyboardInterrupt, or any unexpected
                # raise from a step 5-8 await). Restore the old NM
                # if it has not yet been stopped so self.network is
                # never left dangling at None forever. Best-effort
                # cleanup on the half-built new_nm.
                if not old_nm_stopped and old_nm is not None:
                    self.network = old_nm
                    # R3-MM-6: revert self.yaml_config / hostname /
                    # networking_* attrs back to the pre-rebuild snapshot
                    # so the restored NetworkManager isn't paired with
                    # half-applied new config. Best-effort — if
                    # _apply_yaml itself raises here we still want the
                    # original ``exc`` to propagate, not a secondary one.
                    try:
                        await self._apply_yaml(old_yaml)
                    except BaseException:
                        self._logger.exception(
                            "_rebuild_networking: failed to restore old "
                            "yaml_config during rollback; config may be "
                            "inconsistent with restored NetworkManager."
                        )
                    self._logger.error(
                        "_rebuild_networking: aborted mid-flight; "
                        "restored old NetworkManager. Cause: %r",
                        exc,
                    )
                else:
                    # Old has already been stopped — cannot restore.
                    # self.network remains None; the finally branch
                    # surfaces a clear error if no successor exists.
                    self._logger.critical(
                        "_rebuild_networking: aborted after old NM "
                        "stop() — no restore path. Cause: %r",
                        exc,
                    )

                # Best-effort cleanup of the half-built new_nm. The
                # in-tree NetworkManager only exposes async stop();
                # call shutdown() if a future implementation provides
                # one, else fall back to stop(). Swallow any error
                # from cleanup — the original cause is what we
                # re-raise below.
                if new_nm is not None and self.network is not new_nm:
                    cleanup = getattr(new_nm, "shutdown", None) or getattr(
                        new_nm, "stop", None
                    )
                    if cleanup is not None:
                        try:
                            result = cleanup()
                            if asyncio.iscoroutine(result):
                                await result
                        except BaseException:
                            self._logger.debug(
                                "_rebuild_networking: cleanup of "
                                "half-built new_nm raised; "
                                "swallowing.",
                                exc_info=True,
                            )

                self._rebuild_aborted.set()
                # R4-UU-9: emit a failure event so subscribers see
                # rebuild aborts without polling _rebuild_aborted. The
                # restored flag reflects whether the rollback branch
                # was able to put the old NM back in place.
                try:
                    self._internal_emit(
                        "_core/network/rebuild_failed",
                        aborted=True,
                        error=type(exc).__name__,
                        restored=(not old_nm_stopped and old_nm is not None),
                        ts=time.time(),
                    )
                except Exception:
                    self._logger.debug(
                        "_rebuild_networking: rebuild_failed emit "
                        "raised",
                        exc_info=True,
                    )
                raise
            finally:
                # R2-DD-4: invariant — exiting the rebuild
                # orchestrator with self.network=None is acceptable
                # ONLY when networking is intentionally disabled
                # (new_enabled=False). Any other path that lands
                # here with self.network=None means the framework is
                # in a known-bad state; log CRITICAL so operators
                # see a clear signal rather than a silent dangling
                # None.
                if self.network is None and new_enabled:
                    self._rebuild_aborted.set()
                    self._logger.critical(
                        "_rebuild_networking: orchestrator exiting "
                        "with self.network=None despite "
                        "networking.enabled=True — framework is in "
                        "a degraded state, operator reload required."
                    )

            # C-080: emit `_core/network/rebuilt` so observers (TUI,
            # monitoring plugins) can react to a networking rebuild
            # without polling. Payload distinguishes enabled vs
            # disabled outcome; ``ts`` is wall-clock per the existing
            # event-timestamp convention.
            try:
                self._internal_emit(
                    "_core/network/rebuilt",
                    enabled=new_enabled,
                    hostname=new_yaml.get("general", {}).get("hostname")
                    or new_yaml.get("networking", {}).get("hostname")
                    or "",
                    ts=time.time(),
                )
            except Exception:
                self._logger.debug(
                    "_rebuild_networking: _internal_emit failed",
                    exc_info=True,
                )

    async def _drain_for_rebuild(self, old_nm, timeout: float = 10.0) -> None:
        """Drain in-flight remote-bound work for a clean teardown.

        Two snapshot sources:

        * ``self.requests`` filtered for not-done + not explicitly
          ``_is_remote=False``. **Pessimistic filter** (cycle 7 HIGH-1
          fix): the stamp is set INSIDE ``_process_request*`` AFTER
          the request is already in ``self.requests``, so a request
          that hasn't yet reached the RemotePlugin branch wouldn't
          be caught by a strict ``_is_remote=True`` filter. Including
          unclassified requests is safe — local ones complete quickly
          via the local dispatch path so ``asyncio.wait`` returns them
          immediately.
        * ``old_nm._inflight_publishes`` — fire-and-forget per-peer
          publish tasks (PR3 Stage C).

        Best-effort: surviving tasks log warning at timeout expiry;
        the rebuild continues regardless. Per cycle 1 HIGH-1 + cycle
        2 HIGH-C.
        """
        pending = []

        # Snapshot Request-tracked in-flight requests under lock.
        # Pessimistic: include any not-done request that isn't
        # explicitly stamped ``_is_remote=False`` (no request ever is,
        # so this catches stamped-True + unstamped).
        async with self.request_lock:
            for req in list(self.requests.values()):
                if req._future.done():
                    continue
                if getattr(req, "_is_remote", None) is False:
                    continue
                pending.append(req._future)

        # Snapshot old_nm's _inflight_publishes under its struct lock.
        if old_nm is not None:
            try:
                async with old_nm._adverts_struct_lock:
                    for peer_set in list(old_nm._inflight_publishes.values()):
                        pending.extend(t for t in peer_set if not t.done())
            except Exception:
                self._logger.debug(
                    "_drain_for_rebuild: snapshot "
                    "_inflight_publishes raised; continuing with "
                    "partial drain.",
                    exc_info=True,
                )

        if not pending:
            return

        self._logger.info(
            "_rebuild_networking: draining %d in-flight task(s) " "(timeout=%.1fs)...",
            len(pending),
            timeout,
        )
        try:
            done, still_pending = await asyncio.wait(pending, timeout=timeout)
            if still_pending:
                self._logger.warning(
                    "_rebuild_networking: %d task(s) still pending "
                    "after %.1fs; continuing rebuild (surviving "
                    "tasks will be cancelled by old NM's stop()).",
                    len(still_pending),
                    timeout,
                )
        except Exception as e:
            self._logger.warning(
                "_rebuild_networking: drain await failed: %s; " "continuing rebuild.",
                e,
            )

    def _update_networking_in_place(self, yaml_config: dict) -> None:
        """Update non-rebuild networking fields on the live NM in
        place. Called from the rebuild orchestrator's else-branch
        when ``_networking_config_changed`` returned False.

        Fields updated:

        * ``heartbeat_interval`` / ``lookup_interval`` /
          ``liveness_timeout`` — live effect: heartbeat / discovery /
          liveness loops use the new value on next tick.
        * ``discover_nodes`` — toggle live; lookup_loop checks attr
          each tick.
        * ``direct_discoverable`` / ``auto_discoverable`` — read by
          the INFO handler; next inbound INFO observes new value.
        * ``pool_size`` — best-effort: only affects pools created
          AFTER this call. Existing pools keep their construction-
          time ``maxsize``.

        (C-029 + C-030: ``secret`` / ``cert_file`` / ``key_file`` were
        listed here as legacy attr-update fields; both the attrs and
        this block have been removed. mTLS identity comes from
        ``self.cert_path`` / ``self.key_path`` on disk; runtime
        rotation requires a full rebuild.)

        NO rebuild needed because these don't change wire identity
        or server bind state. No-op when ``self.network`` is None
        (networking disabled or boot incomplete).
        """
        nm = self.network
        if nm is None:
            return

        nw_cfg = yaml_config.get("networking") or {}
        if not isinstance(nw_cfg, dict):
            return

        from .networking import (
            DEFAULT_HEARTBEAT_INTERVAL as _DEF_HB,
            DEFAULT_LOOKUP_INTERVAL as _DEF_LOOK,
            DEFAULT_LIVENESS_TIMEOUT as _DEF_LIVE,
            DEFAULT_RESYNC_INTERVAL as _DEF_RESYNC,
        )

        def _safe_float(val, default):
            try:
                f = float(val)
                return f if f > 0 else default
            except (TypeError, ValueError):
                return default

        nm.heartbeat_interval = _safe_float(
            nw_cfg.get("heartbeat_interval", _DEF_HB), _DEF_HB
        )
        nm.lookup_interval = _safe_float(
            nw_cfg.get("lookup_interval", _DEF_LOOK), _DEF_LOOK
        )
        nm.liveness_timeout = _safe_float(
            nw_cfg.get("liveness_timeout", _DEF_LIVE), _DEF_LIVE
        )
        # R2-LL-5: ``probe_timeout`` follows the same in-place update
        # contract as the surrounding knobs — next heartbeat tick adopts
        # the new value (via the snapshot at tick start). Absent or
        # invalid → default to ``min(heartbeat_interval,
        # liveness_timeout)`` so the heartbeat loop never blocks longer
        # than its own cadence on a single probe.
        raw_probe = nw_cfg.get("probe_timeout", None)
        if raw_probe is None:
            nm.probe_timeout = min(nm.heartbeat_interval, nm.liveness_timeout)
        else:
            nm.probe_timeout = _safe_float(
                raw_probe, min(nm.heartbeat_interval, nm.liveness_timeout)
            )
        # C-109: resync_interval updates in place — next heartbeat tick
        # picks up the new value via the time-comparison check.
        nm.resync_interval = _safe_float(
            nw_cfg.get("resync_interval", _DEF_RESYNC), _DEF_RESYNC
        )
        nm.discover_nodes = nw_cfg.get("discover_nodes", False)
        nm.direct_discoverable = nw_cfg.get("direct_discoverable", False)
        nm.auto_discoverable = nw_cfg.get("auto_discoverable", False)
        if nm.auto_discoverable and not nm.direct_discoverable:
            nm.direct_discoverable = True
        nm.pool_size = nw_cfg.get("pool_size", 5)
        # C-029 + C-030 + C-143: legacy `secret` / `cert_file` /
        # `key_file` in-place writes removed alongside the attrs
        # themselves (the previous block silently wiped them to None
        # if absent from the new config — see C-143). mTLS identity
        # is loaded from disk at NM construction via
        # `_load_or_generate_identity`; runtime rotation requires a
        # full rebuild triggered by a `keys_dir` change in
        # `_networking_config_changed`.

    def _build_network_manager(self, yaml_config: dict) -> NetworkManager:
        """Construct a fresh NetworkManager from a yaml_config dict.

        Reads EVERY field from ``yaml_config["networking"]`` dict — NOT
        from ``self.networking_*`` attrs (which may be stale during a
        rebuild that hasn't yet called ``_apply_yaml``). This independence
        is the core of the rebuild ordering:
          1. Build new NetworkManager from new_yaml (no self-state read)
          2. If construct raises → no state mutation, abort cleanly
          3. _apply_yaml(new_yaml) — only after construction succeeds

        Per cycle 3 HIGH-γ.

        Field source-of-truth (per cycle 3 HIGH-γ — must NOT read
        ``self.networking_*``):

        * ``port`` / ``auto_discoverable`` / ``direct_discoverable`` —
          read from ``yaml_config["networking"]``. ``apply_configvalues``
          writes these back to the dict in place after parsing
          (utils.py:1056-1092), so post-apply or fresh-parse gives
          identical values.
        * ``heartbeat_interval`` / ``lookup_interval`` /
          ``liveness_timeout`` — read from yaml_config and parsed via
          ``_safe_float`` (matches ``apply_configvalues``' parsing with
          identical ``<= 0`` rejection boundary, utils.py:1124-1166).
        * ``secret`` / ``cert_file`` / ``key_file`` / ``pool_size`` —
          read raw from yaml_config. ``apply_configvalues`` currently
          passes these through unchanged (utils.py:1098-1101), so
          behavior matches the inline construction sites'
          ``getattr(self, "networking_*")`` path.

        ASSUMPTION: any future change to ``apply_configvalues`` that
        transforms ``secret`` / ``cert_file`` / ``key_file`` /
        ``pool_size`` MUST either mirror that transformation here too,
        or move the storage to a write-back-into-yaml_config style so
        this helper continues to read the resolved value.

        Mirrors the auto/direct_discoverable forcing rule from
        ``ConfigUtil.apply_configvalues`` (auto=True → direct=True).
        All numeric fields fall back to defaults on bad-type input,
        matching ``apply_configvalues``' defensive parsing.
        """
        from pathlib import Path as _Path
        from .networking import (
            DEFAULT_HEARTBEAT_INTERVAL as _DEF_HB,
            DEFAULT_LOOKUP_INTERVAL as _DEF_LOOK,
            DEFAULT_LIVENESS_TIMEOUT as _DEF_LIVE,
            DEFAULT_RESYNC_INTERVAL as _DEF_RESYNC,
        )

        nw_cfg = yaml_config.get("networking") or {}

        def _safe_float(val, default):
            try:
                f = float(val)
                return f if f > 0 else default
            except (TypeError, ValueError):
                return default

        auto_disc = nw_cfg.get("auto_discoverable", False)
        direct_disc = nw_cfg.get("direct_discoverable", False)
        if auto_disc and not direct_disc:
            direct_disc = True

        cfg_dir = _Path(self.config_path).parent

        return NetworkManager(
            self,
            self._logger.getChild("networking"),
            node_ips=nw_cfg.get("node_ips", []),
            discover_nodes=nw_cfg.get("discover_nodes", False),
            direct_discoverable=direct_disc,
            auto_discoverable=auto_disc,
            port=nw_cfg.get("port", 2510),
            # C-029 + C-030: legacy secret / cert_file / key_file kwargs
            # removed. mTLS auth derives identity from the `peers:`
            # schema; `cert_file`/`key_file` in nw_cfg are now ignored
            # silently. Future enhancement: warn at config-load time if
            # legacy keys are present (operator hint).
            pool_size=nw_cfg.get("pool_size", 5),
            networking_config=nw_cfg,
            config_dir=cfg_dir,
            heartbeat_interval=_safe_float(
                nw_cfg.get("heartbeat_interval", _DEF_HB), _DEF_HB
            ),
            lookup_interval=_safe_float(
                nw_cfg.get("lookup_interval", _DEF_LOOK), _DEF_LOOK
            ),
            liveness_timeout=_safe_float(
                nw_cfg.get("liveness_timeout", _DEF_LIVE), _DEF_LIVE
            ),
            # C-109: periodic full-snapshot resync interval (5min default).
            # 0 disables the resync sweep entirely (tests can opt out).
            resync_interval=_safe_float(
                nw_cfg.get("resync_interval", _DEF_RESYNC), _DEF_RESYNC
            ),
            # R2-LL-5: per-probe heartbeat budget. ``None`` (the default)
            # lets the NM constructor compute ``min(heartbeat_interval,
            # liveness_timeout)``; operators can pin a tighter value via
            # ``networking.probe_timeout`` in config.yml. Bad-type input
            # falls through to ``None`` so the constructor's default
            # math still applies.
            probe_timeout=(
                _safe_float(nw_cfg["probe_timeout"], None)
                if isinstance(nw_cfg.get("probe_timeout"), (int, float, str))
                else None
            ),
        )

    def _normalize_networking_for_diff(self, yaml_dict: dict) -> dict:
        """Return a copy of ``yaml_dict`` with rebuild-relevant defaults
        filled in.

        Used by Step 4's ``_networking_config_changed`` so the diff
        doesn't false-positive when one side has had
        ``apply_configvalues`` mutate it (writing back resolved defaults
        in-place) while the other is freshly parsed.

        Per cycle 3 HIGH-δ (originally cycle 3 LOW-1, upgraded).

        Fields normalised:

        * ``networking.enabled`` / ``networking.port`` /
          ``networking.auto_discoverable`` /
          ``networking.direct_discoverable`` — written back by
          ``apply_configvalues`` (utils.py:1056-1092). Defaults match
          ``apply_configvalues``'.
        * ``networking.keys_dir`` — read by ``NetworkManager.__init__``
          with default ``"_keys"`` (networking.py:176). Not written back
          by ``apply_configvalues`` but a rebuild trigger, so an
          implicit ``"_keys"`` candidate must compare equal to an
          explicit ``"_keys"`` live yaml.
        * ``general.hostname`` — written back by ``apply_configvalues``
          with ``socket.gethostname()`` fallback (utils.py:970-973).
          Also a rebuild trigger (lives under ``general``, not
          ``networking``).
        * Auto-forces-direct rule mirrored (auto=True → direct=True)
          so a candidate with explicit auto/no-direct doesn't
          false-diff against post-apply live yaml that already had
          direct flipped to True.

        Top-level dict is shallow-copied; ``networking`` and ``general``
        sub-dicts are shallow-copied. Other sections share refs with
        the input — diff only inspects the rebuild fields, so deeper
        isolation is unnecessary.
        """
        import socket as _socket

        out = dict(yaml_dict)

        # Networking section defaults.
        nw_in = out.get("networking") or {}
        if not isinstance(nw_in, dict):
            nw_in = {}
        nw_out = dict(nw_in)
        nw_out.setdefault("enabled", False)
        nw_out.setdefault("port", 2510)
        nw_out.setdefault("auto_discoverable", False)
        nw_out.setdefault("direct_discoverable", False)
        nw_out.setdefault("keys_dir", "_keys")
        # Step 4 cycle 1: peers absent vs explicit empty list both
        # equal post-normalization. Without this default, an old
        # yaml with peers: [] vs a new yaml dropping the key (or
        # vice versa) would diff-as-different and trigger a spurious
        # rebuild on a change that has no operational effect.
        nw_out.setdefault("peers", [])
        if nw_out["auto_discoverable"] and not nw_out["direct_discoverable"]:
            nw_out["direct_discoverable"] = True
        out["networking"] = nw_out

        # General section: hostname is a rebuild field. apply_configvalues
        # fills socket.gethostname() when absent or empty (utils.py:970-973);
        # mirror exactly so a fresh-parsed candidate without hostname
        # doesn't false-positive against a post-apply live yaml.
        gen_in = out.get("general") or {}
        if not isinstance(gen_in, dict):
            gen_in = {}
        gen_out = dict(gen_in)
        if not gen_out.get("hostname"):
            gen_out["hostname"] = _socket.gethostname()
        out["general"] = gen_out

        return out

    def _validate_networking_config(self, yaml_config: dict) -> None:
        """Pre-flight validation of a candidate networking config. Raises
        on first malformed peer or bad config; returns None on success.

        Called from the rebuild orchestrator BEFORE any state mutation
        AND BEFORE the new ``NetworkManager`` is constructed. Lets the
        rebuild abort cleanly on bad config — the live network keeps
        running, no torn-down state.

        No side effects: no SSL context creation, no socket binds, no
        temp files, no instance-state mutation. Re-uses
        ``NetworkManager._parse_peers_dryrun`` static helper.

        Disabled-network candidate (``networking.enabled: false``)
        short-circuits with no validation — nothing to validate when
        the rebuild target is "stop networking".

        Empty-peers-when-enabled is NOT caught here — it propagates to
        the construction-failure path in Step 7 (``NetworkManager.start()``
        already raises with an actionable message at networking.py:1072+
        when peers is empty). The pre-validation gate covers per-peer
        parse / fingerprint / endpoint-uniqueness errors that would
        otherwise tear down the live network just to surface a config
        typo.
        """
        nw_cfg = yaml_config.get("networking") or {}
        if not isinstance(nw_cfg, dict):
            raise ValueError("networking section must be a mapping")
        if not nw_cfg.get("enabled", False):
            return  # disabled → nothing to validate

        port_default = nw_cfg.get("port", 2510)

        from pathlib import Path as _Path

        keys_dir_str = nw_cfg.get("keys_dir", "_keys")
        keys_dir_path = _Path(keys_dir_str)
        if not keys_dir_path.is_absolute():
            keys_dir_path = (_Path(self.config_path).parent / keys_dir_path).resolve()

        NetworkManager._parse_peers_dryrun(
            self._logger.getChild("networking"),
            nw_cfg.get("peers") or [],
            port_default=port_default,
            keys_dir=keys_dir_path,
        )

    def _networking_config_changed(self, old_yaml: dict, new_yaml: dict) -> bool:
        """Return True iff a rebuild-trigger field differs between
        ``old_yaml`` and ``new_yaml``. Rebuild triggers are
        ``networking.peers``, ``networking.enabled``,
        ``networking.port``, ``networking.hostname``,
        ``general.hostname``, and ``networking.keys_dir`` — the
        explicit per-field compares below are the source of truth.

        Both sides are normalized via ``_normalize_networking_for_diff``
        before comparison so a fresh-parsed candidate (no defaults
        filled) doesn't false-positive against a post-apply live yaml
        (where ``apply_configvalues`` has written resolved defaults
        back in place). Per cycle 3 HIGH-δ.

        Hostname has TWO source paths (cycle 4 finding):

        * ``networking.hostname`` — read by ``NetworkManager.__init__``
          at networking.py:175 for ``self.hostname`` (the value the
          network layer uses on the wire).
        * ``general.hostname`` — read by ``apply_configvalues`` at
          utils.py:970-973 for ``plexus.hostname`` (the value the
          framework uses for topic-dispatch / sub author-id / etc.).

        ``apply_configvalues`` writes ONLY to ``general.hostname``
        (with ``socket.gethostname()`` fallback when absent/empty); it
        does NOT write to ``networking.hostname``. ``NetworkManager``
        falls back to ``socket.gethostname()`` independently for its
        own ``self.hostname`` if ``networking.hostname`` is absent.

        Both source paths must trigger rebuild on change so the live
        ``NetworkManager`` instance picks up a new hostname for either
        purpose. The diff compares both.

        Other networking fields (``heartbeat_interval`` /
        ``lookup_interval`` / ``liveness_timeout`` / ``pool_size`` /
        ``discover_nodes`` / ``direct_discoverable`` /
        ``auto_discoverable``) update the live NetworkManager attrs
        in place via ``_update_networking_in_place`` (Step 7) — NOT
        rebuild triggers. (C-029 + C-030: legacy ``secret`` /
        ``cert_file`` / ``key_file`` removed; mTLS identity is loaded
        from ``keys_dir`` on disk and rotation needs a full rebuild
        triggered by the ``keys_dir`` change above.)

        Caller contract: ``old_yaml`` and ``new_yaml`` MUST be non-None
        dicts. The Step 7 orchestrator short-circuits the
        ``old_yaml is None`` bootstrap case before reaching this
        method; ``new_yaml`` is guaranteed non-None because
        ``_load_yaml_dict``'s integrity check rejects empty/null yaml.
        """
        old_n = self._normalize_networking_for_diff(old_yaml)
        new_n = self._normalize_networking_for_diff(new_yaml)

        old_nw = old_n.get("networking") or {}
        new_nw = new_n.get("networking") or {}
        if old_nw.get("peers") != new_nw.get("peers"):
            return True
        if old_nw.get("enabled") != new_nw.get("enabled"):
            return True
        if old_nw.get("port") != new_nw.get("port"):
            return True
        if old_nw.get("keys_dir") != new_nw.get("keys_dir"):
            return True
        # networking.hostname — NetworkManager-internal source path.
        # apply_configvalues never writes this key, so both sides read
        # raw yaml. Both absent → both None → equal. Both fall back to
        # socket.gethostname() inside NetworkManager.__init__ at
        # construction time.
        if old_nw.get("hostname") != new_nw.get("hostname"):
            return True

        # general.hostname — framework-canonical source path filled by
        # apply_configvalues with socket.gethostname() fallback.
        # _normalize_networking_for_diff mirrors that fallback so an
        # absent-vs-explicit-default doesn't false-positive.
        old_gen = old_n.get("general") or {}
        new_gen = new_n.get("general") or {}
        if old_gen.get("hostname") != new_gen.get("hostname"):
            return True

        return False

    # ── Per-logger threshold API (delegates to LogUtil) ─────────────
    # Plugins should call self.set_logger_level / self.clear_logger_level /
    # self.list_logger_levels via the Plugin base helpers — those auto-fill
    # the owner tuple. These wrappers exist so the helpers have something to
    # delegate to and so admin/CLI code can pass owner explicitly if needed.

    def set_logger_level(
        self,
        name: str,
        *,
        console: Optional[str] = None,
        file: Optional[str] = None,
        plugin_name: str,
        plugin_uuid: str,
    ) -> None:
        LogUtil.set_logger_level(
            name, console=console, file=file, owner=(plugin_name, plugin_uuid)
        )

    def clear_logger_level(
        self,
        name: str,
        *,
        console: bool = True,
        file: bool = True,
        plugin_name: Optional[str] = None,
        plugin_uuid: Optional[str] = None,
    ) -> None:
        if plugin_name is None or plugin_uuid is None:
            owner = None
        else:
            owner = (plugin_name, plugin_uuid)
        LogUtil.clear_logger_level(name, console=console, file=file, owner=owner)

    def list_logger_levels(self) -> dict:
        return LogUtil.list_logger_levels()

    # ── Config file editing ──────────────────────────────────────────

    @log_errors
    def list_config_files(self) -> Dict[str, str]:
        """Return {label: absolute_path} for main config and all plugin configs.

        R2-DD-1: include a ``<name>/plugin_config.yml`` entry whenever
        the plugin directory exists, even if the YAML file is not yet
        on disk. The TUI / external editor needs the path so it can
        create the file on first save; gating on file existence
        excluded newly-added plugins from the listing.

        R2-DD-8: paths are normalised via ``os.path.normcase`` +
        ``os.path.realpath`` so case-insensitive filesystems
        (Windows) and symlinks compare consistently against the
        allowlist used in ``read_config_file`` / ``save_config_file``.
        """
        files = {}
        main_config = os.path.normcase(os.path.realpath(self.config_path))
        files["config.yml (main)"] = main_config

        for entry in self.yaml_config.get("plugins", []):
            name = entry.get("name", "")
            path = entry.get("path") or os.path.join(self.plugin_package, name)
            abs_dir = os.path.normcase(os.path.realpath(path))
            cfg = os.path.normcase(
                os.path.realpath(os.path.join(abs_dir, "plugin_config.yml"))
            )
            if os.path.isdir(abs_dir):
                files[f"{name}/plugin_config.yml"] = cfg

        return files

    @log_errors
    def read_config_file(self, path: str) -> str:
        """Read and return raw content of a known config file.

        Args:
            path: Absolute path to the config file.

        Returns:
            File content as string.

        Raises:
            FileNotFoundError: If path doesn't exist.
            ValueError: If path not in list_config_files().
        """
        # R2-DD-8: normcase + realpath so the path matches the
        # allowlist on case-insensitive filesystems and symlinks
        # resolve consistently. list_config_files applies the same
        # normalisation when building the allowed set.
        abs_path = os.path.normcase(os.path.realpath(path))
        allowed = set(self.list_config_files().values())
        if abs_path not in allowed:
            raise ValueError(f"Path not in known config files: {path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            return f.read()

    @log_errors
    def save_config_file(self, path: str, content: str, backup: bool = True) -> None:
        """Validate YAML, create .bak backup, and write content.

        Does NOT re-apply main config — call load_config_yaml() explicitly
        if you need settings to take effect immediately.

        Args:
            path: Absolute path to the config file.
            content: New YAML content to write.
            backup: Whether to create a .yml.bak before overwriting.

        Raises:
            ValueError: If path not in known config files or content parses to empty.
            yaml.YAMLError: If content is invalid YAML.
        """
        # R2-DD-8: normcase + realpath so the allowlist comparison
        # works on Windows / symlinks. Mirrors read_config_file +
        # list_config_files.
        abs_path = os.path.normcase(os.path.realpath(path))
        allowed = set(self.list_config_files().values())
        if abs_path not in allowed:
            raise ValueError(f"Path not in known config files: {path}")

        parsed = yaml.safe_load(content)
        if not parsed:
            raise ValueError("Config content is empty or null after parsing")

        with self._config_write_lock:
            if backup and os.path.exists(abs_path):
                with open(abs_path, "r", encoding="utf-8") as f:
                    old_content = f.read()
                bak_path = abs_path + ".bak"
                # R2-DD-7: write the backup to a sibling .bak.tmp
                # file first, then os.replace() it into the final
                # .bak path. The previous open(bak_path, "w") form
                # truncated the existing .bak at open() time, so a
                # disk-full / permission flip mid-write destroyed
                # the prior backup AND left a partial new backup —
                # the W2-H2 try/except only logged, it could not
                # restore the truncated content. The temp-file form
                # leaves the prior .bak intact on partial-write
                # failure and only swaps it atomically once the new
                # backup has been fully written + fsynced.
                bak_tmp_path = bak_path + ".tmp"
                bak_replaced = False
                try:
                    with open(bak_tmp_path, "w", encoding="utf-8") as f:
                        f.write(old_content)
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except (OSError, AttributeError):
                            pass
                    os.replace(bak_tmp_path, bak_path)
                    bak_replaced = True
                except OSError as exc:
                    self._logger.warning(
                        "save_config_file: .bak write failed for %s: %s "
                        "(continuing to main write)",
                        bak_path, exc,
                    )
                finally:
                    if not bak_replaced:
                        try:
                            os.unlink(bak_tmp_path)
                        except OSError:
                            pass

            # C-071: atomic write-then-rename so a concurrent reader
            # (async_load_config_yaml / _load_yaml_dict) cannot observe
            # a partial write. The reader path does NOT acquire
            # _config_write_lock (it is a threading.Lock that would
            # block the event loop), so atomicity on the filesystem
            # side is the only guard. os.replace() is atomic on POSIX
            # and Windows for same-volume renames; the temp file lives
            # next to the target so the rename never crosses volumes.
            #
            # try/finally: if the write or fsync raises (disk full,
            # permission flip, etc.) BEFORE os.replace runs, the .tmp
            # file is partial-state garbage on disk. Clean it up so
            # operators diagnosing a failed save don't see stale
            # leftovers next to the real config.
            tmp_path = abs_path + ".tmp"
            rename_done = False
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    f.write(content)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except (OSError, AttributeError):
                        # fsync is best-effort: some filesystems
                        # (Windows pipes, certain network mounts)
                        # don't support it. The atomic rename below
                        # is the load-bearing guarantee for
                        # reader-side correctness.
                        pass
                os.replace(tmp_path, abs_path)
                rename_done = True
            finally:
                if not rename_done:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    def is_main_config(self, path: str) -> bool:
        """Check if path points to the main config.yml."""
        return os.path.abspath(path) == os.path.abspath(self.config_path)

    @async_log_errors
    async def load_plugins(self):
        # Load the plugins
        await self.get_plugins()

        # Resolve declared dependencies (cycles, missing/mismatched
        # versions, transitive cascade) BEFORE enabling. Failed plugins
        # transition to FAILED_LOAD so start_plugins skips them.
        await self._resolve_dependencies()

        # Enable them
        await self.start_plugins()

        # Rate limiter (Step 3): build the charge-set side-tables now that every
        # plugin's endpoints / events / subscriptions are registered. No-op when
        # no rate limit is configured (the default).
        await self._rebuild_charge_sets()

        self._logger.info(f"Finished Loading plugins!")

    async def _resolve_dependencies(self) -> None:
        """Resolve plugin dependencies after load, before enable.

        Boot-only. Hot-reload paths (_reload_plugin) do NOT trigger this
        — operator restart required to enforce changed deps.

        Failed plugins are transitioned to FAILED_LOAD via the two-phase
        protocol: _set_plugin_state_no_emit under plugin_lock, then emit
        AFTER releasing (sync observers must NOT acquire plugin_lock).
        Resolver runs INSIDE the lock so the plugin_versions /
        disabled_in_config / failed_load_names snapshots are consistent.

        Not decorated with @async_log_errors. If resolve() itself raises
        (programmer bug), the exception propagates out via load_plugins
        (which IS @async_log_errors and re-raises) -> asyncio.gather at
        core.py:708-718 -> wait_until_ready. Framework start fails fast
        with a loud traceback rather than silently producing an empty
        topo order.
        """
        pending_emits = []
        # Pre-bind so the post-lock optional_warnings loop doesn't trip
        # UnboundLocalError on a future caller that wraps
        # _resolve_dependencies in try/except (the docstring relies on
        # the resolver's exception propagating, but a future maintainer
        # might add a guard that swallows it — defensive pre-bind keeps
        # the post-lock cleanup safe in either case).
        result: Optional[DepResolutionResult] = None
        async with self.plugin_lock:
            # plugin_lock serializes against pop_plugin / enable_plugin /
            # disable_plugin / _reload_plugin. It does NOT serialize
            # against _apply_yaml at core.py:1188 (which mutates
            # self.yaml_config without any lock). Safe at boot only
            # because hot-reload cannot run before wait_until_ready
            # returns. Do not generalize this guarantee to runtime
            # callers without an additional guard.
            plugin_versions = {
                name: self.plugins[name].version
                for name in self._plugin_deps
                if name in self.plugins
            }
            # Match core.py:2032's "not get('enabled')" with NO default —
            # absent key is treated as disabled, same as core skips it.
            # Warn (not error) on non-bool enabled values so operator
            # typos (e.g. `enabled: 0`) surface a hint.
            disabled_in_config: Set[str] = set()
            for entry in self.yaml_config.get("plugins", []):
                entry_name = entry.get("name")
                if not entry_name:
                    continue
                enabled_val = entry.get("enabled")
                if enabled_val is not None and not isinstance(enabled_val, bool):
                    self._logger.warning(
                        f"Plugin '{entry_name}': 'enabled' in config.yml "
                        f"should be a bool, got {type(enabled_val).__name__} "
                        f"({enabled_val!r}) — treating as {bool(enabled_val)}."
                    )
                if not enabled_val:
                    disabled_in_config.add(entry_name)
            # Plugins already in FAILED_LOAD from prior framework load
            # failures (Python import error, on_load raise) are absent
            # from _plugin_deps. Resolver uses this set to emit the
            # distinct "failed to load" reason rather than generic
            # "missing" for their dependents.
            failed_load_names = {
                n for n, ps in self.plugin_states.items()
                if ps.state == State.FAILED_LOAD
            }

            result = _resolve_deps(
                self._plugin_deps,
                plugin_versions,
                __version__,
                disabled_in_config=disabled_in_config,
                failed_load_names=failed_load_names,
            )

            for failed_name in result.failed:
                if failed_name not in self.plugin_states:
                    continue
                # R2-HH-7: both INACTIVE -> FAILED_LOAD and UNLOADED ->
                # FAILED_LOAD are valid per _VALID_TRANSITIONS (core.py).
                # A plugin reaching the cascade here may be in either
                # source state: INACTIVE (normal load succeeded but its
                # dependency failed resolution) or UNLOADED (the plugin
                # itself failed to even load and we are now cascading
                # the failure to its dependents).
                old_state, new_state, ts = self._set_plugin_state_no_emit(
                    failed_name, State.FAILED_LOAD
                )
                reason = result.failed[failed_name]
                pending_emits.append(
                    (failed_name, old_state, new_state, ts, reason)
                )
            self._dep_topo_order = result.topo_order

        # plugin_lock released. Emits + logs fire outside lock.
        for failed_name, old_state, new_state, ts, reason in pending_emits:
            self._logger.error(
                f"Plugin '{failed_name}': dependency check failed: {reason}"
            )
            self._emit_plugin_state_change(failed_name, old_state, new_state, ts)
        for warning in result.optional_warnings:
            self._logger.warning(warning)

    @async_log_errors
    async def get_plugins(self) -> None:

        for plugin_entry in self.yaml_config.get("plugins", []):

            # Load and initiate the pluginclass
            await self.load_plugin_with_conf(plugin_entry)

    @async_log_errors
    async def start_plugins(self) -> None:
        """Enable INACTIVE plugins in topological dependency order.

        Plugins are grouped into levels by required-dep depth (built via
        _build_topo_levels from self._dep_topo_order which the resolver
        populates at boot). Within a level, enables run in parallel via
        asyncio.gather; between levels they are sequential. Optional
        deps do NOT contribute to ordering — see dependencies.py
        decision 5.

        Plugins marked FAILED_LOAD by _resolve_dependencies are not in
        _dep_topo_order, so they are skipped here. Any plugin in a
        non-INACTIVE state (already ENABLED, mid-transition, FAILED_LOAD)
        is also skipped via the state check.

        Enable-time cascade: before scheduling each level, re-check each
        candidate's required-dep states. A required dep transitioned
        back to INACTIVE by _enable_plugin_under_lock's rollback path
        (on_enable raise) means a downstream dependent should NOT run
        its own on_enable. Transition the dependent to FAILED_LOAD with
        a cascade reason and skip. Batch the cascade per level (single
        plugin_lock acquire) to avoid lock-acquire churn.

        Re-entry note: _dep_topo_order is a boot-time snapshot. A
        runtime call after pop_plugin uses stale topo data; the
        plugin = self.plugins.get(name) guard handles popped entries.
        Runtime-added plugins won't appear until next load_plugins.
        """
        levels = self._build_topo_levels()
        for level in levels:
            tasks = []
            task_plugins = []
            cascaded: List[Tuple[str, List[str]]] = []
            for name in level:
                plugin = self.plugins.get(name)
                if plugin is None:
                    continue
                ps = self.plugin_states.get(name)
                if ps is None or ps.state != State.INACTIVE:
                    continue
                # Enable-time dep-state precheck.
                unmet: List[str] = []
                for spec in self._plugin_deps.get(name, []):
                    if spec.optional or spec.name == PLEXUS_SELF_NAME:
                        continue
                    dep_ps = self.plugin_states.get(spec.name)
                    if dep_ps is None or dep_ps.state != State.ENABLED:
                        unmet.append(spec.name)
                if unmet:
                    cascaded.append((name, unmet))
                    continue
                tasks.append(self.enable_plugin(name))
                task_plugins.append(plugin)

            # Batched cascade transitions for this level: single
            # plugin_lock acquire, then all emits + logs outside lock.
            if cascaded:
                cascade_emits = []
                async with self.plugin_lock:
                    for name, unmet in cascaded:
                        old_state, new_state, ts = self._set_plugin_state_no_emit(
                            name, State.FAILED_LOAD
                        )
                        # W1-B3: record a machine-readable cascade error so
                        # operators querying last_errors[Phase.LOAD] for a
                        # cascade-failed plugin see the upstream context.
                        # exception_type matches the dotted-path format used
                        # at line 2737; traceback is empty because the cascade
                        # is an inference, not a raised exception.
                        cascade_reason = (
                            f"required dep(s) {sorted(unmet)!r} did not "
                            f"reach ENABLED (enable-time cascade)"
                        )
                        self.plugin_states[name].last_errors[Phase.LOAD] = (
                            ErrorRecord(
                                exception_type="plexus.exceptions.PluginDependencyError",
                                exception_repr=cascade_reason,
                                traceback="",
                                ts=ts,
                            )
                        )
                        cascade_emits.append(
                            (name, unmet, old_state, new_state, ts)
                        )
                for name, unmet, old_state, new_state, ts in cascade_emits:
                    self._logger.error(
                        f"Plugin '{name}': required dep(s) {unmet!r} did "
                        f"not reach ENABLED (enable-time cascade); "
                        f"skipping enable"
                    )
                    self._emit_plugin_state_change(
                        name, old_state, new_state, ts
                    )

            if not tasks:
                continue
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for plugin, result in zip(task_plugins, results):
                # W3-I2: BaseException catches both Exception AND
                # CancelledError (which moved from Exception to BaseException
                # in Python 3.8). gather(return_exceptions=True) returns
                # CancelledError instances for cancelled tasks; the prior
                # narrow check silently treated those as success.
                #
                # Cycle review I2/J1: split the log severity. Routine
                # framework-shutdown cancellation logs at WARNING without
                # a traceback (would be noisy and uninformative — every
                # shutdown would spam tracebacks). Real exceptions still
                # log at ERROR with exc_info.
                if isinstance(result, asyncio.CancelledError):
                    self._logger.warning(
                        'Enable cancelled for plugin "%s" '
                        '(framework shutdown or peer task cancel)',
                        plugin.plugin_name,
                    )
                elif isinstance(result, BaseException):
                    self._logger.error(
                        'Error occurred while enabling plugin with name "%s": %s: %s',
                        plugin.plugin_name,
                        type(result).__name__,
                        result,
                        exc_info=result,
                    )

    def _build_topo_levels(self) -> List[List[str]]:
        """Group self._dep_topo_order into levels by required-dep depth.

        Level N contains plugins whose required deps all live in levels
        < N. Optional deps and the plexus sentinel contribute no
        ordering. Belt-and-suspenders: if a required dep target is
        missing from the placed map (should not happen — the resolver
        would have failed the dependent), log a warning and treat as
        level 0.

        Runs outside plugin_lock. Pop-window race is benign: popped
        entries become None at start_plugins enable time and are
        skipped via plugins.get(name) guard.
        """
        levels: List[List[str]] = []
        placed: Dict[str, int] = {}
        for name in self._dep_topo_order:
            deps = self._plugin_deps.get(name, [])
            max_dep_level = -1
            for spec in deps:
                if spec.optional or spec.name == PLEXUS_SELF_NAME:
                    continue
                if spec.name in placed:
                    max_dep_level = max(max_dep_level, placed[spec.name])
                else:
                    self._logger.warning(
                        f"_build_topo_levels: required dep '{spec.name}' "
                        f"of '{name}' not in topo order (resolver "
                        f"invariant violation; treating as level 0)"
                    )
            my_level = max_dep_level + 1
            placed[name] = my_level
            while len(levels) <= my_level:
                levels.append([])
            levels[my_level].append(name)
        return levels

    @async_log_errors
    async def load_plugin_with_conf(self, plugin_entry: list) -> None:

        async def error_config(message):
            self._logger.error(f"Plugin '{name}': {message}")
            await self.pop_plugin(name)

        async def warn_config(message):
            self._logger.warning(f"Plugin '{name}': {message}")

        # Get values
        name = plugin_entry["name"]

        # Validate plugin name shape (identifier + non-reserved). Done up
        # front so the rejection happens before file I/O. C-059:
        # underscore-prefix is disallowed for plugin names because the
        # plugin name composes into the default topic prefix and would
        # collide with the framework's ``_core/...`` reserved namespace.
        try:
            _validate_identifier_name(
                name,
                context="plugin name",
                disallow_underscore_prefix=True,
            )
        except ValueError as e:
            await error_config(str(e))
            return

        if not plugin_entry.get("enabled"):
            self._logger.debug(
                f'Plugin "{name}" wont be loaded due to it being disabled'
            )
            if name in self.plugins:
                # Existing instance from a prior load — pop it. pop_plugin
                # transitions ENABLED→...→UNLOADED itself.
                await self.pop_plugin(name)
            else:
                # No instance to pop. Create or transition the plugin_states
                # entry so TUI/external code can see the plugin exists in
                # config but has no instance.
                if name in self.plugin_states:
                    if self.plugin_states[name].state != State.UNLOADED:
                        self._transition_plugin(name, State.UNLOADED)
                else:
                    self.plugin_states[name] = PluginState(
                        name=name, state=State.UNLOADED
                    )
            return

        if name in list(self.plugins.keys()):
            self._logger.info(
                f'Plugin "{name}" has an old instance, that will be overwritten'
            )
            await self.pop_plugin(name)

        # Resolve plugin directory
        path = plugin_entry.get("path") or os.path.join(self.plugin_package, name)
        path = os.path.abspath(path)
        if not os.path.exists(path):
            await error_config(f"Plugin directory missing: {name} ({path})")
            return

        # Load plugin config
        try:
            with open(
                os.path.join(path, "plugin_config.yml"), "r", encoding="utf-8"
            ) as f:
                plugin_config = yaml.safe_load(f)
        except Exception as e:
            await error_config(f"Failed loading config for {name}: {e}")
            return

        # Validate plugin config
        for field in [
            "description",
            "version",
            "remote",
            "arguments",
            "endpoints",
            "dependencies",
        ]:
            if field not in plugin_config:
                await warn_config(f"{name} missing {field} in plugin_config.yml")

        # Parse `dependencies:` shape early so malformed YAML fails the
        # plugin load before any expensive instantiation. Stash happens
        # LATE (under plugin_lock at the registration block) so a
        # partial-load failure between here and registration does NOT
        # leave a ghost entry in self._plugin_deps.
        deps_raw = plugin_config.get("dependencies")
        deps_parsed, deps_field, deps_reason = parse_dependencies(deps_raw)
        if deps_reason is not None:
            prefix = f".{deps_field}" if deps_field else ""
            await error_config(f"dependencies{prefix}: {deps_reason}")
            return
        # SHAPE-only identifier check on each dep target. Forward
        # references (cycle plugins pointing at each other before both
        # are loaded) are intentionally legal here; existence checks
        # happen later in _resolve_dependencies after all plugins are
        # loaded. Skip the plexus self-sentinel.
        for spec in deps_parsed:
            if spec.name == PLEXUS_SELF_NAME:
                continue
            try:
                _validate_identifier_name(spec.name, context="dependency target")
            except ValueError as e:
                await error_config(str(e))
                return

        # Early shape check on RAW endpoints config (PR2: dict keyed by
        # access_name). Catches the legacy list-form before override
        # merge runs — overrides on a list-shaped base would silently
        # discard the base. Detail validation (required fields, types,
        # access_name keys, internal_name shape) runs AFTER override
        # merge so override-introduced violations are also caught (C12).
        endpoints_raw = plugin_config.get("endpoints")
        if endpoints_raw is None:
            # Absent or null endpoints -> plugin has 0 endpoints. Skip rest.
            pass
        elif isinstance(endpoints_raw, list):
            await error_config(
                "endpoints: must be a dict keyed by access_name; list-form was "
                "removed in PR2. Convert each list entry to a dict entry "
                "keyed by its access_name."
            )
            return
        elif not isinstance(endpoints_raw, dict):
            await error_config(
                f"endpoints: must be a dict keyed by access_name; got "
                f"{type(endpoints_raw).__name__}."
            )
            return

        # ── Argument override application ────────────────────────────────
        # Base args from plugin_config.yml. Must be dict-or-null.
        base_args = plugin_config.get("arguments")
        if base_args is not None and not isinstance(base_args, dict):
            await error_config(
                f"top-level 'arguments' in plugin_config.yml must be a mapping (dict) "
                f"or omitted; got {type(base_args).__name__}"
            )
            return

        # Detect legacy top-level `arguments:` on the plugin entry — Q22:
        # field was renamed to `overrides.arguments:` in PR2.
        if "arguments" in plugin_entry:
            await warn_config(
                "main config 'arguments:' on plugin entry is a legacy field; "
                "use `overrides.arguments:` instead. Ignored."
            )

        # Q22: warn on any other unrecognized plugin-entry-level field.
        # Common mistake: writing `prefix:` or `verbose_notifier:` at the
        # plugin-entry level instead of inside `overrides:`. Warn + ignore.
        _KNOWN_PLUGIN_ENTRY_KEYS = frozenset(
            {
                "name",
                "enabled",
                "path",
                "overrides",
                # legacy `arguments:` already handled above with a tailored
                # message; include here so we don't double-warn.
                "arguments",
            }
        )
        for stray_key in plugin_entry.keys():
            if stray_key in _KNOWN_PLUGIN_ENTRY_KEYS:
                continue
            await warn_config(
                f"main config plugin entry for {name!r}: unknown field "
                f"{stray_key!r}; expected one of "
                f"{sorted(_KNOWN_PLUGIN_ENTRY_KEYS - {'arguments'})} "
                f"or place plugin_config overrides inside `overrides:` "
                f"(Q22). Ignored."
            )

        # Apply broader `overrides:` block from main config plugin entry.
        # Type-check (dict-or-None or warn-and-ignore deployment misconfig).
        override = plugin_entry.get("overrides")
        if override is None:
            merged_config = dict(plugin_config)
        elif not isinstance(override, dict):
            await warn_config(
                f"main config 'overrides' for '{name}' must be a mapping; "
                f"got {type(override).__name__}; ignoring overrides"
            )
            merged_config = dict(plugin_config)
        else:
            try:
                merged_config = apply_overrides(
                    plugin_config, override, name, self._logger
                )
            except ValueError as e:
                await error_config(f"override application failed: {e}")
                return

        # Validate MERGED endpoints (post-override). Override-introduced
        # violations (e.g. `__replace__: true` that drops required fields,
        # or a wrong-type boolean) are caught here. C12 contract.
        merged_endpoints = merged_config.get("endpoints")
        if merged_endpoints is None:
            # No endpoints after merge - fine, plugin has 0 endpoints.
            pass
        elif not isinstance(merged_endpoints, dict):
            # Should not happen given apply_overrides type checks, but
            # defensive guard. apply_overrides would raise on a non-dict
            # `endpoints:` override, and the early shape check above
            # rejected list/non-dict raw form.
            await error_config(
                f"endpoints (post-override) must be a dict keyed by access_name; "
                f"got {type(merged_endpoints).__name__}"
            )
            return
        else:
            for ep_key, endpoint in merged_endpoints.items():
                # The dict key is the canonical access_name. Validate it.
                try:
                    _validate_identifier_name(ep_key, context="endpoint access_name")
                except ValueError as e:
                    await error_config(str(e))
                    return

                if not isinstance(endpoint, dict):
                    await error_config(
                        f"endpoint '{ep_key}': value must be a mapping; got "
                        f"{type(endpoint).__name__}"
                    )
                    return

                # access_name field on the entry is optional; if present and
                # different from the dict key, warn and use the key.
                if "access_name" in endpoint:
                    ep_access = endpoint.get("access_name")
                    if ep_access != ep_key:
                        await warn_config(
                            f"endpoint '{ep_key}': 'access_name' field "
                            f"{ep_access!r} differs from dict key; using key "
                            f"{ep_key!r}"
                        )

                # remote, accessible_by_other_plugins still required (C12:
                # `__replace__: true` that omits these triggers this check).
                for field in ["remote", "accessible_by_other_plugins"]:
                    if field not in endpoint:
                        await error_config(
                            f"endpoint '{ep_key}' is missing {field} in plugin_config.yml"
                        )
                        return

                # internal_name optional; if present, validate as str/non-empty/ascii.
                if "internal_name" in endpoint:
                    iv = endpoint["internal_name"]
                    if type(iv) != str:
                        await error_config(
                            f"endpoint '{ep_key}': internal_name has wrong type "
                            f"{type(iv)} in plugin_config.yml as it must be a "
                            f"{str}"
                        )
                        return
                    if not iv.strip():
                        await error_config(
                            f"endpoint '{ep_key}': internal_name is empty in "
                            f"plugin_config.yml"
                        )
                        return
                    if not iv.isascii():
                        await error_config(
                            f"endpoint '{ep_key}': internal_name contains non "
                            f"ascii chars in plugin_config.yml"
                        )
                        return

                # Type checks for required boolean fields.
                for check in [
                    ("remote", bool, False, False),
                    ("accessible_by_other_plugins", bool, False, False),
                ]:  # ({config_option}, {type}, {empty_allowed}, {check_ascii})
                    if type(endpoint[check[0]]) != check[1]:
                        await error_config(
                            f"endpoint '{ep_key}': {check[0]} has wrong type "
                            f"{type(endpoint[check[0]])} in plugin_config.yml "
                            f"as it must be a {check[1]}"
                        )
                        return

        merged_args = merged_config.get("arguments")

        # Dynamic import. C-056: module-level execution (imports, decorator
        # evaluation, top-level statements in plugin.py) may raise. Mirror
        # the Plugin(...) FAILED_LOAD catch below so a broken plugin module
        # leaves an observable plugin_states entry instead of vanishing
        # silently. Pre-create the state entry on raise (load_plugin_with_conf
        # normally pre-creates AFTER exec_module + class lookup, but here
        # the raise short-circuits that path) so observers can see the
        # FAILED_LOAD transition and read last_errors[Phase.LOAD].
        #
        # Multi-file plugin support (2026-05-27): the plugin's directory is
        # added to sys.path so absolute imports like
        # `from plexus_my_plugin.consumer import run` resolve against any
        # sub-package the plugin author ships alongside plugin.py. Also pass
        # submodule_search_locations to the spec so relative imports
        # (`from . import consumer`) work if the plugin author uses that
        # pattern. We snapshot sys.modules before exec_module so
        # _pop_plugin_under_lock can clean up the plugin's added module
        # entries at unload time (prevents stale-cache bugs on hot-reload).
        # Without this cleanup, a reload would re-bind to old module objects
        # via Python's import cache.
        module_path = os.path.join(path, "plugin.py")
        plugin_dir = path
        # Defensive lazy-init for tests that build a Plexus instance via
        # object.__new__(Plexus) bypassing the regular __init__. Production
        # code paths always go through __init__ which sets this to {} up front.
        if not hasattr(self, "_plugin_loader_cleanup"):
            self._plugin_loader_cleanup = {}
        sys_path_was_added = plugin_dir not in sys.path
        if sys_path_was_added:
            # append (not insert) so stdlib + framework win over plugin files.
            # Without this, a plugin shipping `logging.py` (or any stdlib name)
            # at its top level would shadow Python stdlib for the WHOLE process,
            # not just the plugin. future-expansion-c12 MAJ-1 (2026-05-27).
            sys.path.append(plugin_dir)
        modules_before = set(sys.modules.keys())
        spec = importlib.util.spec_from_file_location(
            name,
            module_path,
            submodule_search_locations=[plugin_dir],
        )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except BaseException as exc:
            # Undo our sys.modules + sys.path additions before propagating, so
            # a retry (or a subsequent plugin) sees a clean state. Mirror the
            # successful-load bookkeeping + filter to plugin-owned modules only
            # (failure-modes-c12 CRIT-1: never purge third-party deps from
            # sys.modules; another plugin might be holding live references).
            _plugin_dir_norm_exc = os.path.normcase(os.path.abspath(plugin_dir))
            for _mod_name in set(sys.modules.keys()) - modules_before:
                _mod = sys.modules.get(_mod_name)
                if _mod is None:
                    continue
                _mod_file = getattr(_mod, "__file__", None)
                if _mod_file is None:
                    continue
                try:
                    _mod_file_norm = os.path.normcase(os.path.abspath(_mod_file))
                    if os.path.commonpath([_plugin_dir_norm_exc, _mod_file_norm]) == _plugin_dir_norm_exc:
                        sys.modules.pop(_mod_name, None)
                except (TypeError, ValueError):
                    continue
            if sys_path_was_added:
                try:
                    sys.path.remove(plugin_dir)
                except ValueError:
                    pass  # already removed by something else (defensive)
            # Always leave an observable plugin_states entry so the plugin
            # does not silently vanish from introspection. On cancellation
            # we DO NOT transition to FAILED_LOAD (cancellation is not a
            # plugin error — same convention as the Plugin(...)
            # instantiation catch below); we just leave the pre-created
            # UNLOADED entry in place so an operator can see "load was
            # attempted but interrupted." Only non-cancellation errors
            # write Phase.LOAD + transition to FAILED_LOAD.
            if name not in self.plugin_states:
                self.plugin_states[name] = PluginState(
                    name=name, state=State.UNLOADED
                )
            if not isinstance(exc, asyncio.CancelledError):
                self.plugin_states[name].last_errors[Phase.LOAD] = ErrorRecord(
                    exception_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
                    exception_repr=repr(exc),
                    traceback=traceback.format_exc(),
                    ts=time.time(),
                )
                self._transition_plugin(name, State.FAILED_LOAD)
                self._logger.error(
                    "Plugin '%s': module-level exec_module raised — %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
            raise
        # Success: record sys.modules + sys.path additions for pop-time cleanup.
        # Filter modules_added to ONLY plugin-owned modules (those whose __file__
        # lives under plugin_dir) — third-party libs the plugin transitively
        # imported (httpx, numpy, yaml, etc.) are NOT owned and must NOT be
        # purged on pop. Without this filter, popping plugin A would remove
        # shared deps from sys.modules; plugin B's subsequent `import httpx`
        # would re-execute the httpx module, creating a SECOND module object
        # and breaking class identity / isinstance checks across plugins.
        # failure-modes-c12 CRIT-1 + CRIT-2 (2026-05-27).
        modules_added_all = set(sys.modules.keys()) - modules_before
        plugin_dir_norm = os.path.normcase(os.path.abspath(plugin_dir))
        modules_added_owned = set()
        for _mod_name in modules_added_all:
            _mod = sys.modules.get(_mod_name)
            if _mod is None:
                continue
            _mod_file = getattr(_mod, "__file__", None)
            if _mod_file is None:
                # Built-in, frozen, or namespace package without __file__.
                # Do NOT claim ownership; leave to Python's import machinery.
                continue
            try:
                _mod_file_norm = os.path.normcase(os.path.abspath(_mod_file))
            except (TypeError, ValueError):
                continue
            # Use commonpath to robustly test ancestry (handles trailing
            # separator + case-insensitive Windows paths via normcase above).
            try:
                if os.path.commonpath([plugin_dir_norm, _mod_file_norm]) == plugin_dir_norm:
                    modules_added_owned.add(_mod_name)
            except ValueError:
                # Different drives (Windows) — definitely not owned.
                continue
        self._plugin_loader_cleanup[name] = {
            "sys_modules_added": modules_added_owned,
            "sys_path_added": plugin_dir if sys_path_was_added else None,
        }

        # Find first Plugin subclass
        plugin_class = next(
            (
                cls
                for _, cls in inspect.getmembers(module, inspect.isclass)
                if issubclass(cls, Plugin) and cls != Plugin
            ),
            None,
        )
        if plugin_class is None:
            await error_config(f"No Plugin subclass found in {module_path}")
            return

        # Session 3 (v0.26.0): pre-create state entry BEFORE Plugin(...)
        # so the @property read inside Plugin.__init__ works (returns False
        # — only ENABLED state returns True from the property). On reload,
        # transition any existing entry (UNLOADED / FAILED_LOAD) to INACTIVE.
        if name in self.plugin_states:
            if self.plugin_states[name].state != State.INACTIVE:
                self._transition_plugin(name, State.INACTIVE)
            # C-021 fix: clear ONLY the prior Phase.LOAD error. Phase.ENABLE
            # / Phase.DISABLE errors from previous lifecycle cycles are
            # preserved so operators can still see why the plugin's last
            # enable / disable failed — re-load shouldn't wipe that
            # diagnostic context. The original `.clear()` wiped the whole
            # dict and lost those errors silently.
            self.plugin_states[name].last_errors.pop(Phase.LOAD, None)
        else:
            # C-131: pre-create with state=UNLOADED (not INACTIVE) so
            # observers polling self.plugin_states during the window
            # between pre-create and instance-bind see UNLOADED+None
            # — the natural "config exists, no instance yet" state —
            # instead of the inconsistent INACTIVE+None. The transition
            # to INACTIVE happens AFTER the instance is bound below.
            self.plugin_states[name] = PluginState(name=name, state=State.UNLOADED)

        # Instantiate with merged arguments. on_load runs inside __init__;
        # any raise (validation, missing config, plugin author error) puts
        # plugin_states[name] into FAILED_LOAD with traceback recorded.
        try:
            plugin = plugin_class(
                self._logger.getChild(name),
                self,
                arguments=merged_args,
                plugin_name=name,
            )
        except BaseException as exc:
            if not isinstance(exc, asyncio.CancelledError):
                self.plugin_states[name].last_errors[Phase.LOAD] = ErrorRecord(
                    exception_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
                    exception_repr=repr(exc),
                    traceback=traceback.format_exc(),
                    ts=time.time(),
                )
                # W1-B1: also keep the FAILED_LOAD transition inside this
                # guard. CancelledError is a transparent-cancellation
                # signal — moving plugin_states[name] to FAILED_LOAD on
                # cancel would poison the entry for a task that was
                # merely cancelled (no real load failure recorded; state
                # would lie about the cause).
                self._transition_plugin(name, State.FAILED_LOAD)
                self._logger.error(
                    "Plugin '%s': on_load raised — %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
            else:
                # Cycle review J2: cancellation is transparent; log at
                # DEBUG so operators tailing ERROR don't see "on_load
                # raised — CancelledError" for tasks that were cleanly
                # cancelled by framework shutdown.
                self._logger.debug(
                    "Plugin '%s' load cancelled: %s",
                    name,
                    exc,
                )
            raise

        plugin.plugin_name = name
        # R4-WW-2: fallback must be a valid PEP 440 string. The prior
        # placeholder literal tripped packaging.version.Version with
        # InvalidVersion, so every non-empty SpecifierSet check failed
        # against it (silently breaking version-constrained deps on any
        # plugin that did not declare a version in plugin_config.yml).
        raw_version = merged_config.get("version")
        if not raw_version:
            self._logger.warning(
                "Plugin %r has no version declared in plugin_config.yml; "
                "defaulting to '0.0.0'.",
                name,
            )
            plugin.version = "0.0.0"
        else:
            plugin.version = raw_version
        plugin.remote = merged_config.get("remote") or False
        plugin.description = merged_config.get("description") or "UNKNOWN"
        plugin.arguments = merged_args

        # PR3 Stage B: prefix + verbose_notifier plugin-level fields. prefix
        # defaults to plugin_name (per LOCKED J — author-default fallback).
        # verbose_notifier defaults to False (Q18). Both are overridable
        # via the standard overrides mechanism.
        prefix_val = merged_config.get("prefix")
        if prefix_val is None or (
            isinstance(prefix_val, str) and not prefix_val.strip()
        ):
            prefix_val = name
        if not isinstance(prefix_val, str):
            await warn_config(
                f"prefix must be a string; got {type(prefix_val).__name__}; "
                f"falling back to plugin_name"
            )
            prefix_val = name
        plugin.prefix = prefix_val

        # Q5: warn (allow) when another already-loaded plugin uses the
        # same prefix. Two instances sharing a prefix isn't an error
        # (intentional use case for running two Discord bots etc.) but
        # the warning helps the author spot accidental collisions.
        for existing_name, existing_plugin in self.plugins.items():
            if existing_name == name:
                continue
            existing_prefix = getattr(existing_plugin, "prefix", None)
            if existing_prefix == prefix_val:
                await warn_config(
                    f"plugin {name!r} prefix {prefix_val!r} collides with "
                    f"already-loaded plugin {existing_name!r} (Q5: warn + "
                    f"allow). Topic templates using {{prefix}} on either "
                    f"plugin will resolve to the same prefix segment — "
                    f"intentional only if you want shared advertisement."
                )

        verbose_val = merged_config.get("verbose_notifier", False)
        if not isinstance(verbose_val, bool):
            await warn_config(
                f"verbose_notifier must be a bool; got "
                f"{type(verbose_val).__name__}; falling back to False"
            )
            verbose_val = False
        plugin.verbose_notifier = verbose_val

        endpoints_cfg = merged_config.get("endpoints") or {}
        if not isinstance(endpoints_cfg, dict):
            # apply_overrides + the validator above already enforce dict shape.
            # Defensive guard against post-merge misshape.
            await warn_config(
                f"endpoints must be a dict keyed by access_name in "
                f"plugin_config.yml; got {type(endpoints_cfg).__name__}"
            )
            endpoints_cfg = {}
        plugin.endpoints = endpoints_cfg
        # Alias retained for backward-compatible callsite naming. Same dict.
        plugin._endpoint_by_access = plugin.endpoints

        # Step 4: parse this plugin's self-declared `rate_limits:` block (option
        # a) into its own flat (dim,key)->{max,window} dicts and stash them on
        # the plugin. _rebuild_charge_sets reads _declared_rate_limits off every
        # loaded plugin to recompute the declared layer (main config wins on any
        # overlapping key). Block carries the same out/in/endpoints/events/subs
        # sub-shape as main rate_limits.plugins.<name>; a malformed block fails
        # the plugin load loud (like any other manifest validation). The block
        # is namespaced to this plugin's name, so it can only limit itself.
        try:
            decl_cfg, decl_sub = parse_plugin_rate_limits(
                name, merged_config.get("rate_limits")
            )
        except ValueError as e:
            await error_config(f"rate_limits: {e}")
            return
        plugin._declared_rate_limits = (decl_cfg, decl_sub)

        # ── PR3 Stage B: parse events: and subscriptions: sections ─────
        # Both sections are optional, default to empty dict. Per LOCKED A.
        # Validation rules (LOCKED L + Q15 + Q16 + C20) applied here at
        # load. Topic templates resolved against load-time placeholders
        # ({prefix}, {plugin_name}, {hostname}, {plugin_uuid}); unknown
        # {var} placeholders are LEFT INTACT for runtime templating.
        events_cfg = merged_config.get("events")
        if events_cfg is None:
            events_cfg = {}
        if not isinstance(events_cfg, dict):
            await error_config(
                f"events: must be a mapping (dict keyed by event_id); got "
                f"{type(events_cfg).__name__}"
            )
            return

        subs_cfg = merged_config.get("subscriptions")
        if subs_cfg is None:
            subs_cfg = {}
        if not isinstance(subs_cfg, dict):
            await error_config(
                f"subscriptions: must be a mapping (dict keyed by "
                f"declared_id); got {type(subs_cfg).__name__}"
            )
            return

        hostname_val = self.hostname
        plugin_events: Dict[str, Dict[str, Any]] = {}
        for event_id, entry in events_cfg.items():
            try:
                _validate_identifier_name(event_id, context="event_id")
            except ValueError as e:
                await error_config(str(e))
                return
            if entry is None:
                entry = {}
            if not isinstance(entry, dict):
                await error_config(
                    f"events.{event_id}: entry must be a mapping; got "
                    f"{type(entry).__name__}"
                )
                return

            raw_topic = entry.get("topic")
            if raw_topic is None or not isinstance(raw_topic, str):
                await error_config(
                    f"events.{event_id}: 'topic' field is required and must "
                    f"be a string"
                )
                return

            # Resolve load-time placeholders (LOCKED J).
            resolved_topic = _resolve_load_time_template(
                raw_topic,
                prefix=plugin.prefix,
                plugin_name=name,
                hostname=hostname_val,
                plugin_uuid=plugin.plugin_uuid,
            )

            # Validate post-templating shape. Events forbid wildcards
            # (LOCKED L #1) but ALLOW {var} runtime placeholders (so we
            # only reject embedded * mid-segment + empty middle segments
            # + empty topic. Wildcards == any '*' character — but
            # _validate_topic_static checks segment-by-segment with
            # allow_wildcards=False rejecting ANY '*'. {var} placeholders
            # are FINE because they don't contain '*'.).
            try:
                stripped_topic = _validate_topic_static(
                    resolved_topic,
                    context=f"events.{event_id}.topic",
                    allow_wildcards=False,
                )
            except ValueError as e:
                await error_config(str(e))
                return

            # Validate event-entry hosts/blocked_hosts via the same
            # normalizer execute_sync uses (rejects empty list, empty
            # string in list, non-str items, etc.). Raw YAML values
            # otherwise reach _publisher_targets_local unchecked,
            # silently mishandling forms like `hosts: []` (would drop
            # all local fan-out without warning).
            try:
                eh = _normalize_hosts(
                    entry.get("hosts"),
                    param_name=f"events.{event_id}.hosts",
                    default=None,
                )
                ebh = _normalize_hosts(
                    entry.get("blocked_hosts"),
                    param_name=f"events.{event_id}.blocked_hosts",
                    default=None,
                    is_blocked=True,
                )
            except ValueError as e:
                await error_config(str(e))
                return

            entry_dict = {
                "topic": stripped_topic,
                "hosts": eh,
                "blocked_hosts": ebh,
                "enabled": (bool(entry["enabled"]) if "enabled" in entry else True),
            }
            plugin_events[event_id] = entry_dict
        plugin.events = plugin_events

        plugin_subs: Dict[str, Dict[str, Any]] = {}
        for declared_id, entry in subs_cfg.items():
            try:
                _validate_identifier_name(declared_id, context="declared_id")
            except ValueError as e:
                await error_config(str(e))
                return
            if entry is None:
                entry = {}
            if not isinstance(entry, dict):
                await error_config(
                    f"subscriptions.{declared_id}: entry must be a mapping; "
                    f"got {type(entry).__name__}"
                )
                return

            raw_topic = entry.get("topic")
            if raw_topic is None or not isinstance(raw_topic, str):
                await error_config(
                    f"subscriptions.{declared_id}: 'topic' field is required "
                    f"and must be a string"
                )
                return

            target_access = entry.get("target_access_name")
            if (
                target_access is None
                or not isinstance(target_access, str)
                or not target_access.strip()
            ):
                await error_config(
                    f"subscriptions.{declared_id}: 'target_access_name' "
                    f"field is required and must be a non-empty string"
                )
                return

            # Resolve load-time placeholders FIRST (then reject {var} +
            # other invalid shapes). LOCKED J says unknown {var} is left
            # intact at load time; subscriptions then reject any
            # remaining {var} syntax (LOCKED L #2). Reserved-template
            # vars are resolved away here, so only USER {var} survives,
            # which is then rejected.
            resolved_topic = _resolve_load_time_template(
                raw_topic,
                prefix=plugin.prefix,
                plugin_name=name,
                hostname=hostname_val,
                plugin_uuid=plugin.plugin_uuid,
            )
            try:
                stripped_topic = _validate_subscription_topic(
                    resolved_topic,
                    context=f"subscriptions.{declared_id}.topic",
                )
            except ValueError as e:
                await error_config(str(e))
                return

            # R2-KK-2: filter values may contain load-time templates
            # such as ``hosts: '{hostname}'`` (or per-item in a list).
            # Without templating, the literal brace string reaches the
            # filter logic and the subscription silently never matches.
            # Resolve BEFORE normalize so the normalizer sees the final
            # value (and so list-of-templates collapses + dedups cleanly
            # post-substitution).
            def _resolve_filter_value(raw):
                if isinstance(raw, str):
                    return _resolve_load_time_template(
                        raw,
                        prefix=plugin.prefix,
                        plugin_name=name,
                        hostname=hostname_val,
                        plugin_uuid=plugin.plugin_uuid,
                    )
                if isinstance(raw, list):
                    out = []
                    for item in raw:
                        if isinstance(item, str):
                            out.append(
                                _resolve_load_time_template(
                                    item,
                                    prefix=plugin.prefix,
                                    plugin_name=name,
                                    hostname=hostname_val,
                                    plugin_uuid=plugin.plugin_uuid,
                                )
                            )
                        else:
                            out.append(item)
                    return out
                return raw

            raw_hosts = entry.get("hosts", "any")
            raw_blocked_hosts = entry.get("blocked_hosts")
            raw_authors = entry.get("authors")
            raw_blocked_authors = entry.get("blocked_authors")

            raw_hosts = _resolve_load_time_template(
                raw_hosts,
                prefix=plugin.prefix,
                plugin_name=name,
                hostname=hostname_val,
                plugin_uuid=plugin.plugin_uuid,
            ) if isinstance(raw_hosts, str) else _resolve_filter_value(raw_hosts)
            raw_blocked_hosts = _resolve_filter_value(raw_blocked_hosts)
            raw_authors = _resolve_filter_value(raw_authors)
            raw_blocked_authors = _resolve_filter_value(raw_blocked_authors)

            # Normalize sub-level filter values via _normalize_hosts /
            # _normalize_authors (parity with the events: section fix from
            # cycle 6). Without this, YAML forms like `hosts: []` (empty
            # list — spec says invalid) would silently produce a sub that
            # rejects all delivery, with no warning at load time.
            try:
                sh = _normalize_hosts(
                    raw_hosts,
                    param_name=f"subscriptions.{declared_id}.hosts",
                    default="any",
                )
                sbh = _normalize_hosts(
                    raw_blocked_hosts,
                    param_name=f"subscriptions.{declared_id}.blocked_hosts",
                    default=None,
                    is_blocked=True,
                )
                sa = _normalize_authors(
                    raw_authors,
                    param_name=f"subscriptions.{declared_id}.authors",
                    default=None,
                )
                sba = _normalize_authors(
                    raw_blocked_authors,
                    param_name=f"subscriptions.{declared_id}.blocked_authors",
                    default=None,
                )
            except ValueError as e:
                await error_config(str(e))
                return

            # R2-DD-9: validate target_plugin / target_plugin_uuid
            # types BEFORE they are stored. A YAML entry with a
            # non-string value (e.g. ``target_plugin: 42``) used to
            # pass through unchecked and surface as AttributeError
            # at the first string operation downstream. Mirrors the
            # target_access_name validation above.
            target_plugin = entry.get("target_plugin", name)
            if not isinstance(target_plugin, str) or not target_plugin.strip():
                await error_config(
                    f"subscriptions.{declared_id}: 'target_plugin' must "
                    f"be a non-empty string; got {type(target_plugin).__name__}"
                )
                return

            target_plugin_uuid = entry.get("target_plugin_uuid")
            if target_plugin_uuid is not None and not isinstance(
                target_plugin_uuid, str
            ):
                await error_config(
                    f"subscriptions.{declared_id}: 'target_plugin_uuid' "
                    f"must be a string or null; got "
                    f"{type(target_plugin_uuid).__name__}"
                )
                return

            entry_dict = {
                "topic": stripped_topic,
                "target_access_name": target_access,
                "target_plugin": target_plugin,
                "target_plugin_uuid": target_plugin_uuid,
                "hosts": sh,
                "blocked_hosts": sbh,
                "authors": sa,
                "blocked_authors": sba,
                "enabled": (bool(entry["enabled"]) if "enabled" in entry else True),
            }
            plugin_subs[declared_id] = entry_dict
        plugin.subscriptions = plugin_subs

        async with self.plugin_lock:
            self.plugins[name] = plugin
            # C-153: Plugin.__init__ is @final and unconditionally sets
            # ``plugin_uuid`` to ``uuid4().hex``, so the previous
            # ``getattr(plugin, "plugin_uuid", None)`` defensive pattern
            # masked the contract. Read directly; if the contract is
            # ever violated by a future Plugin subclass that overrides
            # __init__ without calling super(), AttributeError will
            # surface the violation here instead of silently degrading.
            plugin_uuid = plugin.plugin_uuid
            if plugin_uuid:
                self.plugins_by_uuid[plugin_uuid] = plugin
            # Session 3 + C-131: bind instance into plugin_states then
            # transition UNLOADED -> INACTIVE atomically under
            # plugin_lock. The pre-create at 2270 set UNLOADED so
            # observers never saw INACTIVE+None mid-load; the emit
            # below publishes the consistent INACTIVE+instance pair.
            self.plugin_states[name].instance = plugin
            # W3-L4: capture the no-emit state-change tuple so the paired
            # emit can fire AFTER plugin_lock release. The UNLOADED ->
            # INACTIVE transition was previously invisible to observers
            # subscribed to _core/plugin/state_changed.
            inactive_change: Optional[Tuple[State, State, float]] = None
            if self.plugin_states[name].state == State.UNLOADED:
                inactive_change = self._set_plugin_state_no_emit(
                    name, State.INACTIVE
                )
            # Late-stash for dependencies. UNCONDITIONAL — placed after
            # the if-UNLOADED block so a future re-entry path with state
            # already INACTIVE still gets its deps stashed. Inside
            # plugin_lock so the stash is atomic with self.plugins[name].
            self._plugin_deps[name] = deps_parsed

        # plugin_lock RELEASED. Emit the deferred UNLOADED -> INACTIVE
        # state change so observers see the consistent INACTIVE+instance
        # pair the docstring promises (W3-L4).
        if inactive_change is not None:
            old_state, new_state, ts = inactive_change
            self._emit_plugin_state_change(name, old_state, new_state, ts)

        # PR3 Stage B moved YAML subscription registration to
        # _register_yaml_subscriptions (called from enable_plugin) so
        # that disable -> re-enable re-registers subs. Stage D removed
        # the legacy `topic:` field auto-registration path entirely.

        self._logger.info(
            f"Successfully loaded plugin: {name} (Version: {plugin.version}, Path: {path})"
        )

    @async_log_errors
    async def pop_plugin(self, plugin_name: str) -> None:
        """Remove a plugin from the runtime.

        Session 3 (v0.26.0) state-machine semantics: the resulting
        plugin_states entry depends on whether config still references
        the plugin.

        - Config has the entry → state becomes UNLOADED (entry kept;
          can be re-enabled later via enable_plugin).
        - Config dropped the entry → entry is removed from plugin_states
          entirely.

        For FAILED_LOAD or UNLOADED entries with no live instance,
        pop_plugin still applies these semantics — useful for clearing
        a stale FAILED_LOAD record after the underlying issue is fixed
        and the config entry has been removed.
        """
        self._logger.info(f"Popping plugin: {plugin_name}")
        try:
            config_has_entry = any(
                p.get("name") == plugin_name
                for p in self.yaml_config.get("plugins", [])
            )

            if plugin_name not in self.plugins:
                # R2-BB-2: acquire lifecycle_lock for the no-live-instance
                # early-return path. Without it, two concurrent pop_plugin
                # callers on the same stale name race; one may KeyError
                # inside _set_plugin_state_no_emit after the other has
                # already deleted the state entry. Mirrors the locking
                # discipline of the normal (live-instance) branch below.
                lifecycle_lock = self._get_lifecycle_lock(plugin_name)
                async with lifecycle_lock:
                    ps = self.plugin_states.get(plugin_name)
                    if ps is not None:
                        if config_has_entry:
                            if ps.state != State.UNLOADED:
                                self._transition_plugin(plugin_name, State.UNLOADED)
                        else:
                            self.plugin_states.pop(plugin_name, None)
                    else:
                        self._logger.warning(
                            f'Plugin with name "{plugin_name}" doesnt exist'
                        )
                return

            lifecycle_lock = self._get_lifecycle_lock(plugin_name)
            async with lifecycle_lock:
                try:
                    await self._pop_plugin_under_lock(plugin_name)
                finally:
                    # Post-pop state transition. Cycle 1 review: must run
                    # in finally so a partial failure inside
                    # _pop_plugin_under_lock doesn't leave plugin_states
                    # inconsistent. Only fires if the instance is gone
                    # (i.e. the dict-pop step inside _pop_plugin_under_lock
                    # ran). If _pop_plugin_under_lock raised before the
                    # dict pop, the plugin is still in self.plugins, so
                    # we skip the UNLOADED transition — its state was
                    # set to INACTIVE by _disable_plugin_under_lock's
                    # finally and the next pop attempt can resume cleanly.
                    if (
                        plugin_name in self.plugin_states
                        and plugin_name not in self.plugins
                    ):
                        if config_has_entry:
                            # Cycle 3 fix: clear instance BEFORE the
                            # state transition so observers of
                            # _core/plugin/state_changed reading
                            # `instance` for state == UNLOADED see None,
                            # not a stale reference to the just-popped
                            # plugin.
                            self.plugin_states[plugin_name].instance = None
                            self._transition_plugin(plugin_name, State.UNLOADED)
                        else:
                            del self.plugin_states[plugin_name]
        except Exception as error:
            # W5-R3: surface as RequestException (framework's documented
            # exception type for plugin-call failures) AND chain via
            # ``from error`` so callers inspecting __cause__ see the
            # original.
            raise RequestException(
                f'Error while popping plugin "{plugin_name}": {error}'
            ) from error

    @async_log_errors
    async def purge_plugins(self):
        # R4-UU-1: refuse to purge after close(). close() drives the
        # framework's own teardown; a concurrent purge_plugins call
        # would race that teardown for shared resources.
        if getattr(self, "_closed", False):
            self._logger.warning(
                "Refusing to reload/rebuild: Plexus is closed"
            )
            return
        # B-005 fix: delegate to pop_plugin per-name. pop_plugin fails
        # pending requests (request_lock loop) BEFORE disable, then
        # disables, pops dicts, unsubscribes, and clears logger levels
        # — the full cleanup path. The previous implementation called
        # disable_plugin per plugin then swept the dicts in a single
        # plugin_lock acquisition; that path skipped the pending-request
        # cancellation step (B-005). Reuses Stage O's
        # _pop_plugin_under_lock shared helper.
        #
        # R2-II-1: Behavior on per-plugin failure: continues iterating
        # on per-plugin failure, collecting errors into an
        # ExceptionGroup raised at end (C-022). Each pop is fully
        # independent — a single failing pop_plugin no longer halts
        # the rest of the purge. Plugins that pop successfully are
        # fully cleaned up; the ones that raised are reported via the
        # aggregated ExceptionGroup so the operator sees every failure.
        self._logger.info("Purging plugins")
        # C-022 fix: continue-and-collect. A failing pop on one plugin
        # used to abort the whole loop, leaving the rest of the plugins
        # still loaded with no operator signal which ones got purged.
        # Now each pop is wrapped individually and all exceptions are
        # surfaced together via ExceptionGroup (3.11+) at the end.
        # R2-BB-3: include ghost plugin_states entries (FAILED_LOAD /
        # UNLOADED with no live instance) so they don't linger after
        # purge. pop_plugin handles the no-live-instance case correctly
        # via its early-return branch.
        #
        # R4-UU-7: snapshot self.plugins + self.plugin_states under
        # self._config_lock so a concurrent loader / hot-reload cannot
        # mutate either dict mid-snapshot. The snapshot is taken inside
        # the lock; the per-name pop loop runs OUTSIDE the lock because
        # pop_plugin itself acquires per-plugin lifecycle locks (taking
        # _config_lock around the loop would re-enter or block them).
        async with self._config_lock:
            plugins_to_purge = list(
                set(self.plugins.keys()) | set(self.plugin_states.keys())
            )
        errors: List[BaseException] = []
        for plugin_name in plugins_to_purge:
            try:
                await self.pop_plugin(plugin_name)
            except Exception as exc:
                self._logger.error(
                    "purge_plugins: pop_plugin %r raised — continuing",
                    plugin_name,
                    exc_info=True,
                )
                errors.append(exc)
        if errors:
            raise ExceptionGroup(
                f"purge_plugins: {len(errors)} of "
                f"{len(plugins_to_purge)} plugins failed to pop",
                errors,
            )
        self._logger.info("Purged all plugins")

    @async_log_errors
    async def purge_plugins_except(self, excluded_names: List[str]):
        """Purge all plugins except those in the excluded_names list.

        B-005 fix: delegate to pop_plugin per-name. See purge_plugins
        for the full rationale.

        C-022 fix: per-iteration try/except + ExceptionGroup aggregation
        (3.11+). Symmetric with purge_plugins above.
        """
        self._logger.info(f"Purging plugins except: {excluded_names}")
        plugins_to_purge = [
            name for name in list(self.plugins.keys()) if name not in excluded_names
        ]
        errors: List[BaseException] = []
        for plugin_name in plugins_to_purge:
            try:
                await self.pop_plugin(plugin_name)
            except Exception as exc:
                self._logger.error(
                    "purge_plugins_except: pop_plugin %r raised — continuing",
                    plugin_name,
                    exc_info=True,
                )
                errors.append(exc)
        if errors:
            raise ExceptionGroup(
                f"purge_plugins_except: {len(errors)} of "
                f"{len(plugins_to_purge)} plugins failed to pop",
                errors,
            )
        self._logger.info(
            f"Purged {len(plugins_to_purge)} plugins, kept {len(excluded_names)}"
        )

    @async_log_errors
    async def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get structured information about a plugin."""
        async with self.plugin_lock:
            plugin = self.plugins.get(plugin_name)
            if not plugin:
                return None

            return {
                "name": plugin.plugin_name,
                "version": getattr(plugin, "version", "unknown"),
                "uuid": plugin.plugin_uuid,
                "enabled": plugin.enabled,
                "remote": getattr(plugin, "remote", False),
                "description": getattr(plugin, "description", "No description"),
                "arguments": getattr(plugin, "arguments", None),
            }

    @async_log_errors
    async def get_plugin_endpoints(
        self, plugin_name: str
    ) -> Optional[List[Dict[str, Any]]]:
        """Get all endpoints for a plugin."""
        async with self.plugin_lock:
            plugin = self.plugins.get(plugin_name)
            if not plugin:
                return None

            endpoints = getattr(plugin, "endpoints", {})
            if not isinstance(endpoints, dict):
                return []

            return [
                {
                    "access_name": ep_key,
                    "internal_name": ep.get("internal_name", ep_key),
                    "remote": ep.get("remote", False),
                    "accessible_by_other_plugins": ep.get(
                        "accessible_by_other_plugins", False
                    ),
                    "description": ep.get("description", ""),
                    "tags": ep.get("tags", []),
                }
                for ep_key, ep in endpoints.items()
                if isinstance(ep, dict)
            ]

    @async_log_errors
    async def list_plugins_state(self) -> List[Dict[str, Any]]:
        """Return list of all loaded plugins with name, enabled, and description."""
        async with self.plugin_lock:
            return [
                {
                    "name": p.plugin_name,
                    "enabled": p.enabled,
                    "description": getattr(p, "description", "No description"),
                }
                for p in self.plugins.values()
            ]

    @async_log_errors
    async def graceful_shutdown(self):
        """Gracefully shutdown the system by closing Plexus."""
        self._logger.info("Initiating graceful shutdown...")
        await self.close()
        # Note: Stopping the event loop should be handled by the main application

    # ── Stage O lock helpers ─────────────────────────────────────────
    # Strict lock-acquisition order (deadlock-prevention rule):
    #   1. lifecycle_lock(plugin_name) — per-plugin, returned by
    #      _get_lifecycle_lock. Held across user on_enable / on_disable
    #      so concurrent ops on the SAME plugin serialize, but ops on
    #      DIFFERENT plugins do not (B-046 fix).
    #   2. request_lock — global. May be nested INSIDE lifecycle_lock
    #      (pop_plugin / _reload_plugin do this to fail pending requests
    #      atomically with the lifecycle transition); MUST NOT be
    #      acquired while holding plugin_lock.
    #   3. plugin_lock — global. Held briefly for self.plugins /
    #      self.plugins_by_uuid dict reads/writes; MUST be released
    #      before any user callback runs.
    #   4. topic_registry._lock — internal to TopicRegistry; acquired
    #      inside subscribe / unsubscribe. Re-acquired by
    #      ``unsubscribe_plugin`` during bulk-pop on plugin teardown.
    #   5. _adverts_struct_lock — internal to NetworkManager; acquired
    #      by advertise_subs_remote / send_sub_delta_remote / advert-
    #      ack and timeout scans / _drop_peer_advert_state. Always
    #      acquired AFTER topic_registry._lock when both are needed
    #      (the broadcast hooks in Plexus subscribe/unsubscribe paths
    #      release topic_registry._lock before reaching the NM).
    #   6. _advert_locks[peer_hostname] — per-peer (per
    #      NetworkManager); wraps the FULL outbound advert lifecycle
    #      (build + send) so snapshot vs delta serialise per peer.
    #      Always acquired INSIDE _adverts_struct_lock when both are
    #      held simultaneously (the snapshot path does this).
    #   7. connection_pool entry-lock (implicit via asyncio.Queue
    #      single-owner ownership). The pool is keyed by (IP, port);
    #      checkout-then-use-then-return is the serialised primitive.
    #
    # Network I/O note: _register_yaml_subscriptions returns the list of
    # newly-registered sub_uuids without broadcasting them; broadcast
    # happens AFTER plugin_lock is released (avoiding network I/O while
    # holding the global dict lock). Same for unregister: broadcast
    # remove-deltas happen outside plugin_lock too.
    def _get_lifecycle_lock(self, plugin_name: str) -> asyncio.Lock:
        """Return the per-plugin lifecycle lock, creating it on demand.

        Locks are leaked across the process lifetime — bounded by the
        number of distinct plugin names ever loaded. Lock entries are
        not removed on pop_plugin so a concurrent waiter on a
        popped-and-reloaded plugin keeps lock identity (so a sequence
        like: enable starts -> caller wants to pop -> reload re-creates
        -> caller still serializes against reload's enable).
        """
        lock = self._lifecycle_locks.get(plugin_name)
        if lock is None:
            lock = asyncio.Lock()
            self._lifecycle_locks[plugin_name] = lock
        return lock

    async def _wait_for_plugin_ready(self, plugin: Plugin) -> None:
        """Stage O readiness gate: wait for both readiness events.

        Waits for plugin._lifecycle_ready (framework-controlled, set
        after on_enable returns) and plugin.ready (author-controlled).
        Honors the configured timeout (`general.plugin_ready_timeout`)
        and emits a slow-wait WARNING when the wait took more than 1s
        so legitimate-but-slow startups are visible in logs.

        Raises asyncio.TimeoutError on expiry.

        R1 HIGH-1 fix: wait on BOTH events under a single
        asyncio.wait_for budget. The previous split-timeout pattern
        (wait on _lifecycle_ready, then on ready with `remaining`) hit
        a zero-budget bug — when _lifecycle_ready consumed the entire
        timeout, `remaining=0.0` and asyncio.wait_for(coro, timeout=0.0)
        raises TimeoutError immediately even when plugin.ready was
        already set.
        """
        timeout = getattr(self, "plugin_ready_timeout", DEFAULT_PLUGIN_READY_TIMEOUT)
        loop = self.main_event_loop or asyncio.get_running_loop()
        start = loop.time()

        async def _both():
            await plugin._lifecycle_ready.wait()
            await plugin.ready.wait()

        await asyncio.wait_for(_both(), timeout=timeout)
        elapsed = loop.time() - start
        if elapsed > 1.0:
            self._logger.warning(
                "[STAGE_O] readiness gate waited %.2fs for plugin %s",
                elapsed,
                plugin.plugin_name,
            )

    # ── Stage O locked-body helpers ──────────────────────────────────
    # The "_under_lock" suffix means: caller MUST already hold
    # self._get_lifecycle_lock(plugin_name). These bodies are reused by
    # pop_plugin / _reload_plugin without recursive lock acquisition.
    async def _enable_plugin_under_lock(self, plugin_name: str) -> None:
        """Body of enable_plugin minus the lifecycle_lock acquisition.

        Stage O: plugin_lock is held only for the dict read + state
        transition + YAML sub registration (microseconds). It is RELEASED
        before the user on_enable callback runs so concurrent ops on
        OTHER plugins (which acquire plugin_lock briefly themselves) are
        not blocked. _lifecycle_ready is set after on_enable returns.

        Session 3 (v0.26.0): the INACTIVE → ENABLING transition happens
        UNDER plugin_lock so concurrent observers see the consistent
        state. ENABLING → ENABLED happens after on_enable succeeds.
        ENABLING → INACTIVE happens in the rollback path. last_errors
        [Phase.ENABLE] is populated on Exception (not CancelledError).

        PR3 Stage B (Q23 + C15): YAML subs register BEFORE on_enable so
        the plugin starts with subs already live; events arriving during
        on_enable are dispatched to handlers (which exist by definition
        — methods on the plugin class). The Stage O readiness gate then
        blocks fan-out to a still-not-ready handler.
        """
        async with self.plugin_lock:
            plugin = self.plugins.get(plugin_name)
            ps = self.plugin_states.get(plugin_name)
            # Skip non-INACTIVE plugins. Cycle 1 review:
            # ENABLING included so a defensive re-entry (any caller that
            # somehow bypasses the lifecycle_lock serialisation) cannot
            # double-register YAML subs. R2-BB-6: broadened from
            # (ENABLING, ENABLED) to "!= INACTIVE" so FAILED_LOAD and
            # UNLOADED entries also short-circuit here; INACTIVE is the
            # only legitimate enable starting state.
            if (
                plugin is None
                or ps is None
                or ps.state != State.INACTIVE
            ):
                return
            # Register YAML subs FIRST. Disabled subs (Q13 `enabled:
            # false`) ARE registered, but with the Subscription.enabled=
            # False flag so find_all (and _find_first) skip them. Broadcast of
            # add-deltas happens AFTER plugin_lock release (below) — see
            # the Network I/O note in the lock-ordering rule.
            new_sub_uuids = await self._register_yaml_subscriptions(plugin)
            # Transition INACTIVE → ENABLING per Q23 + Q11 so handlers
            # are callable for self-publish-from-on_enable. Rollback to
            # INACTIVE on raise. POSS-W-D1-002 / W-A1-001: state flip
            # MUST stay under plugin_lock so a concurrent re-entry
            # checking ps.state ∈ {ENABLING, ENABLED} cannot double-
            # register YAML subs (cycle 1 review invariant) — but the
            # observer emit is deferred to AFTER lock release so a
            # sync observer scheduling async work cannot deadlock on
            # plugin_lock.
            enable_state_change = self._set_plugin_state_no_emit(
                plugin_name, State.ENABLING
            )

        # plugin_lock RELEASED. lifecycle_lock still held. Emit the
        # deferred state-change now that observers can safely use
        # async APIs that acquire plugin_lock. The broadcast
        # loop and on_enable call run together under one cancellation-
        # aware try/except/finally so a CancelledError mid-flight (which
        # is a BaseException, NOT Exception, so a plain `except Exception:`
        # would skip cleanup) still triggers full rollback.
        self._emit_plugin_state_change(plugin_name, *enable_state_change)
        ok = False
        try:
            # Broadcast add-deltas to peers OUTSIDE plugin_lock so a
            # slow/multi-peer broadcast doesn't block other dict ops
            # cluster-wide. _broadcast_yaml_sub_added is a no-op when
            # networking is disabled / not ready.
            for sub_uuid in new_sub_uuids:
                await self._broadcast_yaml_sub_added(sub_uuid)

            # C-017: wrap user on_enable in asyncio.wait_for with a
            # configurable timeout (plugin_enable_timeout, default 30s)
            # so a misbehaving handler cannot pin lifecycle_lock
            # indefinitely. Mirrors the disable-side pattern at
            # _disable_plugin_under_lock. On TimeoutError the BaseException
            # branch below records the failure and rollback runs as if
            # on_enable had raised. Sync caveat: wait_for cancels the
            # awaitable but cannot interrupt a thread already blocked in
            # the user's synchronous callback — the worker thread keeps
            # running until the user code naturally returns; lifecycle_lock
            # IS released so other lifecycle ops resume.
            on_enable_timeout = getattr(
                self, "plugin_enable_timeout", DEFAULT_PLUGIN_ENABLE_TIMEOUT
            )
            # Caller identity: lifecycle scope is exempt from charging. Stamp
            # an exempt caller frame so execute/publish calls the plugin makes
            # from inside on_enable inherit the exemption down the chain. The
            # _core/ + system-origin exemption is a charge-site read (Step 3),
            # not an identity push, so it is not handled here.
            _enable_ident = (
                CallerIdentity(plugin.plugin_name, plugin.plugin_uuid, exempt=True)
                if self._identity_active else None
            )
            _enable_active = _enable_ident is not None
            if asyncio.iscoroutinefunction(plugin.on_enable):
                with caller_chain_scope(_enable_ident, _enable_active):
                    if on_enable_timeout is not None:
                        await asyncio.wait_for(
                            plugin.on_enable(), timeout=on_enable_timeout
                        )
                    else:
                        await plugin.on_enable()
            else:
                # C-136: explicit None-check on main_event_loop so a
                # pre-wait_until_ready call surfaces a clear RuntimeError
                # instead of an opaque
                # ``AttributeError: 'NoneType' object has no attribute
                # 'run_in_executor'`` from inside the helper. Async
                # on_enable callbacks work fine without this guard
                # because they pick up the running loop implicitly via
                # ``await``; the sync branch is the one that needs the
                # stored loop reference to dispatch to the executor.
                if self.main_event_loop is None:
                    raise RuntimeError(
                        f"_enable_plugin_under_lock {plugin_name!r}: "
                        f"sync on_enable cannot dispatch — "
                        f"self.main_event_loop is None. "
                        f"wait_until_ready() must complete before "
                        f"enable_plugin can run a sync on_enable."
                    )
                executor_call = self.main_event_loop.run_in_executor(
                    self._plugin_executor,
                    self._seed_sync_hook(
                        plugin.on_enable,
                        seeded_sync_chain(_enable_active, _enable_ident),
                    ),
                )
                if on_enable_timeout is not None:
                    await asyncio.wait_for(executor_call, timeout=on_enable_timeout)
                else:
                    await executor_call
            # Stage O: signal lifecycle-ready AFTER on_enable returns
            # successfully. Other plugins blocked in the readiness gate
            # unblock here.
            # C-142: transition to ENABLED FIRST, then set the event.
            # If the set were first, observers woken by _lifecycle_ready
            # would see state=ENABLING (the transition hadn't fired
            # yet). Reordering closes that single-statement window.
            self._transition_plugin(plugin_name, State.ENABLED)
            plugin._lifecycle_ready.set()
            ok = True
        except BaseException as exc:
            # Session 3: capture on_enable failure for last_errors.
            # R2-BB-7: skip CancelledError (cancellation is not a
            # plugin error) AND TimeoutError (per-spec routine for a
            # hung on_enable, callers handle the timeout signal cleanly
            # via the raise below). Matches _disable_plugin_under_lock's
            # except block — symmetry restored.
            if not isinstance(exc, (asyncio.CancelledError, asyncio.TimeoutError)):
                self.plugin_states[plugin_name].last_errors[Phase.ENABLE] = ErrorRecord(
                    exception_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
                    exception_repr=repr(exc),
                    traceback=traceback.format_exc(),
                    ts=time.time(),
                )
            raise
        finally:
            if not ok:
                # Rollback runs on Exception, CancelledError, or any
                # other BaseException out of the try block above.
                #
                # Sync state updates first (event clear/set — atomic,
                # cannot raise) so they're guaranteed regardless of
                # what happens during async cleanup below.
                plugin._lifecycle_ready.clear()
                # R1 HIGH-2 fix: restore plugin.ready to its
                # default-set state. If the plugin author cleared
                # self.ready inside on_enable and then on_enable
                # raised / was cancelled, the cleared event would
                # otherwise persist on the same Plugin instance and
                # stall any subsequent enable / cross-plugin call
                # behind the gate until timeout. The author's next
                # on_enable can clear it again if they want manual
                # control.
                plugin.ready.set()
                # B-004 fix: call user on_disable to give the plugin
                # a chance to undo partial setup from the failed
                # on_enable (per README: "on_enable must be fully
                # undoable by on_disable"). Author must write
                # on_disable defensively against partial state
                # (e.g. `if self.db_pool: await self.db_pool.close()`).
                #
                # Nested try/finally chain mirrors the shape used by
                # _disable_plugin_under_lock so the `enabled = False`
                # flip is the LAST action and runs unconditionally —
                # even on CancelledError mid-await. Each async cleanup
                # is wrapped in try/except Exception so a non-fatal
                # raise doesn't skip the next step. CancelledError
                # propagates through both try blocks (Exception
                # doesn't catch it) but the outer finally chain still
                # runs, guaranteeing the flag flip.
                #
                # POSS-W-D2-010 fix: wrap rollback on_disable in the
                # same asyncio.wait_for timeout that the runtime
                # disable_plugin / _pop_plugin_under_lock paths use
                # (B-009 fix), so a misbehaving rollback on_disable
                # cannot pin lifecycle_lock indefinitely. Sync
                # on_disable caveat from _disable_plugin_under_lock
                # docstring applies here too: wait_for cancels the
                # awaitable but cannot interrupt a thread blocked
                # inside the user's synchronous callback running in
                # _plugin_executor.
                rollback_disable_timeout = getattr(
                    self,
                    "plugin_disable_timeout",
                    DEFAULT_PLUGIN_DISABLE_TIMEOUT,
                )
                # Caller identity: rollback on_disable is lifecycle scope
                # too -> exempt frame.
                _rb_ident = (
                    CallerIdentity(plugin.plugin_name, plugin.plugin_uuid, exempt=True)
                    if self._identity_active else None
                )
                _rb_active = _rb_ident is not None
                try:
                    try:
                        if asyncio.iscoroutinefunction(plugin.on_disable):
                            with caller_chain_scope(_rb_ident, _rb_active):
                                await asyncio.wait_for(
                                    plugin.on_disable(),
                                    timeout=rollback_disable_timeout,
                                )
                        else:
                            await asyncio.wait_for(
                                self.main_event_loop.run_in_executor(
                                    self._plugin_executor,
                                    self._seed_sync_hook(
                                        plugin.on_disable,
                                        seeded_sync_chain(_rb_active, _rb_ident),
                                    ),
                                ),
                                timeout=rollback_disable_timeout,
                            )
                    except asyncio.TimeoutError:
                        self._logger.warning(
                            "[STAGE_O] _enable_plugin_under_lock rollback: "
                            "on_disable exceeded %.1fs timeout for plugin %r "
                            "— continuing rollback (subs will still be "
                            "unregistered, state will transition to INACTIVE)",
                            rollback_disable_timeout,
                            plugin.plugin_name,
                        )
                    except Exception:
                        self._logger.exception(
                            "[STAGE_O] _enable_plugin_under_lock rollback: "
                            "on_disable raised for plugin %r — partial "
                            "cleanup incomplete (original on_enable error "
                            "still propagates)",
                            plugin.plugin_name,
                        )
                finally:
                    try:
                        try:
                            await self._unregister_plugin_subscriptions(plugin)
                        except Exception:
                            self._logger.exception(
                                "[STAGE_O] _enable_plugin_under_lock rollback: "
                                "_unregister_plugin_subscriptions raised for "
                                "plugin %r — partial cleanup incomplete",
                                plugin.plugin_name,
                            )
                        # W3-L3: mirror the disable path's observer cleanup
                        # so internal_observe registrations made during a
                        # partial on_enable don't leak as ghost observers
                        # firing against the rolled-back instance.
                        try:
                            self._unobserve_plugin(plugin.plugin_uuid)
                        except Exception:
                            self._logger.exception(
                                "[STAGE_O] _enable_plugin_under_lock rollback: "
                                "_unobserve_plugin raised for plugin %r",
                                plugin.plugin_name,
                            )
                    finally:
                        # Session 3: sync state transition (cannot raise),
                        # guaranteed to run via the outer finally chain
                        # even if both async cleanups above are cancelled.
                        self._transition_plugin(plugin_name, State.INACTIVE)

    async def _disable_plugin_under_lock(
        self,
        plugin_name: str,
        on_disable_timeout: Optional[float] = None,
    ) -> None:
        """Body of disable_plugin minus the lifecycle_lock acquisition.

        Stage O: clears _lifecycle_ready BEFORE on_disable so any
        in-flight gate wait against this plugin times out rather than
        dispatching to a tearing-down plugin. plugin_lock is held only
        for the dict reads + state transition; user on_disable runs
        without it held.

        Session 3 (v0.26.0): the ENABLED → DISABLING transition happens
        UNDER plugin_lock so observers see the consistent state. The
        DISABLING → INACTIVE transition happens in the finally block —
        unconditional regardless of whether on_disable raised, was
        cancelled, or timed out (per O3). last_errors[Phase.DISABLE]
        is populated on Exception (not CancelledError or TimeoutError —
        TimeoutError is per-spec routine).

        PR3 Stage B (C15): YAML + runtime subs are unregistered AFTER
        on_disable returns. User code can publish/receive events during
        shutdown teardown.

        Optional ``on_disable_timeout`` wraps the user on_disable
        callback in ``asyncio.wait_for``. On expiry, raises
        ``asyncio.TimeoutError``; the finally block still runs the
        unregister + state transition, so callers that catch the
        TimeoutError can safely treat the plugin as INACTIVE. Callers
        who do NOT want a timeout pass None.

        Sync ``on_disable`` caveat: ``wait_for`` cancels the awaitable
        but cannot interrupt a thread blocked inside the user's
        synchronous callback running in ``_plugin_executor``. The
        event loop unblocks on time and the framework's bookkeeping
        (subs, state, dict pop) all complete; the worker thread keeps
        running until the user code naturally returns and may hold
        thread-pool capacity / external resources until then.

        Callers and their timeout values:
          - ``close()``                → 30.0 (hardcoded shutdown cap)
          - ``disable_plugin``         → ``plugin_disable_timeout`` (B-009 fix)
          - ``_pop_plugin_under_lock`` → ``plugin_disable_timeout`` (B-009 fix)

        ``_enable_plugin_under_lock``'s rollback-on-failure path calls
        ``plugin.on_disable()`` directly (not via this helper) but is
        now wrapped in the same ``asyncio.wait_for`` timeout via
        ``plugin_disable_timeout`` so a misbehaving rollback on_disable
        cannot pin ``lifecycle_lock``. See the rollback site comment.
        """
        async with self.plugin_lock:
            plugin = self.plugins.get(plugin_name)
            ps = self.plugin_states.get(plugin_name)
            if plugin is None or ps is None:
                return
            # C-137: explicit handling of non-ENABLED states. Previously
            # silent no-op for everything other than ENABLED — operators
            # had no way to tell whether disable_plugin was rejected
            # because the plugin was ENABLING (race), DISABLING (already
            # being disabled), INACTIVE (already off), FAILED_LOAD
            # (never loaded), or UNLOADED. Now logs at DEBUG/WARNING
            # with the actual state so the caller can interpret the
            # no-op. The function still returns silently — the public
            # API contract is "disable returns when the plugin is not
            # ENABLED" and changing that to raise would break callers
            # that depend on the idempotent shape.
            if ps.state != State.ENABLED:
                if ps.state == State.ENABLING:
                    # ENABLING — there's a concurrent enable in flight.
                    # Disabling a plugin mid-enable is undefined per
                    # the state-machine docs; we treat it as a no-op
                    # but operators should see the race at WARNING.
                    self._logger.warning(
                        "[DISABLE] plugin %r is in state ENABLING (race "
                        "with a concurrent enable_plugin); no-op. If the "
                        "caller wanted to abort an in-flight enable, that "
                        "is not supported — wait for the enable to finish, "
                        "then disable.",
                        plugin_name,
                    )
                else:
                    # INACTIVE / DISABLING / UNLOADED / FAILED_LOAD —
                    # expected idempotent paths, log at DEBUG.
                    self._logger.debug(
                        "[DISABLE] plugin %r is in state %s; no-op (not ENABLED).",
                        plugin_name, ps.state.value,
                    )
                return
            # Session 3: transition ENABLED → DISABLING under plugin_lock
            # so any concurrent enable check sees DISABLING (not ENABLED)
            # and bails. Flip happens before plugin_lock release.
            # POSS-W-D1-002 / W-A1-001: state mutation stays under-lock
            # for the race-protection invariant above; observer emit is
            # deferred to AFTER lock release so a sync observer
            # scheduling async work cannot deadlock on plugin_lock.
            disable_state_change = self._set_plugin_state_no_emit(
                plugin_name, State.DISABLING
            )

        # plugin_lock RELEASED. Emit the deferred state-change now
        # that observers can safely use async APIs.
        self._emit_plugin_state_change(plugin_name, *disable_state_change)
        # Stage O: clear lifecycle-ready BEFORE on_disable so any
        # in-flight gate wait either re-fires against the cleared event
        # (and times out) rather than dispatching to a tearing-down
        # plugin.
        plugin._lifecycle_ready.clear()

        # plugin_lock RELEASED — run on_disable without holding it.
        # Outer try/except/finally guarantees the cleanup runs on any
        # exit path including CancelledError. Cleanup is itself nested
        # in try/finally so the state transition is the LAST action and
        # is unconditional — _transition_plugin is sync and cannot be
        # interrupted by cancellation. Without this nesting, a
        # cancellation hitting during _unregister_plugin_subscriptions
        # would skip the transition and leave the plugin in a stuck
        # DISABLING state.
        # Caller identity: on_disable is lifecycle scope -> exempt frame,
        # same as on_enable.
        _disable_ident = (
            CallerIdentity(plugin.plugin_name, plugin.plugin_uuid, exempt=True)
            if self._identity_active else None
        )
        _disable_active = _disable_ident is not None
        try:
            if asyncio.iscoroutinefunction(plugin.on_disable):
                with caller_chain_scope(_disable_ident, _disable_active):
                    if on_disable_timeout is not None:
                        await asyncio.wait_for(
                            plugin.on_disable(), timeout=on_disable_timeout
                        )
                    else:
                        await plugin.on_disable()
            else:
                executor_call = self.main_event_loop.run_in_executor(
                    self._plugin_executor,
                    self._seed_sync_hook(
                        plugin.on_disable,
                        seeded_sync_chain(_disable_active, _disable_ident),
                    ),
                )
                if on_disable_timeout is not None:
                    await asyncio.wait_for(executor_call, timeout=on_disable_timeout)
                else:
                    await executor_call
        except BaseException as exc:
            # Session 3: capture on_disable failure for last_errors. Skip
            # CancelledError (cancellation is not a plugin error) and
            # TimeoutError (per-spec routine, callers handle it cleanly).
            # R2-BB-7: matches _enable_plugin_under_lock — parity restored.
            if not isinstance(exc, (asyncio.CancelledError, asyncio.TimeoutError)):
                self.plugin_states[plugin_name].last_errors[Phase.DISABLE] = (
                    ErrorRecord(
                        exception_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
                        exception_repr=repr(exc),
                        traceback=traceback.format_exc(),
                        ts=time.time(),
                    )
                )
            raise
        finally:
            # Unregister all subs (YAML + runtime) AND clear internal-bus
            # observers registered by this plugin via internal_observe,
            # regardless of whether on_disable raised, was cancelled, or
            # timed out. Symmetric with rollback in
            # _enable_plugin_under_lock. Without the observer cleanup
            # here, declarative subs would be auto-cleared on disable
            # but bound-method observers would persist — a re-enable
            # cycle that re-registers observers in on_enable would
            # accumulate duplicate callbacks across each disable→enable
            # cycle. The pop path still calls _unobserve_plugin
            # defensively (idempotent — owners-set is already empty
            # after disable ran).
            try:
                try:
                    await self._unregister_plugin_subscriptions(plugin)
                except Exception:
                    # B-050 fix: don't let an unregister failure mask
                    # the original on_disable exception. Without this
                    # except, a TimeoutError from on_disable's wait_for
                    # would be replaced by whatever
                    # _unregister_plugin_subscriptions raised, and any
                    # caller's `except asyncio.TimeoutError` would miss
                    # it. Mirrors the pattern in
                    # _enable_plugin_under_lock rollback.
                    self._logger.exception(
                        "_disable_plugin_under_lock: "
                        "_unregister_plugin_subscriptions raised for "
                        "plugin %r — original on_disable exception (if "
                        "any) still propagates; best-effort cleanup "
                        "incomplete",
                        plugin.plugin_name,
                    )
                # Mirror the sub-cleanup with observer-cleanup so
                # internal_observe registrations don't survive a
                # disable→enable cycle as duplicates. Wrapped in its
                # own try so a failure here can't mask either the
                # original on_disable exception or the unregister-subs
                # exception above.
                try:
                    # C-153: direct read; Plugin.__init__ guarantees
                    # plugin_uuid is set.
                    plugin_uuid = plugin.plugin_uuid
                    if plugin_uuid:
                        # W3-L1: disable cleans observers but uses the
                        # default (no quarantine). Same instance + uuid
                        # is reused on re-enable.
                        self._unobserve_plugin(plugin_uuid)
                except Exception:
                    self._logger.exception(
                        "_disable_plugin_under_lock: "
                        "_unobserve_plugin raised for plugin %r — "
                        "best-effort cleanup incomplete",
                        plugin.plugin_name,
                    )
            finally:
                # Session 3: sync state transition (cannot raise),
                # guaranteed to run even if the unregister await above
                # is cancelled. plugin_lock is not needed here: any
                # find_endpoint reader that briefly sees DISABLING
                # before this line is already covered by the
                # _lifecycle_ready.clear() at the top (gate blocks).
                self._transition_plugin(plugin_name, State.INACTIVE)

    async def _pop_plugin_under_lock(self, plugin_name: str) -> bool:
        """Body of pop_plugin minus the lifecycle_lock acquisition.

        Caller MUST already hold ``self._get_lifecycle_lock(plugin_name)``.
        Returns True if a plugin was popped, False if absent (or popped
        by a concurrent caller between the caller's lock acquisition and
        the dict mutation below — defensive).

        Stage O: shared by ``pop_plugin`` and ``_reload_plugin`` so the
        pop body is not duplicated. Both callers already hold the
        per-plugin lifecycle_lock; this helper does not re-acquire it.
        Lock-ordering: request_lock (nested inside lifecycle_lock per
        the rule at ``_get_lifecycle_lock``) -> _disable_plugin_under_lock
        (briefly takes plugin_lock) -> plugin_lock for the final dict pop.
        """
        if plugin_name not in self.plugins:
            return False

        # B-073 (Session 2 Step 2 prep): snapshot under the lock,
        # iterate outside. Producer-side finally pops in
        # ``_process_request*`` mutate ``self.requests`` lock-free
        # (Python dict ``pop`` is GIL-atomic). Iterating directly
        # under the lock would risk ``RuntimeError: dictionary changed
        # size during iteration`` if a producer completes mid-await.
        # Snapshot copies references; already-popped entries' futures
        # short-circuit via the ``not done()`` check below.
        #
        # C-064: do an INITIAL snapshot-then-set_result pass, then a
        # FINAL pass with request_lock held for the entire iteration,
        # so any new request created between the first snapshot
        # release and the plugin pop is also caught. set_result's
        # internal ``if not self._future.done()`` guard makes the
        # double-call on the second pass a no-op for any request
        # already resolved by the first pass.
        async with self.request_lock:
            snapshot = list(self.requests.values())
        # R2-AA-5: the set_result loop awaits inside it, so a cancel
        # between snapshot release and a particular set_result call
        # would leave later snapshot entries with futures permanently
        # unresolved (their consumers hang). Wrap in try/finally so on
        # any exit path (including CancelledError) every snapshot entry
        # that targets the popped plugin and is still pending gets its
        # future resolved synchronously via Future.cancel(). Cancel
        # raises asyncio.CancelledError in the consumer's await — a
        # legitimate signal that the plugin went away.
        try:
            for req in snapshot:
                if req.target_plugin == plugin_name and not req._future.done():
                    await req.set_result(
                        f"Plugin {plugin_name} was unloaded while request was pending",
                        error=True,
                    )
        finally:
            for req in snapshot:
                if req.target_plugin == plugin_name and not req._future.done():
                    req._future.cancel()

        # W1-B2: ENABLING and DISABLING are transient under-lock states.
        # ``pop_plugin`` (and ``_reload_plugin``) both acquire the
        # per-plugin ``lifecycle_lock`` before calling
        # ``_pop_plugin_under_lock``; the same lock serializes
        # ``enable_plugin`` / ``disable_plugin`` / ``_enable_plugin_under_lock``
        # / ``_disable_plugin_under_lock``. By the time control reaches
        # this branch the in-flight transition has finished and
        # ``ps_check.state`` is a final value (ENABLED, INACTIVE,
        # FAILED_LOAD, or UNLOADED) — never ENABLING or DISABLING. The
        # narrow ``== State.ENABLED`` guard is correct: we only need to
        # tear down enabled plugins; the other final states are
        # already in their stable form.
        ps_check = self.plugin_states.get(plugin_name)
        if (
            plugin_name in self.plugins
            and ps_check is not None
            and ps_check.state == State.ENABLED
        ):
            # B-009 fix: wrap user on_disable in asyncio.wait_for via
            # the configured runtime timeout (default 30s) so a hanging
            # on_disable can't block this plugin's lifecycle_lock
            # indefinitely. Symmetric with close()'s 30s cap.
            disable_timeout = getattr(
                self,
                "plugin_disable_timeout",
                DEFAULT_PLUGIN_DISABLE_TIMEOUT,
            )
            try:
                await self._disable_plugin_under_lock(
                    plugin_name, on_disable_timeout=disable_timeout
                )
            except asyncio.TimeoutError:
                # B-009: on_disable exceeded the runtime timeout. The
                # under-lock body's finally already transitioned to
                # INACTIVE and unregistered subs, so it's safe to
                # proceed with the dict pop below. Without this catch
                # the TimeoutError propagates up and leaves the plugin
                # half-removed (still in self.plugins / plugins_by_uuid,
                # topics + logger-level entries never cleaned).
                self._logger.warning(
                    "pop_plugin %r: on_disable exceeded %.1fs timeout; "
                    "continuing with pop (subs already unregistered, "
                    "state already INACTIVE)",
                    plugin_name,
                    disable_timeout,
                )

        async with self.plugin_lock:
            plugin = self.plugins.pop(plugin_name, None)
            if plugin is None:
                return False
            # C-153: Plugin.__init__ guarantees plugin_uuid.
            plugin_uuid = plugin.plugin_uuid
            if plugin_uuid and plugin_uuid in self.plugins_by_uuid:
                self.plugins_by_uuid.pop(plugin_uuid, None)

        # C-064 final sweep: with the plugin now popped from
        # self.plugins, any new request that slipped in between the
        # initial snapshot and now must also be resolved. Snapshot
        # under request_lock (so no concurrent create_request can
        # insert mid-snapshot), then release the lock and iterate
        # set_result OUTSIDE the lock. The set_result call is async:
        # Request.set_result is non-blocking, but
        # GeneratorRequest.set_result ends in ``await
        # self.queue.put(...)`` which yields to the loop. Holding
        # request_lock across that yield would stall every concurrent
        # create_request / create_gen_request caller for the full
        # queue-put latency of every matching GeneratorRequest. Mirror
        # the initial-sweep pattern (snapshot in lock, dispatch
        # outside) and rely on the future.done() guard inside
        # set_result for idempotency against double-resolve.
        async with self.request_lock:
            final_sweep_snapshot = [
                r for r in self.requests.values()
                if r.target_plugin == plugin_name and not r._future.done()
            ]
        for req in final_sweep_snapshot:
            if not req._future.done():
                await req.set_result(
                    f"Plugin {plugin_name} was unloaded while "
                    f"request was pending",
                    error=True,
                )

        async with self.plugin_lock:
            # Symmetric cleanup with the late-stash in
            # load_plugin_with_conf so popped plugins don't leave
            # ghost entries in self._plugin_deps that would mislead
            # _resolve_dependencies on a subsequent boot path.
            self._plugin_deps.pop(plugin_name, None)
            if plugin_uuid:
                await self.topic_registry.unsubscribe_plugin(plugin_uuid)
                # B-073: bulk-unobserve every internal-event-bus observer
                # this plugin registered. Mirrors the topic-sub cleanup
                # above so observer state can't outlive the Plugin
                # instance (memory leak) AND post-pop emits don't
                # dispatch to a torn-down plugin's bound methods.
                # Idempotent — _disable_plugin_under_lock already
                # cleared the owners-set in its finally block; this
                # re-call covers the edge where a pop happens against
                # an INACTIVE plugin that never ran enable→disable
                # (no observers registered) or where a future caller
                # bypasses the disable path.
                # W3-L1: pop path quarantines the uuid — the instance
                # is gone for good. Any cancelled-but-still-running
                # async task that fires ``internal_observe(uuid, ...)``
                # past this point MUST be rejected.
                self._unobserve_plugin(plugin_uuid, quarantine=True)
                LogUtil.clear_logger_levels_owned_by(plugin_name, plugin_uuid)
        # Multi-file plugin loader cleanup (2026-05-27): undo the sys.path +
        # sys.modules additions that load_plugin_with_conf made for this plugin.
        # Without this, hot-reload would re-bind to stale module objects via
        # Python's import cache (sys.modules) and operators would observe
        # newly-loaded code mysteriously executing OLD logic. Done outside
        # the plugin_lock above because sys-module mutation is unrelated to
        # the plugin_dict / topic / observer / logger cleanup that needs the
        # lock. Defensive getattr for tests that bypass __init__ via
        # object.__new__(Plexus) and never populate _plugin_loader_cleanup.
        cleanup = getattr(self, "_plugin_loader_cleanup", {}).pop(plugin_name, None)
        if cleanup is not None:
            for _mod_name in cleanup["sys_modules_added"]:
                sys.modules.pop(_mod_name, None)
            _path_entry = cleanup["sys_path_added"]
            if _path_entry:
                try:
                    sys.path.remove(_path_entry)
                except ValueError:
                    pass  # already removed by something else (defensive)

        # Rate limiter (Step 3): with the plugin removed from self.plugins, a
        # rebuild drops its now-orphan static + Sub-IN buckets and keeps the
        # active master switch honest. Idempotent + no-op when off. (A reload
        # rebuilds again after re-loading; the double rebuild is harmless.)
        if self._rate_limits_active:
            await self._rebuild_charge_sets()

        return True

    @async_log_errors
    async def enable_plugin(self, plugin_name: str):
        """Public-facing enable that acquires the per-plugin
        lifecycle_lock (Stage O) and delegates to
        _enable_plugin_under_lock. Concurrent enable on the SAME plugin
        serializes here; concurrent ops on OTHER plugins do not block.

        Session 3 (v0.26.0): renamed from `_enable_plugin` to public
        `enable_plugin`. State machine transitions are emitted via
        _transition_plugin under plugin_lock.

        C-149: decorator is now ``@async_log_errors`` to mirror
        ``disable_plugin``. Previously ``@async_handle_errors(None)``
        silently swallowed exceptions and returned None — callers had no
        way to detect enable failure. Symmetric error propagation
        across enable/disable lets callers react consistently.
        """
        lifecycle_lock = self._get_lifecycle_lock(plugin_name)
        async with lifecycle_lock:
            await self._enable_plugin_under_lock(plugin_name)

    @async_log_errors
    async def disable_plugin(self, plugin_name: str):
        """Public-facing disable that acquires the per-plugin
        lifecycle_lock (Stage O) and delegates to
        _disable_plugin_under_lock. Waits for any in-progress
        enable_plugin on the same name to complete first.

        Session 3 (v0.26.0): renamed from `_disable_plugin` to public
        `disable_plugin`. State machine transitions are emitted via
        _transition_plugin.

        B-009 fix: user on_disable wrapped in asyncio.wait_for via
        on_disable_timeout — symmetric with close()'s 30s cap.
        Configurable via general.plugin_disable_timeout. On timeout
        the under-lock body's finally still unregisters subs and
        transitions to INACTIVE; this wrapper logs and returns cleanly
        rather than propagating asyncio.TimeoutError to callers
        (parity with close()'s per-plugin TimeoutError catch).
        """
        disable_timeout = getattr(
            self, "plugin_disable_timeout", DEFAULT_PLUGIN_DISABLE_TIMEOUT
        )
        lifecycle_lock = self._get_lifecycle_lock(plugin_name)
        async with lifecycle_lock:
            try:
                await self._disable_plugin_under_lock(
                    plugin_name, on_disable_timeout=disable_timeout
                )
            except asyncio.TimeoutError:
                self._logger.warning(
                    "disable_plugin %r: on_disable exceeded %.1fs timeout",
                    plugin_name,
                    disable_timeout,
                )

    # C-020: explicit transition validity matrix. Maps each State to the
    # set of States it is allowed to transition to. Same-state hops are
    # always permitted (idempotent no-ops); other transitions log a
    # WARNING and proceed (non-fatal — operators see drift but framework
    # does not break). Raising would risk leaving callers in inconsistent
    # state half-way through a multi-step sequence (e.g. _pop_plugin),
    # so the conservative choice is log-and-allow.
    _VALID_TRANSITIONS: Dict[State, frozenset] = {
        # Initial -> first state happens in _set_plugin_state_no_emit's
        # caller chain; the matrix is consulted only when old_state is
        # already populated. UNLOADED is the typical fresh-load state.
        State.UNLOADED: frozenset({State.INACTIVE, State.FAILED_LOAD}),
        State.INACTIVE: frozenset(
            {
                State.ENABLING,
                State.UNLOADED,
                # Rare: a reload after FAILED_LOAD can re-enter INACTIVE,
                # but we model that as UNLOADED -> INACTIVE; INACTIVE ->
                # FAILED_LOAD also possible if on_load raises after a
                # prior successful load (re-init).
                State.FAILED_LOAD,
            }
        ),
        State.ENABLING: frozenset(
            {
                State.ENABLED,
                # Rollback after on_enable raise / timeout.
                State.INACTIVE,
            }
        ),
        State.ENABLED: frozenset({State.DISABLING}),
        State.DISABLING: frozenset({State.INACTIVE}),
        State.FAILED_LOAD: frozenset(
            {
                # Recovery: pop_plugin transitions FAILED_LOAD -> UNLOADED
                # (or directly removes the entry). A successful reload
                # then goes UNLOADED -> INACTIVE via load_plugin_with_conf.
                State.UNLOADED,
            }
        ),
    }

    def _validate_transition(
        self, name: str, old_state: State, new_state: State
    ) -> None:
        """C-020 helper: WARN if (old_state -> new_state) is not in the
        validity matrix. Same-state (idempotent no-op) is always allowed.
        Does NOT raise — see _VALID_TRANSITIONS docstring for the
        log-and-allow rationale.
        """
        if old_state == new_state:
            return
        allowed = self._VALID_TRANSITIONS.get(old_state, frozenset())
        if new_state not in allowed:
            self._logger.warning(
                "[STATE] plugin=%r: invalid transition %s -> %s "
                "(allowed from %s: %s). Proceeding anyway; investigate "
                "the call site as this may indicate a logic bug.",
                name,
                old_state.value,
                new_state.value,
                old_state.value,
                sorted(s.value for s in allowed),
            )

    def _transition_plugin(self, name: str, new_state: State) -> None:
        """Atomic state transition + _core/plugin/state_changed emit.

        Session 3 (v0.26.0). All state mutations on PluginState go through
        this method (D2). Direct field writes on PluginState are forbidden
        — code review enforces.

        Sync method (no await) so callers under existing locks can
        transition without re-acquiring. Observer dispatch in
        _internal_emit is sync per E2'. Sync observers must NOT acquire
        plugin_lock / lifecycle_lock / request_lock — see api_reference.md
        observer contract.

        POSS-W-D1-002 / D1-006: call sites that already hold
        ``plugin_lock`` should use ``_set_plugin_state_no_emit`` +
        ``_emit_plugin_state_change`` to separate the mutation (which
        must be under-lock for race protection) from the emit (which
        must NOT be under-lock so observers cannot self-deadlock).

        C-020: validates the transition against ``_VALID_TRANSITIONS``
        and logs a WARNING for invalid hops (no raise — see helper
        docstring).
        """
        old_state, _, ts = self._set_plugin_state_no_emit(name, new_state)
        self._emit_plugin_state_change(name, old_state, new_state, ts)

    def _set_plugin_state_no_emit(
        self, name: str, new_state: State
    ) -> Tuple[State, State, float]:
        """Mutate PluginState.state without firing the observer emit.

        Returns ``(old_state, new_state, ts)``. Callers under
        ``plugin_lock`` use this to keep the state flip atomic with
        their lock-protected work, then call
        ``_emit_plugin_state_change`` AFTER releasing the lock — so
        observers that schedule async work cannot deadlock on a lock
        still held by the transition path.

        C-020: validates the transition before applying.

        R2-BB-8: bracket-lookup replaced with .get() + early-return so
        a TOCTOU race (a concurrent pop between caller's existence
        check and this method's lookup) no longer raises KeyError.
        Several callers (cascade, pop, load, reload) do not hold
        plugin_lock at the call site, so this is the safer default.
        Returns a sentinel (old=new=UNLOADED, ts=now) so unpacking
        callers don't crash; the no-op transition's emit (which uses
        old==new) is harmless on the internal bus.
        """
        ps = self.plugin_states.get(name)
        if ps is None:
            self._logger.warning(
                "_set_plugin_state_no_emit: plugin %r missing from "
                "plugin_states; treating as no-op (concurrent pop?)",
                name,
            )
            now = time.time()
            return State.UNLOADED, State.UNLOADED, now
        old_state = ps.state
        self._validate_transition(name, old_state, new_state)
        ps.state = new_state
        ps.last_state_change = time.time()
        return old_state, new_state, ps.last_state_change

    def _emit_plugin_state_change(
        self, name: str, old_state: State, new_state: State, ts: float
    ) -> None:
        """Companion to ``_set_plugin_state_no_emit``. Fires the
        ``_core/plugin/state_changed`` internal-bus event for callers
        that deferred the emit until after their lock release.
        """
        self._internal_emit(
            "_core/plugin/state_changed",
            name=name,
            from_state=old_state.value,
            to_state=new_state.value,
            ts=ts,
        )

    @async_log_errors
    async def get_unloaded_metadata(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Return metadata for an UNLOADED plugin by reading its on-disk
        plugin_config.yml.

        Returns None if the plugin is not in plugin_states or its state
        is not UNLOADED. For ENABLED / INACTIVE / etc., callers should
        use get_plugin_info(plugin_name) which reads from the live
        instance.

        Session 3 (v0.26.0): supports TUI listing of disabled-in-config
        plugins (per B1 design decision).
        """
        ps = self.plugin_states.get(plugin_name)
        if ps is None or ps.state != State.UNLOADED:
            return None
        entry = next(
            (
                p
                for p in self.yaml_config.get("plugins", [])
                if p.get("name") == plugin_name
            ),
            None,
        )
        if not entry:
            return None
        path = entry.get("path") or os.path.join(self.plugin_package, plugin_name)
        path = os.path.abspath(path)
        try:
            with open(
                os.path.join(path, "plugin_config.yml"),
                "r",
                encoding="utf-8",
            ) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            return None
        return {
            "name": plugin_name,
            "version": cfg.get("version", "unknown"),
            "description": cfg.get("description", ""),
            "path": path,
            "declared_endpoints": list((cfg.get("endpoints") or {}).keys()),
            "declared_events": list((cfg.get("events") or {}).keys()),
            "declared_subscriptions": list((cfg.get("subscriptions") or {}).keys()),
        }

    async def _broadcast_yaml_sub_added(self, sub_uuid: str) -> None:
        """Helper used by YAML-registration sites to push add-delta to
        peers. Wraps the get_subscription + ready-flag check in one place
        so the YAML loop stays clean."""
        # Snapshot nm. Per Commit 2b cycle 2 MED-B: a mid-block
        # hot-reload could otherwise leak the broadcast call onto a
        # stopped NM. Single-call site so the practical race window is
        # tiny, but snapshotting matches the pattern used by the loop
        # sites (publish_event / request_event / etc.) for consistency.
        nm = self.network
        if not (
            getattr(self, "networking_enabled", False)
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            return
        sub = await self.topic_registry.get_subscription(sub_uuid)
        if sub is None:
            return
        try:
            await nm.broadcast_local_sub_added(sub)
        except Exception:
            self._logger.debug(
                "_broadcast_yaml_sub_added: broadcast failed", exc_info=True
            )

    async def _unregister_plugin_subscriptions(self, plugin: Plugin) -> None:
        """Unregister every sub (YAML + runtime) for ``plugin`` at
        on_disable end (C15). Uses unsubscribe_plugin which removes by
        plugin_uuid (covers BOTH YAML subs registered via the wrapper
        AND runtime subs registered via Plugin.subscribe — both share
        plugin_uuid). plugin._sub_uuids is cleared as a side-effect.
        """
        # C-153: Plugin.__init__ guarantees plugin_uuid.
        plugin_uuid = plugin.plugin_uuid
        if plugin_uuid:
            # PR3 Stage C remove-delta loop (locked #18 item 5). Snapshot
            # subs BEFORE the bulk-unsubscribe, then per-sub broadcast.
            # Snapshot nm (Commit 2b cycle 2 MED-B): the per-sub broadcast
            # loop below would otherwise leak calls onto a stopped NM if
            # a hot-reload swaps self.network mid-loop.
            nm = self.network
            if (
                getattr(self, "networking_enabled", False)
                and nm is not None
                and getattr(nm, "is_ready", False)
            ):
                try:
                    subs_to_remove = await self.topic_registry.get_plugin_subscriptions(
                        plugin_uuid
                    )
                except Exception:
                    subs_to_remove = []
                for sub in subs_to_remove:
                    try:
                        await nm.broadcast_local_sub_removed(sub)
                    except Exception:
                        self._logger.debug(
                            "_unregister_plugin_subscriptions: broadcast failed",
                            exc_info=True,
                        )
            # Rate limiter (Step 3): drop each sub's Sub-IN bucket BEFORE the
            # bulk unsubscribe (sub_uuids are unique, so unremoved buckets would
            # accumulate across resubscribes). No-op when rate limiting is off.
            if self._rate_limits_active:
                try:
                    for sub in await self.topic_registry.get_plugin_subscriptions(
                        plugin_uuid
                    ):
                        self._rl_teardown_sub(sub.sub_uuid)
                except Exception:
                    self._logger.debug(
                        "_unregister_plugin_subscriptions: rate-limit teardown "
                        "failed", exc_info=True,
                    )
            await self.topic_registry.unsubscribe_plugin(plugin_uuid)
        plugin._sub_uuids = []

    @async_log_errors
    async def _reload_plugin(self, plugin_name: str):
        """Reload a plugin by disabling, removing, re-loading from
        config, and re-enabling.

        Stage O: the WHOLE pop+load+enable chain runs under the
        per-plugin lifecycle_lock so a concurrent enable_plugin caller
        on the same name can't interleave between the pop and the
        re-enable. The locked-body helpers (_pop_plugin_under_lock /
        _enable_plugin_under_lock) avoid recursive lock acquisition.

        Session 3 (v0.26.0): the natural state transition sequence is:
            ENABLED → DISABLING → INACTIVE → UNLOADED → INACTIVE → ENABLING → ENABLED
        for an enabled source. For an INACTIVE source:
            INACTIVE → UNLOADED → INACTIVE
        The INACTIVE → UNLOADED transition happens after
        _pop_plugin_under_lock (which only transitions ENABLED→INACTIVE).
        load_plugin_with_conf transitions back to INACTIVE on re-instantiation.

        R4-UU-1: refuses to run if Plexus is closed; otherwise a
        reload waiting on any internal lock could resurrect plugins
        onto a torn-down framework.
        """
        if getattr(self, "_closed", False):
            self._logger.warning(
                "Refusing to reload/rebuild: Plexus is closed"
            )
            return

        lifecycle_lock = self._get_lifecycle_lock(plugin_name)
        async with lifecycle_lock:
            ps = self.plugin_states.get(plugin_name)
            previously_enabled = ps is not None and ps.state == State.ENABLED

            await self._pop_plugin_under_lock(plugin_name)
            # Session 3: transition INACTIVE → UNLOADED to match the
            # public pop_plugin contract. load_plugin_with_conf will
            # transition back to INACTIVE on re-instantiation. Cycle 3
            # fix: clear instance BEFORE the transition so observers see
            # instance=None for state==UNLOADED.
            if plugin_name in self.plugin_states:
                self.plugin_states[plugin_name].instance = None
                if self.plugin_states[plugin_name].state != State.UNLOADED:
                    self._transition_plugin(plugin_name, State.UNLOADED)

            # R4-UU-4: read yaml_config under _config_lock so the
            # plugin-entry lookup is atomic against the non-networking
            # branch of async_load_config_yaml, which replaces
            # self.yaml_config via _apply_yaml under the same lock.
            # Without this, _reload_plugin's read races the config
            # write and may observe a torn plugins list.
            async with self._config_lock:
                entry = next(
                    (
                        p
                        for p in self.yaml_config.get("plugins", [])
                        if p.get("name") == plugin_name
                    ),
                    None,
                )
            if not entry:
                # R2-BB-1: clean up the ghost UNLOADED plugin_states entry
                # that _pop_plugin_under_lock + _transition_plugin(UNLOADED)
                # left behind above. Without this, raising ConfigException
                # below leaves a lingering plugin_states entry for a plugin
                # whose config has been removed.
                self.plugin_states.pop(plugin_name, None)
                # W5-R2: ConfigException is the documented type for
                # config-layer errors; bare Exception bypassed the
                # framework's exception taxonomy.
                raise ConfigException(
                    f"Plugin '{plugin_name}' not found in config for reload"
                )

            # C-019: wrap the load step so a re-instantiation failure
            # (syntax error in new code, on_load raise, missing
            # dependency, etc.) surfaces an operator alert. Without
            # this, the @async_handle_errors decorator above swallows
            # the exception and the re-enable branch is skipped
            # silently — the plugin disappears with no recovery hint.
            # ``previously_enabled`` was already captured at line ~3520
            # so it survives the raise; the alert payload carries it
            # so a recovery tool can decide whether to retry-then-enable
            # or just retry-then-leave-inactive.
            try:
                await self.load_plugin_with_conf(entry)
            except Exception:
                self._logger.exception(
                    "[RELOAD] load_plugin_with_conf raised for %r; "
                    "previously_enabled=%s. Plugin is now in FAILED_LOAD "
                    "or has been removed entirely. Inspect logs and "
                    "fix the underlying issue, then call reload_plugin "
                    "again.",
                    plugin_name,
                    previously_enabled,
                )
                self._internal_emit(
                    "_core/plugin/reload_failed",
                    plugin_name=plugin_name,
                    previously_enabled=previously_enabled,
                    ts=time.time(),
                )
                raise
            if previously_enabled:
                # C-144: explicit log on the skip path so an operator can
                # see why a previously-enabled plugin did not come back
                # ENABLED after reload. _enable_plugin_under_lock returns
                # silently when the post-load state is not INACTIVE (e.g.
                # FAILED_LOAD from a dependency mismatch, or UNLOADED
                # because the plugin entry was removed mid-reload). The
                # natural happy-path is INACTIVE → ENABLING → ENABLED;
                # anything else is operator-visible.
                ps_post = self.plugin_states.get(plugin_name)
                if ps_post is None or ps_post.state != State.INACTIVE:
                    state_label = (
                        ps_post.state.value
                        if ps_post is not None
                        else "<no state entry>"
                    )
                    self._logger.warning(
                        "[RELOAD] plugin %r was previously ENABLED but is "
                        "now in state %s after load; skipping the re-enable "
                        "step. Inspect last_errors[Phase.LOAD] for the "
                        "underlying cause.",
                        plugin_name,
                        state_label,
                    )
                else:
                    await self._enable_plugin_under_lock(plugin_name)

            # R4-WW-4: recompute the dependency graph after reload. A
            # reloaded plugin may have changed its declared dependencies
            # (new requirements, removed requirements, new cycle). Without
            # this call self._dep_topo_order would reflect the pre-reload
            # graph — shutdown order is wrong and freshly-introduced
            # cycles go undetected until the next full restart.
            try:
                await self._resolve_dependencies()
            except Exception:
                # _resolve_dependencies isn't expected to raise on cycles
                # (it records them in plugin_states); but if a future
                # variant does, keep reload semantics deterministic.
                self._logger.critical(
                    "Plugin %r reload: _resolve_dependencies raised — the "
                    "in-memory dep topo order may be stale until the next "
                    "framework restart.",
                    plugin_name,
                    exc_info=True,
                )

            # Rate limiter (Step 3): the reloaded plugin has brand-new endpoint
            # dicts + freshly-registered subs, so any cached charge-set that
            # referenced its OLD buckets is stale. A full rebuild re-points every
            # side-table entry at the live buckets (idempotent; no-op when off).
            await self._rebuild_charge_sets()

            # R4-WW-5: a successful reload of `plugin_name` may unblock
            # previously cascade-failed dependents that were marked
            # FAILED_LOAD because they referenced this plugin. We do NOT
            # auto-retry (keeps reload semantics deterministic), but log a
            # warning so the operator knows which dependents to reload.
            failed_dependents = []
            for n, ps in self.plugin_states.items():
                if ps.state != State.FAILED_LOAD:
                    continue
                err = (ps.last_errors or {}).get(Phase.LOAD)
                if err is None:
                    continue
                if plugin_name in (err.exception_repr or ""):
                    failed_dependents.append(n)
            if failed_dependents:
                self._logger.warning(
                    "[RELOAD] Plugin %r reloaded successfully; %d "
                    "dependent(s) remain in FAILED_LOAD and may now "
                    "reload successfully: %s",
                    plugin_name,
                    len(failed_dependents),
                    failed_dependents,
                )

    @contextlib.asynccontextmanager
    async def request_context_async(self, request: Request):
        """Async context manager to handle requests.

        B-073 Session 2 Step 3: ``set_collected`` migrated to
        ``self.requests.pop`` per the done-callback eviction model.
        ``Request.set_collected`` was a no-op flag-setter; the producer's
        finally in ``_process_request`` already pops the request, but
        this outer context-manager pop is symmetric (idempotent under
        ``pop(key, None)``) and matches the migration pattern across
        all 6 framework Request sites.
        """
        try:
            result, error, timed_out = await request.wait_for_result_async()
            if error:
                # C-055: raise RequestException (the documented canonical
                # type) so callers can `except RequestException` to catch
                # request failures. Previously raised bare Exception
                # which forced callers to use `except Exception` and
                # accidentally swallowed unrelated errors too.
                raise RequestException(f"Request {request.id} failed: {request.result}")
            yield result
        finally:
            self.requests.pop(request.id, None)

    @contextlib.contextmanager
    def request_context_sync(self, request: Request):
        """Sync context manager to handle requests.

        B-073 Session 2 Step 3: replaced the ``run_coroutine_threadsafe``
        bridge to ``set_collected`` with a direct sync ``pop``. The pop
        is GIL-atomic so it's safe to call from a worker thread without
        a loop-bridge — Python dict ``pop`` is implemented as a single
        bytecode op. ``_pop_plugin_under_lock`` snapshots iteration so
        concurrent eviction never trips dict-mutation-during-iteration.
        """
        try:
            result = request.get_result_sync()
            if request.error:
                # C-055: see request_context_async — same RequestException
                # canonical type so callers can catch by type.
                raise RequestException(f"Request {request.id} failed: {request.result}")
            yield result
        finally:
            self.requests.pop(request.id, None)

    @async_log_errors
    async def create_request(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Request:
        """Create a new request asynchronously."""

        if author_host is None:
            author_host = self.hostname

        request = Request(
            author_host,
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            request_id,
            self.main_event_loop,
        )

        async with self.request_lock:
            self.requests[request.id] = request

        self._logger.debug(
            f"Request {request.id} created by {author} targeting {plugin}.{method}"
        )

        self._spawn_tracked(
            self._process_request(request),
            name=f"request:{plugin}.{method}#{request.id[:8]}",
        )

        return request

    @log_errors
    def create_request_sync(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Request:
        """Create a new request synchronously."""
        # C-004: same-thread deadlock guard.
        self._check_not_loop_thread("create_request_sync")
        coro = self.create_request(
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            author_host,
            request_id,
        )
        # Caller identity: carry the originating sync handler's identity
        # across the bridge (captured worker-side, re-seated loop-side).
        coro = self._with_caller_chain(current_caller_chain(), coro)
        future = asyncio.run_coroutine_threadsafe(coro, self.main_event_loop)
        # R2-FF-1: bound the worker-thread wait so a stalled event loop
        # (deadlock, long GC pause, racing shutdown) cannot block the
        # caller forever. Derive from the surrounding request timeout
        # (+ 5s grace so the loop-side timeout has a chance to fire
        # first); fall back to a generous default when no request
        # timeout was supplied.
        request_timeout = timeout[0] if isinstance(timeout, tuple) else timeout
        wait_timeout = (request_timeout + 5.0) if isinstance(request_timeout, (int, float)) else 60.0
        # Phase 2b: construction-only park (no endpoint body, sub-ms) — but
        # still route through _bridge_wait for uniformity; freeing E during
        # the wait is harmless. No poison check: not a deadlock source.
        return _bridge_wait(future, wait_timeout)

    @async_log_errors
    async def create_gen_request(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
        _post_construct_hook: Optional[Callable[["GeneratorRequest"], None]] = None,
    ) -> GeneratorRequest:
        """Create a new request asynchronously.

        R2-FF-7: ``_post_construct_hook`` runs after the GeneratorRequest
        is constructed but BEFORE the producer task is spawned, so the
        caller can stamp attributes (e.g. ``_call_chain``) that the
        producer reads without racing the spawn. Internal only.
        """

        if author_host is None:
            author_host = self.hostname

        request = GeneratorRequest(
            author_host,
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            request_id,
            self.main_event_loop,
        )

        # R2-FF-7: run any pre-spawn stamp hook before submitting the
        # producer task so the producer sees a fully-stamped request.
        if _post_construct_hook is not None:
            _post_construct_hook(request)

        async with self.request_lock:
            self.requests[request.id] = request

        self._logger.debug(
            f"GeneratorRequest {request.id} created by {author} targeting {plugin}.{method}"
        )

        task = self._spawn_tracked(
            self._process_request_stream(request),
            name=f"request_stream:{plugin}.{method}#{request.id[:8]}",
        )
        request._producer_task = task  # B-002: enable cancel-on-collect

        return request

    @log_errors
    def create_gen_request_sync(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
        _post_construct_hook: Optional[Callable[["GeneratorRequest"], None]] = None,
    ) -> Request:
        """Create a new request synchronously.

        R2-FF-7: ``_post_construct_hook`` is forwarded to
        ``create_gen_request`` and runs pre-producer-spawn so callers can
        stamp ``request._call_chain`` (or similar) without a race
        against the producer task that reads it.
        """
        # C-004: same-thread deadlock guard.
        self._check_not_loop_thread("create_gen_request_sync")
        coro = self.create_gen_request(
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            author_host,
            request_id,
            _post_construct_hook=_post_construct_hook,
        )
        # Caller identity: carry the originating sync handler's identity
        # across the bridge (captured worker-side, re-seated loop-side).
        coro = self._with_caller_chain(current_caller_chain(), coro)
        future = asyncio.run_coroutine_threadsafe(coro, self.main_event_loop)
        # R2-FF-1: bound the worker-thread wait — see create_request_sync.
        request_timeout = timeout[0] if isinstance(timeout, tuple) else timeout
        wait_timeout = (request_timeout + 5.0) if isinstance(request_timeout, (int, float)) else 60.0
        # Phase 2b: construction-only park — route through _bridge_wait for
        # uniformity (frees E during the sub-ms wait). No poison check.
        return _bridge_wait(future, wait_timeout)

    @async_log_errors
    async def find_endpoints_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """
        Find all endpoints carrying a tag, across local + remote nodes.

        Returns a list of dicts, one per (plugin_name, access_name,
        plugin_version) capability. Same version across hosts is merged;
        different versions are separate entries (so each entry's spec is
        internally consistent and honest for every host in it). Each entry::

            {
              "access_name": str,
              "plugin_name": str,
              "plugin_version": str,
              "description": Any, "arguments": Any, "tags": Any,
              "endpoint": dict,          # shallow copy of the endpoint config
              "hosts": [str, ...],       # "local" and/or node hostnames
              "instances": [{"host": str, "plugin_uuid": str}, ...],
            }

        Returns [] when nothing matches. `hosts` reflects where a matching
        endpoint was OBSERVED, not reachability; remote-eligibility is
        recoverable from ``entry["endpoint"]["remote"]``. An enabled node
        that errors is silently omitted (best-effort).
        """

        def _ver(v):
            return str(v) if v is not None else "unknown"

        # Collect raw matches (one per physical endpoint) then merge.
        raw = []
        for plugin in self.plugins.values():
            plugin: Plugin
            if plugin.enabled:
                for ep_key, endpoint in plugin.endpoints.items():
                    if tag in (endpoint.get("tags") or []):
                        raw.append(
                            {
                                "access_name": ep_key,
                                "plugin_name": plugin.plugin_name,
                                "plugin_uuid": plugin.plugin_uuid,
                                "plugin_version": _ver(
                                    getattr(plugin, "version", "unknown")
                                ),
                                "endpoint": dict(endpoint),
                                "host": "local",
                            }
                        )

        # Snapshot self.network once. Per Commit 2b cycle 3 HIGH-A:
        # during a hot-reload rebuild, self.network is set to None for
        # the entire rebuild duration; per cycle 2 MED-B: a mid-block
        # swap would otherwise leak calls onto a stopped NM. Both
        # conditions resolve cleanly here — None falls through to the
        # local-only path.
        nm = self.network
        if (
            self.networking_enabled
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):
            for node in nm.nodes:
                node: Node
                if node.enabled:
                    result = await nm.node_get_tagged_endpoints(node.IP, tag)
                    if result:
                        for entry in result:
                            access_name = entry.get("access_name")
                            plugin_name = entry.get("plugin_name")
                            plugin_uuid = entry.get("plugin_uuid")
                            ep = entry.get("endpoint")
                            # An old node predating the access_name wire field,
                            # or any malformed entry missing a required field,
                            # cannot be keyed safely -> skip+warn rather than
                            # guess (a wrong name would misroute) or KeyError
                            # (which would abort the whole call, losing every
                            # result collected so far).
                            if not access_name or not plugin_name or (
                                not plugin_uuid
                            ) or ep is None:
                                self._logger.warning(
                                    "[TAG_SEARCH] remote endpoint from %s "
                                    "missing a required field (old/malformed "
                                    "node?); skipping",
                                    entry.get("host") or node.IP,
                                )
                                continue
                            raw.append(
                                {
                                    "access_name": access_name,
                                    "plugin_name": plugin_name,
                                    "plugin_uuid": plugin_uuid,
                                    "plugin_version": _ver(
                                        entry.get("plugin_version", "unknown")
                                    ),
                                    "endpoint": dict(ep),
                                    "host": entry.get("host") or node.IP,
                                }
                            )

        # Merge by (plugin_name, access_name, plugin_version). Local-preferred
        # canonical spec; instances deduped by plugin_uuid; any host equal to
        # self.hostname normalized to "local" (core treats them as aliases).
        merged = {}
        for r in raw:
            host = "local" if r["host"] == self.hostname else r["host"]
            key = (r["plugin_name"], r["access_name"], r["plugin_version"])
            entry = merged.get(key)
            if entry is None:
                entry = merged[key] = {
                    "access_name": r["access_name"],
                    "plugin_name": r["plugin_name"],
                    "plugin_version": r["plugin_version"],
                    "description": r["endpoint"].get("description"),
                    "arguments": r["endpoint"].get("arguments"),
                    "tags": r["endpoint"].get("tags"),
                    "endpoint": r["endpoint"],
                    "_instances": {},
                }
            if host == "local":
                entry["description"] = r["endpoint"].get("description")
                entry["arguments"] = r["endpoint"].get("arguments")
                entry["tags"] = r["endpoint"].get("tags")
                entry["endpoint"] = r["endpoint"]
            entry["_instances"][r["plugin_uuid"]] = host

        out = []
        for entry in merged.values():
            instances = [
                {"host": h, "plugin_uuid": u}
                for u, h in entry.pop("_instances").items()
            ]
            instances.sort(
                key=lambda i: (i["host"] != "local", i["host"], i["plugin_uuid"])
            )
            entry["instances"] = instances
            hosts = []
            for i in instances:
                if i["host"] not in hosts:
                    hosts.append(i["host"])
            entry["hosts"] = hosts
            out.append(entry)
        out.sort(
            key=lambda e: (e["plugin_name"], e["access_name"], e["plugin_version"])
        )
        return out

    @async_log_errors
    async def find_endpoint(
        self,
        access_name: str,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        plugin_uuid: Optional[str] = None,
        requester_id: Optional[str] = None,
        target_plugin: Optional[str] = None,
    ) -> tuple[
        Optional[Union[Plugin, RemotePlugin]],
        Optional[dict],
        Optional[Node],
    ]:
        """
        Finds a plugin endpoint locally or on remote nodes with access control.

        Args:
            access_name: The access_name of the endpoint to find
            hosts: Target hosts — "local", "remote", "any", a hostname, or a
                list of hostnames (whitelist). Caller is expected to have
                already passed this through _validate_host_args.
            blocked_hosts: Hosts to exclude — same shape as `hosts`, or None
                for no blocking.
            plugin_uuid: Specific plugin UUID to search for (optional)
            requester_id: UUID of the plugin making the request (for access control)
            target_plugin: Optional plugin name filter

        Returns:
            A 3-tuple. On a found endpoint:
                Local:  (Plugin, endpoint_dict, None)
                Remote: (RemotePlugin, endpoint_dict, Node)
            On a miss: (None, None, None) — NOT bare None. Callers must
            unpack-then-check the first element rather than
            `if result is None`. Stage M (B-048): annotation reads accurately;
            behavior unchanged (every callsite already uses unpack-then-check
            after PR3 Stage B cycle 5 fixed the one mismatched caller in
            request_event_stream).
        """

        self._logger.debug(
            f"Finding endpoint: access_name='{access_name}', hosts={hosts!r}, "
            f"blocked_hosts={blocked_hosts!r}, plugin_uuid={plugin_uuid}, "
            f"requester_id={requester_id}, target_plugin={target_plugin}"
        )

        # Determine request provenance
        # This is used to determine if a REMOTE NODE is checking OUR endpoints
        # (handled by _handle_has_endpoint on the remote node)
        is_local_system = requester_id == self.hostname
        is_local_plugin = requester_id in self.plugins_by_uuid
        is_remote_request = not (is_local_system or is_local_plugin)

        if is_remote_request:
            self._logger.debug(
                f"Remote request detected from requester_id: {requester_id}"
            )

        def _matches_local():
            if isinstance(hosts, str):
                return hosts in ("local", "any", self.hostname)
            if isinstance(hosts, list):
                return "local" in hosts or self.hostname in hosts
            return False

        def _is_local_blocked():
            if blocked_hosts is None:
                return False
            if isinstance(blocked_hosts, str):
                return blocked_hosts in ("local", "any", self.hostname)
            if isinstance(blocked_hosts, list):
                return "local" in blocked_hosts or self.hostname in blocked_hosts
            return False

        # Check locally first (only if host includes local)
        # Note: Remote accessibility checks for OUR endpoints should only happen
        # when a remote node is querying us (is_remote_request=True).
        # When WE are searching for remote endpoints, we don't check remote accessibility here.
        if _matches_local() and not _is_local_blocked():
            # R2-BB-4: snapshot via list() to avoid
            # "RuntimeError: dictionary changed size during iteration"
            # when a concurrent _pop_plugin_under_lock mutates
            # self.plugins mid-iteration. list() captures the values
            # at one moment (dict access is GIL-atomic in CPython).
            for plugin in list(self.plugins.values()):
                # Skip if plugin doesn't match UUID filter
                if plugin_uuid and plugin.plugin_uuid != plugin_uuid:
                    continue

                if target_plugin and plugin.plugin_name != target_plugin:
                    continue

                # Check if plugin is enabled and has endpoints
                if not (plugin.enabled and hasattr(plugin, "endpoints")):
                    continue

                # Fast-path by access_name
                endpoint = getattr(plugin, "_endpoint_by_access", {}).get(access_name)
                if endpoint:
                    # Check access based on request type
                    if is_remote_request:
                        # A remote node is checking OUR endpoints - check remote accessibility
                        # This is the ONLY place where we check remote accessibility
                        if not getattr(plugin, "remote", False):
                            continue
                        if not endpoint.get("remote", False):
                            continue
                        return plugin, endpoint, None
                    else:
                        # Local request: check accessible_by_other_plugins flag
                        if (
                            not endpoint.get("accessible_by_other_plugins", False)
                            and plugin.plugin_uuid != requester_id
                        ):
                            pass
                        else:
                            return plugin, endpoint, None

        def _matches_remote_node(node_hostname):
            if isinstance(hosts, str):
                return hosts in ("remote", "any") or hosts == node_hostname
            if isinstance(hosts, list):
                return node_hostname in hosts
            return False

        def _is_remote_node_blocked(node_hostname):
            if blocked_hosts is None:
                return False
            if isinstance(blocked_hosts, str):
                return (
                    blocked_hosts in ("remote", "any") or blocked_hosts == node_hostname
                )
            if isinstance(blocked_hosts, list):
                return node_hostname in blocked_hosts
            return False

        def _other_than_local():
            if isinstance(hosts, str):
                return not hosts in ("local", self.hostname)
            if isinstance(hosts, list):
                return (
                    len(hosts) - hosts.count("local") - hosts.count(self.hostname)
                ) > 0
            return True

        # Check remote nodes if networking is enabled
        # Snapshot nm once. Per Commit 2b cycle 3 HIGH-A: during a
        # hot-reload rebuild, self.network = None for the entire
        # rebuild duration. cycle 2 MED-B: snapshot prevents mid-block
        # swap from leaking calls onto a stopped NM. None falls through
        # to the bottom `return None, None, None` no-match path.
        nm = self.network
        if (
            getattr(self, "networking_enabled", False)
            and _other_than_local()
            and nm is not None
            and getattr(nm, "is_ready", False)
        ):

            for node in nm.nodes:
                if not (node.enabled and await node.is_alive()):
                    continue

                if not _matches_remote_node(node.hostname) or _is_remote_node_blocked(
                    node.hostname
                ):
                    continue

                # Check remote node for endpoint
                result = await nm.node_has_endpoint(
                    node.IP,
                    access_name,
                    plugin_uuid if plugin_uuid != "remote" else None,
                    requester_id,
                    target_plugin,
                )

                if result and result.get("available", False):
                    # Create RemotePlugin from response data
                    plugin_info = result.get("plugin_info", {})
                    endpoint_info = result.get("endpoint", {})

                    remote_plugin = RemotePlugin(
                        name=plugin_info.get("name", "unknown"),
                        version=plugin_info.get("version", "unknown"),
                        uuid=plugin_info.get("uuid"),
                        enabled=True,
                        remote=True,
                        description=plugin_info.get("description", "Remote plugin"),
                        arguments=[],
                        hostname=result.get("hostname", node.hostname),
                    )

                    return remote_plugin, endpoint_info, node

        return None, None, None

    async def is_requester_allowed(self, requester_id: str) -> bool:
        """
        Checks if a requester plugin exists and is allowed to access endpoints.

        Args:
            requester_id: UUID of the plugin making the request

        Returns:
            True if the requester is allowed, False otherwise
        """
        # Check if requester exists locally
        requester_plugin = self.plugins_by_uuid.get(requester_id)
        if not requester_plugin:
            return False

        # Check if requester is enabled
        if not requester_plugin.enabled:
            return False

        # Add additional access control logic here if needed
        # For example, check if the requester has permission to access remote endpoints

        return True

    @async_handle_errors(None)
    async def _process_request(self, request: Request) -> None:
        """Process a request by invoking the target plugin method.

        B-073 Session 2 Step 2: ``finally`` block evicts the Request
        from ``self.requests`` on every completion path (success, error,
        cancellation). Replaces the 10s polling reap performed by the
        ``cleanup_requests`` maintenance loop (killed in Step 4 — both
        mechanisms run idempotently in the meantime). The pop is sync
        + GIL-atomic; ``_pop_plugin_under_lock`` snapshots
        ``self.requests`` under the lock so concurrent eviction never
        triggers ``RuntimeError: dictionary changed size during iteration``.
        """
        try:
            plugin_name = request.target_plugin
            function_name = request.target_method

            # B-073 Step 8 emit: request started.
            # Phase 2a (B-080-adjacent): ``kind`` carries request.kind so
            # observers can distinguish execute / publish_event fan-out /
            # request_event fan-out children without correlating against
            # _core/event/* topics. Backward-compatible — observers ignore
            # unknown keys per the (topic, payload) contract.
            self._internal_emit(
                "_core/request/started",
                request_id=request.id,
                plugin=plugin_name,
                method=function_name,
                author=request.author,
                kind=request.kind,
                ts=time.time(),
            )

            # PR3 Stage A: prefer request.requester_id (set by Stage B
            # fan-out to sub OWNER's plugin_uuid per C18) over
            # author_id. None on execute-path Requests → falls back to
            # author_id, preserving find_endpoint's existing access
            # check semantics.
            requester = request.requester_id or request.author_id
            plugin, endpoint, node = await self.find_endpoint(
                request.target_method,
                request.target_hosts,
                request.blocked_hosts,
                request.target_plugin_uuid,
                requester,
                request.target_plugin,
            )

            if not plugin:
                await self._set_request_result(
                    request, f"Endpoint {function_name} not found", True
                )
                return

            # Stage O: readiness gate. Skip for remote plugins (no ready
            # field) and for self-calls (Q23 — a plugin's own on_enable
            # publishing to its own subscriber must not deadlock against
            # its own _lifecycle_ready).
            if isinstance(plugin, Plugin) and plugin.plugin_uuid != requester:
                try:
                    await self._wait_for_plugin_ready(plugin)
                except asyncio.TimeoutError:
                    timeout = getattr(
                        self,
                        "plugin_ready_timeout",
                        DEFAULT_PLUGIN_READY_TIMEOUT,
                    )
                    await self._set_request_result(
                        request,
                        f"Plugin {plugin.plugin_name!r} not ready within "
                        f"{timeout}s",
                        True,
                    )
                    return

            host_label = (
                f"(local) {self.hostname}"
                if isinstance(plugin, Plugin)
                else f"{node.IP}#{node.hostname}"
            )
            self._logger.debug(
                f"Found {plugin_name} (ID: {plugin.plugin_uuid}) for Request with ID {request.id} on host {host_label}"
            )

            if isinstance(
                plugin, RemotePlugin
            ):  # NOTE: Fix the timeout thing. Warn if ping is higher than timeout
                # Stamp _is_remote BEFORE the network check so the
                # rebuild drain (Step 7) catches in-flight remote
                # requests even when self.network transitions to None
                # mid-await. Per cycle 1 HIGH-1 — drain filter uses
                # this attribute to distinguish remote-bound requests
                # from local execute path requests.
                request._is_remote = True
                # C-092: stamp the routed peer hostname so
                # NetworkManager._mark_node_dead can fast-fail all
                # in-flight remote Requests bound for that peer (vs.
                # waiting for TCP socket timeout). target_hosts is the
                # caller-side routing filter (list of allowed hosts);
                # target_host is the single concrete peer this Request
                # was actually dispatched to after routing resolved.
                request.target_host = node.hostname
                # Snapshot nm. Per Commit 2b cycle 3 HIGH-A: during a
                # hot-reload rebuild, self.network is None for the
                # entire rebuild duration. cycle 3 HIGH-β requires a
                # distinct fail-fast semantic here (not silent return)
                # so the caller's future resolves with a clear error
                # rather than hanging forever. Also gate on
                # ``is_ready=False`` to cover the post-rebuild window
                # where NM has been assigned but its ``start()`` task
                # hasn't completed yet (cycle 6 fresh-eyes MED).
                nm = self.network
                if nm is None or not getattr(nm, "is_ready", False):
                    await self._set_request_result(
                        request,
                        "Network unavailable mid-rebuild",
                        True,
                    )
                    return
                result = await nm.execute_remote(
                    IP=node.IP,
                    plugin=plugin_name,
                    method=function_name,
                    args=request.args,
                    plugin_uuid=request.target_plugin_uuid,
                    author=f"{self.hostname} - {request.author}#{request.author_id}",
                    author_id=request.author_id,
                    # R2-LL-2: send the timeout DURATION only — never the
                    # sender's wall-clock created_at. Peer clock skew used
                    # to corrupt the remote deadline by however many seconds
                    # the two clocks disagreed; anchoring on the receiver's
                    # own monotonic clock at construction removes the skew.
                    # Old peers still accepted via the tuple branch in
                    # Request.__init__ (its second element is ignored).
                    timeout=request.timeout_duration,
                    request_id=request.id,
                )

            else:
                # PR2: internal_name is optional in plugin_config; defaults to
                # access_name (the dict key, also the request target_method).
                internal_name = endpoint.get("internal_name") or function_name
                func = getattr(plugin, internal_name, None)
                if not callable(func):
                    await self._set_request_result(
                        request,
                        f"Function {function_name}({internal_name}) not found in plugin {plugin_name}",
                        True,
                    )
                    return

                if inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(
                    func
                ):
                    await self._set_request_result(
                        request,
                        f"For Request {request.id}: The method you requested is a generator. Use execute_stream for generators",
                        True,
                    )
                    return

                try:
                    chain = getattr(request, "_call_chain", ())
                    result = await self._call_endpoint(
                        func, request.args, chain, request=request
                    )
                except Exception as e:
                    # Surface the exception TYPE NAME alongside the message so
                    # the caller's RequestException is not opaque ("ValueError:
                    # intentional", not "intentional"). Skip the prefix when the
                    # handler already raised a RequestException — the caller
                    # catches RequestException by contract, so a
                    # "RequestException: ..." prefix would be redundant noise.
                    # Mirrors the request_event stream server's two error
                    # branches in networking.py (raw RequestException vs
                    # type-prefixed wrap for everything else).
                    msg = (
                        str(e)
                        if isinstance(e, RequestException)
                        else f"{type(e).__name__}: {e}"
                    )
                    await self._set_request_result(request, msg, True)
                    return

            await self._set_request_result(request, result)

        except BaseException as e:
            # R4-YY-1: catch BaseException (not just Exception) so a
            # CancelledError that propagates through this function still
            # gets a chance to resolve the future before exiting. The
            # previous ``except Exception`` left the consumer hanging on
            # an unresolved future when the producer task was cancelled.
            # Mirrors the C-048 pattern already in _process_request_stream.
            if not request._future.done():
                try:
                    await self._set_request_result(
                        request,
                        f"Request {request.id} aborted: "
                        f"{type(e).__name__}: {e}",
                        True,
                    )
                except Exception:
                    # Best-effort: we're already mid-cancellation /
                    # mid-shutdown. The finally below still pops the
                    # request entry so framework state stays clean.
                    pass
            # Re-raise so a CancelledError propagates to the task
            # supervisor (otherwise the framework swallows cancellation,
            # which is incorrect).
            if isinstance(e, asyncio.CancelledError):
                raise
            # For regular Exception, do not re-raise — preserves the
            # original "safety-net" semantics (consumer sees the error
            # via the resolved future, not via an unhandled task
            # exception).
        finally:
            # B-073 Step 8 emit: request completed. Observer-presence
            # gate skips the future-state read + payload assembly when
            # nothing is listening — the production-default no-observer
            # path saves ~500ns-1µs per request. The pop below stays
            # outside the gate (eviction is unconditional). Cached
            # ``now`` shared between latency calc + ts payload.
            if "_core/request/completed" in self._internal_observers:
                # Defensive future-state read — cancelled future raises
                # on .result(); guard explicitly. Latency clamped to
                # 0.0 against clock jumps.
                if request._future.done() and not request._future.cancelled():
                    try:
                        _, _err_flag, _ = request._future.result()
                        errored = bool(_err_flag)
                    except Exception:
                        errored = True  # future yielded an exception
                else:
                    errored = request._future.cancelled()
                now = time.time()
                # Phase 2a: kind=request.kind for symmetry with /started.
                self._internal_emit(
                    "_core/request/completed",
                    request_id=request.id,
                    latency=max(0.0, now - request.created_at),
                    error=errored,
                    kind=request.kind,
                    ts=now,
                )

            # B-073 Session 2 Step 2: done-callback eviction. Pop the
            # Request entry from ``self.requests`` on every completion
            # path (success, exception, cancellation). Replaces the
            # ``cleanup_requests`` polling reap (killed in Step 4).
            # ``pop(key, None)`` is GIL-atomic and idempotent — safe
            # under cancel mid-finally.
            self.requests.pop(request.id, None)

    async def _with_caller_chain(self, chain, coro):
        """Caller identity: re-seat a worker-captured caller chain onto the
        loop for ``coro``'s lifetime (the sync-bridge handoff).

        A plugin's sync handler carries its identity in the _sync_identity_chain
        threadlocal; that threadlocal is invisible once a sync mirror bridges
        the operation back onto the loop via run_coroutine_threadsafe. The
        mirror captures ``current_caller_chain()`` worker-side and passes it
        here so the loop-side dispatch attributes to the originating handler,
        not an empty caller. No-op when the captured chain is empty (identity
        off, or a non-plugin top-level sync caller -- nothing to attribute)."""
        if not chain:
            return await coro
        with establish_caller_chain(chain):
            return await coro

    def _seed_sync_hook(self, fn, seed):
        """Caller identity: wrap a bare sync callable (a lifecycle hook
        dispatched via ``run_in_executor`` with no ``_tracked`` wrapper of its
        own) so it seeds the worker caller-identity threadlocal from ``seed``
        and clears it on return. Returns ``fn`` unchanged when ``seed`` is None
        (identity inactive), so the off path adds nothing. The async ContextVar
        is invisible on the worker, hence the explicit seed."""
        if seed is None:
            return fn

        def _seeded(*a, **kw):
            _sync_identity_chain.chain = seed
            try:
                return fn(*a, **kw)
            finally:
                _sync_identity_chain.chain = ()

        return _seeded

    def _load_capability_grants(self) -> None:
        """Capability gate: (re)load the main-config ``capabilities:``
        section into the grant store and recompute the master switch. Called at
        init; re-callable on hot-reload (grants are runtime-reconfigurable). A
        malformed section raises at load via ``parse_capabilities`` -> ValueError
        (fail loud, never a silent missing/over-broad grant)."""
        raw = (self.yaml_config or {}).get("capabilities")
        self._capability_grants = parse_capabilities(raw)
        self._recompute_capability_active()
        if self._capability_active:
            self._logger.info(
                "[CAPABILITY] gate active; grants configured for: %s",
                sorted(self._capability_grants),
            )

    def _load_rate_limits(self) -> None:
        """Step 4: (re)load the main-config ``rate_limits:`` section into the
        three BASE rate-limit dicts. Mirrors ``_load_capability_grants``: parse
        + assign, fail LOUD on a malformed section via ``parse_rate_limits`` ->
        ValueError (never a silent zero-limit or a runtime KeyError). Does NOT
        build buckets -- ``_rebuild_charge_sets`` does that after plugins load
        (and merges the plugin-declared layer on top, main winning).

        Called at init (mirroring ``_load_capability_grants``, which is itself
        init-only -- main-config live reload of these sections is not wired).
        The plugin-declared layer DOES hot-reload via ``_rebuild_charge_sets``
        on plugin reload."""
        cfg, sub_cfg, nodes_cfg = parse_rate_limits(
            (self.yaml_config or {}).get("rate_limits")
        )
        # All THREE base stores are assigned here -- including the Nodes-IN
        # sideband (operator-global; no plugin-declared layer).
        self._rate_limit_config = cfg
        self._rate_limit_sub_config = sub_cfg
        self._rate_limit_nodes_in_config = nodes_cfg

    def _recompute_capability_active(self) -> None:
        """Derive the capability master switch from the grant store. When ANY
        grant exists the gate is live, which requires caller-identity stamping so
        the gate can read the real caller -- so this also turns
        ``_identity_active`` on (it never turns it OFF: a rate limit, or a test,
        may want stamping independently). Called after the ``capabilities:``
        config is applied (and re-callable on hot-reload)."""
        self._capability_active = bool(self._capability_grants)
        if self._capability_active:
            self._identity_active = True

    def _recompute_rate_limits_active(self) -> None:
        """Derive the rate-limit master switch from the limiter's bucket count.
        When ANY bucket is configured the charge path is live, which requires
        caller-identity stamping (to attribute a charge to the real caller / the
        asserted identity) -- so this also turns ``_identity_active`` on (it never
        turns it OFF: the capability gate, or a test, may want stamping
        independently). Called after buckets are (re)configured -- the Step 4
        config-apply / hot-reload path, or directly from tests."""
        self._rate_limits_active = len(self._rate_limiter) > 0
        if self._rate_limits_active:
            self._identity_active = True

    def _rl_configure(self, dim: str, key: str):
        """Configure (create-or-reconfigure) the bucket for ``(dim, key)`` from
        the rate-limit config, or return None when that dimension has no
        configured limit. The charge-set builder uses the returned bucket; an
        unconfigured dimension is simply skipped (zero-overhead-off).

        Step 4: BASE (main-config + test-injected ``_rate_limit_config``) is
        consulted FIRST so an operator's main limit wins; the plugin-declared
        layer fills only slots main did not set."""
        params = self._rate_limit_config.get((dim, key))
        if params is None:
            params = self._rate_limit_config_declared.get((dim, key))
        if params is None:
            return None
        # reset_stream_weight: the rebuild re-registers stream weights from
        # scratch right after, so a reload that lowers a stream_weight + its
        # bucket max must not be rejected by the stale grow-only floor.
        return self._rate_limiter.configure(
            dim, key, params["max"], params["window"], reset_stream_weight=True
        )

    def _rl_build_sub(self, sub) -> None:
        """Build + store ONE subscription's IN-set charge-set. Keyed on the sub's
        TARGET (where the dispatch lands), NOT the owner: a cross-plugin sub owned
        by A targeting E@B charges B. A declared_id Sub-IN limit is resolved to a
        sub_uuid-keyed bucket here (sub_uuid is unknown at config-write time);
        runtime-only subs (declared_id None) get no Sub-IN, so the IN-set
        naturally falls back to [endpoint_in, plugin_in]. The endpoint_in /
        plugin_in buckets are looked up (configured already for the target
        plugin), not created here. Shared by the full rebuild and the runtime
        subscribe path."""
        if sub.declared_id is not None:
            # BASE (main + test) first, then the plugin-declared layer -- main
            # wins on an overlapping (plugin, declared_id) Sub-IN limit.
            scfg = self._rate_limit_sub_config.get(
                (sub.plugin_name, sub.declared_id)
            )
            if scfg is None:
                scfg = self._rate_limit_sub_config_declared.get(
                    (sub.plugin_name, sub.declared_id)
                )
            if scfg is not None:
                sub_b = self._rate_limiter.configure(
                    DIM_SUB_IN, sub.sub_uuid, scfg["max"], scfg["window"],
                    reset_stream_weight=True,
                )
                # 3d fold-in: if the sub's TARGET endpoint is a stream, register
                # its weight against the Sub-IN bucket too. A streaming
                # sub-dispatch charges the sub IN-set at cost=stream_weight, so
                # sub_in must carry max_stream_weight for the reconfigure
                # revalidation (Section 7) to catch sub_in.max < weight LOUD at
                # build instead of as a silent permanent reject at open.
                tgt = self.plugins.get(sub.target_plugin)
                tep = (
                    (getattr(tgt, "endpoints", None) or {}).get(
                        sub.target_access_name
                    )
                    if tgt is not None
                    else None
                )
                tw = tep.get("stream_weight") if isinstance(tep, dict) else None
                if tw is not None:
                    sub_b.register_stream_weight(tw)
        self._rl_sub_in[sub.sub_uuid] = charge_set(
            self._rate_limiter,
            [
                (DIM_SUB_IN, sub.sub_uuid),
                (DIM_ENDPOINT_IN, endpoint_key(sub.target_plugin,
                                               sub.target_access_name)),
                (DIM_PLUGIN_IN, sub.target_plugin),
            ],
        )

    async def _rebuild_charge_sets(self) -> None:
        """(Re)build every precomputed charge-set side-table from the current
        rate-limit config + the live plugin/sub set. Idempotent
        clear-and-repopulate (never appends), so any trigger -- initial load,
        hot-reload, config apply, or a test -- may call it unconditionally and
        twice == once. Re-points every side-table entry at the LIVE bucket
        objects, so a hot-swap that recreated buckets cannot leave a stale
        reference. Ends by recomputing the active master switch.

        Async because it reads the topic registry (get_plugin_subscriptions).
        Charge-sets live in PLEXUS side-tables, never on the endpoint dict /
        Subscription (those are pickle-shipped to peers).
        """
        self._rl_endpoint_in.clear()
        self._rl_sub_in.clear()
        self._rl_event_out.clear()
        self._rl_plugin_out.clear()
        self._rl_framework_in = None
        self._rl_framework_out = []

        # Step 4: recompute the plugin-declared layer FROM SCRATCH from the
        # currently-loaded plugins. This MUST happen BEFORE the early-return
        # guard below -- a node whose ONLY limits are plugin-declared (no main
        # rate_limits:) would otherwise short-circuit with an empty declared
        # layer and silently apply nothing. Recomputing fresh each rebuild is
        # also how a removed plugin's declared limits disappear (it is simply no
        # longer scanned). setdefault keeps it order-independent; cross-plugin
        # (dim,key) collisions cannot occur because every declared key is
        # namespaced to its own plugin (parse_plugin_rate_limits(name, ...)).
        self._rate_limit_config_declared.clear()
        self._rate_limit_sub_config_declared.clear()
        for plugin in list(self.plugins.values()):
            decl = getattr(plugin, "_declared_rate_limits", None)
            if not decl:
                continue
            d_cfg, d_sub = decl
            for k, v in d_cfg.items():
                self._rate_limit_config_declared.setdefault(k, v)
            for k, v in d_sub.items():
                self._rate_limit_sub_config_declared.setdefault(k, v)

        if not (
            self._rate_limit_config
            or self._rate_limit_sub_config
            or self._rate_limit_config_declared
            or self._rate_limit_sub_config_declared
        ) and len(self._rate_limiter) == 0:
            # Zero-overhead-off: nothing configured AND no buckets to tear down.
            # The `len == 0` guard is load-bearing: when nothing is configured but
            # the limiter STILL holds buckets from a prior config (e.g. the last
            # plugin-declared-only limit was just removed on unload/reload), we
            # must NOT short-circuit -- the prune loop below is the ONLY remover of
            # static buckets, so skipping it would leak them AND pin
            # _rate_limits_active True (len > 0). Falling through with empty config
            # leaves `wanted`/`wanted_subs` empty, so the prune drops every static
            # + Sub-IN bucket (Nodes-IN is intentionally never pruned), and the
            # master switch then recomputes honestly.
            self._recompute_rate_limits_active()
            return

        # Track every STATIC (dim, key) we configure this pass so the prune at
        # the end can drop any static bucket left by a now-removed plugin.
        wanted = set()

        def cfg(dim, key):
            b = self._rl_configure(dim, key)
            if b is not None:
                wanted.add((dim, key))
            return b

        self._rl_framework_in = cfg(DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)
        # S1: the framework-only OUT set, charged when the caller chain is empty
        # (framework / system origin -> framework_in alone; Section 8 amendment).
        # Also the fallback when a caller's per-plugin set is missing.
        self._rl_framework_out = charge_set(
            self._rate_limiter, [(DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)]
        )

        for plugin in list(self.plugins.values()):
            p_name = plugin.plugin_name
            cfg(DIM_PLUGIN_IN, p_name)
            cfg(DIM_PLUGIN_OUT, p_name)
            # S1: per-caller OUT set (execute attempt) -- plugin_out, framework_in.
            self._rl_plugin_out[p_name] = charge_set(
                self._rate_limiter,
                [(DIM_PLUGIN_OUT, p_name), (DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)],
            )
            for access, ep in (getattr(plugin, "endpoints", None) or {}).items():
                ek = endpoint_key(p_name, access)
                cfg(DIM_ENDPOINT_IN, ek)
                cs = charge_set(
                    self._rate_limiter,
                    [(DIM_ENDPOINT_IN, ek), (DIM_PLUGIN_IN, p_name)],
                )
                self._rl_endpoint_in[(p_name, access)] = cs
                # A stream endpoint declares a per-call cost; register it against
                # every bucket the stream charges so an over-weight stream fails
                # LOUD at build (Section 7), not as a misleading congestion reject
                # at open. Absent weight -> non-stream -> no registration.
                weight = ep.get("stream_weight") if isinstance(ep, dict) else None
                if weight is not None:
                    # Validate numeric UNCONDITIONALLY (even when cs is empty so
                    # no bucket gets register_stream_weight): a malformed weight
                    # must fail at build, not as a ValueError in the stream
                    # producer at dispatch (Step 3d fold-in).
                    validate_stream_weight(weight, f"endpoint {ek}")
                    for b in cs:
                        b.register_stream_weight(weight)
            for event_id in (getattr(plugin, "events", None) or {}):
                # cfg() still creates/tracks the event_out bucket for the prune
                # set; the precomputed full OUT set re-fetches it via charge_set.
                cfg(DIM_EVENT_OUT, event_key(p_name, event_id))
                # S1: per-(plugin, event) OUT set -- plugin_out, event_out,
                # framework_in. Built for EVERY declared event (charge_set skips
                # any unconfigured dimension), so a publish always finds its set.
                self._rl_event_out[(p_name, event_id)] = charge_set(
                    self._rate_limiter,
                    [(DIM_PLUGIN_OUT, p_name),
                     (DIM_EVENT_OUT, event_key(p_name, event_id)),
                     (DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)],
                )

        wanted_subs = set()
        for plugin in list(self.plugins.values()):
            try:
                subs = await self.topic_registry.get_plugin_subscriptions(
                    plugin.plugin_uuid
                )
            except Exception:
                subs = []
            for sub in subs:
                self._rl_build_sub(sub)
                wanted_subs.add(sub.sub_uuid)

        # Prune orphan buckets left by removed plugins / subs (configure only
        # adds). Static dims are pruned against the configured set; Sub-IN
        # against the live-sub set; Nodes-IN (dynamic runtime get-or-create) is
        # never pruned here. Keeps len(limiter) -- which drives
        # _rate_limits_active -- honest after a removal, while the
        # reconfigure-in-place above preserved token state for surviving buckets.
        for dim, key in self._rate_limiter.keys():
            if dim in _RL_STATIC_DIMS:
                if (dim, key) not in wanted:
                    self._rate_limiter.remove(dim, key)
            elif dim == DIM_SUB_IN and key not in wanted_subs:
                self._rate_limiter.remove(dim, key)
                self._rl_sub_in.pop(key, None)

        self._recompute_rate_limits_active()

    def _rl_teardown_sub(self, sub_uuid: str) -> None:
        """Remove a subscription's Sub-IN bucket + drop its cached charge-set.
        Called when a sub is removed (explicit unsubscribe or plugin disable/pop)
        -- sub_uuids are unique per subscription, so without this their buckets
        would accumulate across resubscribes. No-op when rate limiting is off."""
        if not self._rate_limits_active:
            return
        self._rate_limiter.remove(DIM_SUB_IN, sub_uuid)
        self._rl_sub_in.pop(sub_uuid, None)

    def _rl_admit_out(self, asserted, producer_name=None, event_id=None, now=None):
        """OUT-side (attempt) admit for one operation. Returns the first DRY
        bucket (caller raises RateLimitException) or None when admitted.

        Pinned bucket order: plugin_out, event_out, framework_in (OUT dims then
        Framework-IN; Section 5). OUT cost is always 1.0 (one operation = one
        attempt; stream weight is IN-only, Section 7). No-op when rate limiting
        is off, or when any frame in the live chain is exempt (lifecycle origin).

        The caller chain is read ONCE here (S2) and drives both the exempt check
        and -- on the execute path -- the charged caller name.

        Charge-set source:
          - asserted is None (the common path): a PRECOMPUTED, pinned-order set
            (S1, no per-call allocation) -- the per-(producer, event) set for an
            event, the per-caller set for an execute, or the framework-only set
            for an empty/unknown chain. Each set already has framework_in folded
            in at its tail.
          - asserted is not None (impersonation, rare): built dynamically,
            because plugin_out is keyed by the ASSERTED name while event_out
            stays keyed by the REAL producer -- a mix the per-producer precompute
            cannot hold.
        The ``or`` fallbacks degrade to a looser set when a key is absent (a
        plugin / event not yet rebuilt) and finally to the framework-only set; an
        empty list falls through harmlessly (it can only be empty when the looser
        sets are empty too)."""
        if not self._rate_limits_active:
            return None
        chain = current_caller_chain()
        if any(f.exempt for f in chain):
            return None
        if asserted is not None:
            buckets = []
            pob = self._rate_limiter.get(DIM_PLUGIN_OUT, asserted.name)
            if pob is not None:
                buckets.append(pob)
            if event_id is not None:
                eb = self._rate_limiter.get(
                    DIM_EVENT_OUT, event_key(producer_name, event_id)
                )
                if eb is not None:
                    buckets.append(eb)
            if self._rl_framework_in is not None:
                buckets.append(self._rl_framework_in)
            return self._rate_limiter.admit(buckets, 1.0, now)
        if event_id is not None:
            cs = (self._rl_event_out.get((producer_name, event_id))
                  or self._rl_plugin_out.get(producer_name)
                  or self._rl_framework_out)
        else:
            name = producer_name or (chain[-1].name if chain else None)
            cs = self._rl_plugin_out.get(name) or self._rl_framework_out
        if not cs:
            return None
        return self._rate_limiter.admit(cs, 1.0, now)

    def _rl_admit_in(self, plugin_name, access, sub_uuid, cost=1.0, now=None):
        """IN-side (delivery) admit for one dispatch. Returns the first DRY
        bucket (caller raises / resolves the request) or None when admitted.

        Charge-set is looked up FRESH from the side-tables (live bucket refs, so a
        hot-swap that rebuilt buckets between fan-out and delivery cannot leave a
        stale reference): the sub IN-set [sub_in, endpoint_in, plugin_in] when this
        is a sub-dispatch (``sub_uuid`` set at the fan-out site), else the endpoint
        IN-set [endpoint_in, plugin_in]. ``cost`` is 1.0 for a normal call and the
        endpoint's stream_weight for a stream open (Section 7, IN-only). ``now`` is
        a FRESH ``time.monotonic()`` captured at the IN site (never the OUT
        ``now``). No-op when rate limiting is off, when any frame in the live chain
        is exempt (lifecycle origin), or when nothing is configured for this
        target (empty / missing charge-set)."""
        if not self._rate_limits_active:
            return None
        if any(f.exempt for f in current_caller_chain()):
            return None
        if sub_uuid is not None:
            cs = self._rl_sub_in.get(sub_uuid)
        else:
            cs = self._rl_endpoint_in.get((plugin_name, access))
        if not cs:
            return None
        return self._rate_limiter.admit(cs, cost, now)

    def _rl_log_reject(self, dry, loc=None) -> None:
        """Step 5: emit a SUPPRESSED WARNING for a rejected bucket. First reject
        per (dim, key) per ``RL_REJECT_LOG_WINDOW`` logs; further rejects in the
        window are silent (the ``Bucket.rejected`` counter carries the volume);
        the next reject after the window emits a one-line summary of what was
        suppressed, then a fresh WARNING. Self-contained so it is callable from
        every reject path -- the message sites (via ``_rl_reject_message``, which
        passes ``loc`` pre-resolved) AND the silent fire-and-forget peer-publish
        drop in the networking layer (which passes no ``loc``). Never raises on
        the reject path (a logging fault must not mask a throttle).
        """
        if loc is None:
            loc = self._rate_limiter.locate(dry)
        if loc is None:
            # Unregistered between admit and here -- cannot happen loop-side, but a
            # missing identity is not worth crashing the reject path over.
            return
        where = f"{loc[0]}:{loc[1]}"
        now = time.monotonic()
        st = self._rl_reject_log.get(loc)
        if st is None or (now - st["last_warn"]) >= RL_REJECT_LOG_WINDOW:
            if st is not None:
                # rejected_at_warn was dry.rejected AT the previous WARNING (which
                # already included that warned reject); dry.rejected now includes
                # THIS reject. Subtracting both endpoints counts exactly the
                # in-window suppressed rejects. The -1 is intentional; do NOT
                # "fix" it.
                suppressed = dry.rejected - st["rejected_at_warn"] - 1
                if suppressed > 0:
                    self._logger.warning(
                        "[RATELIMIT] %d further reject(s) on %s in the last ~%.0fs",
                        suppressed, where, RL_REJECT_LOG_WINDOW,
                    )
            self._logger.warning(
                "[RATELIMIT] reject on %s (%.3f/%.0f tokens); suppressing further "
                "warnings ~%.0fs (counter still tracks every reject)",
                where, dry.tokens, dry.max, RL_REJECT_LOG_WINDOW,
            )
            self._rl_reject_log[loc] = {"last_warn": now, "rejected_at_warn": dry.rejected}
        # else: in-window -> suppressed; Bucket.rejected already carries it.

    def _rl_reject_message(self, dry, cost=1.0):
        """Emit the suppressed reject WARNING (Step 5) and return the round-trip
        reject string (Step 3): reverse-map the dry bucket to its dimension/key
        (Bucket carries no identity) and fold dimension/key + remaining tokens +
        the binding cost into a message that survives the request/future boundary
        as a string. ``cost`` is 1.0 for the OUT/non-stream IN path and the
        stream_weight for a stream open, so a weight-rejected stream is legible.

        Every message-building reject site (the raising ``_rl_reject`` + the stream
        producers + the networking handlers) calls this exactly once per reject, so
        the WARNING fires once without each site needing its own log call. The
        bucket identity is resolved ONCE here and shared with ``_rl_log_reject`` so
        the reject path does a single ``locate`` scan, not two."""
        loc = self._rate_limiter.locate(dry)
        self._rl_log_reject(dry, loc)
        # locate() can only miss if the bucket was unregistered between the admit
        # and here; that cannot happen loop-side (no await between), but fall back
        # to a clear label rather than a bare object repr.
        where = f"{loc[0]}:{loc[1]}" if loc is not None else "(unregistered bucket)"
        return (
            f"rate limit exceeded on {where} "
            f"({dry.tokens:.3f}/{dry.max:.0f} tokens available, need {cost})"
        )

    def _rl_reject(self, dry, cost=1.0):
        """Raise ``RateLimitException`` for a dry bucket. OUT callers keep calling
        ``self._rl_reject(dry)`` (cost defaults to 1.0). The WARNING is emitted by
        ``_rl_reject_message`` (Step 5 suppression)."""
        raise RateLimitException(self._rl_reject_message(dry, cost))

    def _rl_admit_inbound(self, peer, include_framework, now=None):
        """Networking inbound admit (Step 3e): per-remote-peer Nodes-IN, plus (for
        the event handlers) Framework-IN, as ONE atomic admit. Returns the first
        dry bucket (the handler rejects per its own convention) or None when
        admitted / nothing configured.

        Nodes-IN is the one DYNAMIC-key dimension: the per-peer bucket is lazily
        get-or-created on first contact from the `_rate_limit_nodes_in_config`
        sideband (per-peer override else "default"). Gated on the SIDEBAND (and
        `_rl_framework_in`), NOT `_rate_limits_active` -- the first peer's bucket
        does not exist yet, so the static-bucket master switch would be False
        (chicken-and-egg). No identity / exempt logic: the key is the peer
        hostname from the connection context, not the caller chain. `now` is a
        FRESH `time.monotonic()` from the handler. Cost is 1 (op-rate cap; the
        per-call stream_weight is charged separately at the IN-set delivery).

        Pinned order: Nodes-IN then Framework-IN, so a per-peer flood is reported
        as the Nodes-IN dimension rather than the global cap.

        Execute handlers pass `include_framework=False` (Framework-IN is charged
        by their re-entry into `plexus.execute` / `plexus.execute_stream`);
        charging it here too would double-charge. Event handlers pass True.
        """
        buckets = []
        cfg = self._rate_limit_nodes_in_config
        if cfg and peer is not None:
            nb = self._rate_limiter.get(DIM_NODES_IN, peer)
            if nb is None:
                params = cfg.get(peer, cfg.get("default"))   # per-peer else default
                if params is not None:
                    nb = self._rate_limiter.configure(
                        DIM_NODES_IN, peer, params["max"], params["window"], now
                    )
            if nb is not None:
                buckets.append(nb)
        if include_framework and self._rl_framework_in is not None:
            buckets.append(self._rl_framework_in)
        if not buckets:
            return None
        return self._rate_limiter.admit(buckets, 1.0, now)

    def _gate_author(self, author, author_id):
        """Capability gate. Returns ``(effective_author,
        effective_author_id, asserted)`` where ``asserted`` is the CallerIdentity
        to install via ``asserted_identity_scope`` for the operation (None = no
        new scope). Raises ``CapabilityException`` (fail CLOSED) on a denied
        assertion. Pass-through no-op when capability is inactive OR the call has
        no real plugin frame (empty chain = framework/system origin, trusted)."""
        if not self._capability_active:
            return author, author_id, None
        chain = current_caller_chain()
        if not chain:
            return author, author_id, None
        real = chain[-1]
        grant = self._capability_grants.get(real.name, {})
        verdict = evaluate_capability(
            real, chain, author, author_id, grant, _asserted_identity.get()
        )
        if not verdict.allowed:
            self._logger.warning("[CAPABILITY] DENY: %s", verdict.reason)
            self._emit_identity_audit(
                real, verdict.author, verdict.author_id, chain, verdict, True
            )
            raise CapabilityException(verdict.reason)
        if verdict.is_assertion:
            self._emit_identity_audit(
                real, verdict.author, verdict.author_id, chain, verdict, False
            )
        return verdict.author, verdict.author_id, verdict.asserted

    def _emit_identity_audit(
        self, real, asserted_author, asserted_author_id, chain, verdict, denied
    ) -> None:
        """Emit the audit event for an asserted (or denied) identity claim onto
        the internal bus, best-effort, with per-(real, asserted, denied) window
        suppression (Section 13, the audit half of the Step-5 reject suppression).

        First emit per key per ``IDENTITY_AUDIT_WINDOW`` fires the event; in-window
        repeats only bump a counter (NO event); the next emit after the window
        carries the ``suppressed`` count -- so across an ACTIVE window the volume
        is preserved and a hot impersonation or a denied-assertion flood cannot
        spam the stream. (A burst that fully STOPS leaves its final count unflushed
        until the next emit for that key; the deferred background sweep would flush
        it -- same tail tradeoff as the reject-log suppression.) Never raises
        (best-effort): a suppression-state fault must not break the gate.

        Suppression key = ``(real.uuid, asserted-name-or-None, denied)``. The
        asserted NAME is kept ONLY on the ALLOW path, where it is operator-bounded
        (a grant + a genuine chain frame / an explicit-list entry), so distinct
        legitimate impersonations are tracked separately. On the DENY path the
        name is CALLER-SUPPLIED and unbounded (an in-process plugin can vary it
        every call), so it is dropped from the key -- otherwise a distinct-name
        flood would mint a fresh key per call and escape both the window
        suppression AND the keyspace bound. All of ``real``'s denied assertions
        therefore collapse to ONE suppressed stream (the useful signal: "real keeps
        attempting assertions it cannot make"); the first emit still carries the
        actual name + reason, and ``suppressed`` carries the volume.
        """
        try:
            key = (real.uuid, None if denied else asserted_author, denied)
            now = time.monotonic()
            st = self._identity_audit_log.get(key)
            if st is not None and (now - st["last_emit"]) < IDENTITY_AUDIT_WINDOW:
                # In-window repeat: collapse it; the count rides the next
                # post-window emit for this key.
                st["suppressed"] += 1
                return
            suppressed = st["suppressed"] if st is not None else 0
            # Emit BEFORE resetting the window state: if _internal_emit is skipped
            # (a re-entrant emit hitting the depth guard) or raises, the
            # accumulated `suppressed` count then survives to the next emit rather
            # than being reset away.
            self._internal_emit(
                "_core/security/identity_asserted",
                real_caller=real.name,
                real_caller_id=real.uuid,
                asserted=asserted_author,
                asserted_id=asserted_author_id,
                denied=denied,
                reason=verdict.reason,
                chain=[f.name for f in chain],
                suppressed=suppressed,
                ts=time.time(),
            )
            self._identity_audit_log[key] = {"last_emit": now, "suppressed": 0}
            # Keyspace safety net. With the deny-path name stripped from the key
            # above, the keyspace is config-bounded (one deny key per real plugin;
            # allow keys bounded by grants / chain depth), so this prune is no
            # longer load-bearing against a flood -- it just drops stale
            # (window-elapsed) entries if the dict ever grows past the cap. A stale
            # entry only exists to carry its count to a NEXT emit that, for an
            # inactive key, never comes -- same tail tradeoff as burst-then-stop.
            if len(self._identity_audit_log) > _IDENTITY_AUDIT_MAX_KEYS:
                for k, e in list(self._identity_audit_log.items()):
                    if (now - e["last_emit"]) >= IDENTITY_AUDIT_WINDOW:
                        del self._identity_audit_log[k]
        except Exception:
            pass

    async def _call_endpoint(
        self,
        func: Callable,
        args: Any,
        call_chain: tuple = (),
        request: Optional[Request] = None,
    ) -> Any:
        """Call endpoint function handling sync/async and arg shapes.

        PR3 Stage A: when ``request`` is provided AND ``request.kind`` is
        an event kind (``"publish_event"`` / ``"request_event"``), the
        handler receives a single positional ``Event`` argument instead of
        the unpacked ``args`` shape used by the execute path. Sync event
        handlers are dispatched on the dedicated SyncDispatcher executor
        via ``run_in_executor`` (Q17 + C3), NOT the shared
        ``_plugin_executor``. The execute path (``request is None`` OR
        ``request.kind == "execute"``) takes ZERO new code paths.
        """
        # Caller identity: stamp the identity of the plugin we are about
        # to enter so its own callbacks into execute/publish read it as the
        # innermost caller. Identity comes from the RESOLVED plugin instance
        # bound to ``func`` (``func.__self__``), NOT request.target_plugin_uuid
        # -- the latter is None whenever the caller addressed the target by name
        # only (the dominant case). The bound method's owner is the exact plugin
        # whose code runs, so it carries both the real name and the real uuid.
        # The sync seed is captured HERE on the loop thread (the worker can't
        # see the async ContextVar) and written into the worker threadlocal.
        _target = getattr(func, "__self__", None)
        _tname = getattr(_target, "plugin_name", None)
        _id_active = self._identity_active and _tname is not None
        ident = (
            CallerIdentity(_tname, getattr(_target, "plugin_uuid", None))
            if _id_active else None
        )
        _sync_seed = seeded_sync_chain(_id_active, ident)

        # Step 3d: IN (delivery) admit, the single choke point for non-stream
        # dispatch (execute + event handlers; streams have their own producers).
        # Charged BEFORE entering the target so a dry IN-set rejects without
        # invoking the handler. cost 1.0; sub-dispatch uses the sub IN-set
        # (request.origin_sub_uuid), else the endpoint IN-set. Uses the in-scope
        # _tname (the resolved target) and a FRESH now. Raising here is caught by
        # _process_request's except -> _set_request_result(error): the 1:1 caller
        # sees it (degraded to RequestException across the boundary), a publish
        # 1:N per-sub reject is swallowed (the sub is skipped, publish continues).
        if request is not None and _tname is not None:
            dry = self._rl_admit_in(
                _tname,
                request.target_method,
                request.origin_sub_uuid,
                1.0,
                time.monotonic(),
            )
            if dry is not None:
                self._rl_reject(dry)

        # PR3 Stage A: kind-aware Event branch. Only fires for event
        # kinds; the execute path (kind="execute" or no request) falls
        # through to the original implementation untouched.
        if request is not None and request.kind in (
            "publish_event",
            "request_event",
        ):
            event = Event.from_request(request)

            if asyncio.iscoroutinefunction(func):
                # Async handlers awaited directly on the main event loop.
                with caller_chain_scope(ident, _id_active):
                    return await func(event)

            # Sync event handlers run on the dedicated SyncDispatcher
            # executor (Q17 + C3 + C8). run_in_executor pattern — NOT
            # submit + done_callback — so the awaiting fan-out task is
            # naturally long-lived and integrates with task_list / the
            # 30s shutdown drain.
            def _tracked_event(ev):
                _sync_call_chain.chain = call_chain
                if _sync_seed is not None:
                    _sync_identity_chain.chain = _sync_seed
                try:
                    return func(ev)
                finally:
                    _sync_call_chain.chain = ()
                    if _sync_seed is not None:
                        _sync_identity_chain.chain = ()

            return await self.main_event_loop.run_in_executor(
                self.sync_dispatcher.executor, _tracked_event, event
            )

        # Execute path — unchanged from PR2 behavior.
        if asyncio.iscoroutinefunction(func):
            with caller_chain_scope(ident, _id_active):
                if isinstance(args, tuple):
                    return await func(*args)
                if isinstance(args, dict):
                    return await func(**args)
                if args is None:
                    return await func()
                return await func(args)

        # sync function -> threadpool, propagate call chain for cycle detection
        def _tracked(*a, **kw):
            _sync_call_chain.chain = call_chain
            if _sync_seed is not None:
                _sync_identity_chain.chain = _sync_seed
            try:
                return func(*a, **kw)
            finally:
                _sync_call_chain.chain = ()
                if _sync_seed is not None:
                    _sync_identity_chain.chain = ()

        if isinstance(args, tuple):
            return await self.main_event_loop.run_in_executor(
                self._plugin_executor, _tracked, *args
            )
        if isinstance(args, dict):
            return await self.main_event_loop.run_in_executor(
                self._plugin_executor, functools.partial(_tracked, **args)
            )
        if args is None:
            return await self.main_event_loop.run_in_executor(
                self._plugin_executor, _tracked
            )
        return await self.main_event_loop.run_in_executor(
            self._plugin_executor, _tracked, args
        )

    # @async_handle_errors(None)
    async def _process_request_stream(self, request: GeneratorRequest) -> None:
        """Process a request by invoking the target plugin method.

        B-073 Session 2 Step 2: ``finally`` block evicts the
        GeneratorRequest from ``self.requests`` on every completion path
        (success, error, cancellation). Symmetric with ``_process_request``
        for non-stream Requests. Replaces the ``cleanup_requests``
        polling reap (killed in Step 4). Sync GIL-atomic ``pop``;
        ``_pop_plugin_under_lock`` snapshots iteration so concurrent
        eviction never trips dict-mutation-during-iteration.

        ``GeneratorRequest.set_collected`` (utils.py B-002 logic)
        continues to be called by the consumer side — it cancels the
        producer task + pushes EndOfQueue sentinel, distinct from
        eviction. Both fire on completion: producer-side finally pops
        from ``self.requests``; consumer-side ``set_collected`` handles
        producer-task lifecycle. Symmetric, single-source-of-truth per
        concern.
        """
        try:
            plugin_name = request.target_plugin
            function_name = request.target_method

            # PR3 Stage A: same requester_id-aware lookup as
            # _process_request (C18). None on execute-path Requests →
            # falls back to author_id.
            requester = request.requester_id or request.author_id
            plugin, endpoint, node = await self.find_endpoint(
                request.target_method,
                request.target_hosts,
                request.blocked_hosts,
                request.target_plugin_uuid,
                requester,
                request.target_plugin,
            )

            if not plugin:
                await self._set_gen_request_result(
                    request, f"Endpoint {function_name} not found", True
                )
                return

            # Stage O: readiness gate (stream variant). Same skip rules
            # as _process_request — remote plugins and self-calls bypass.
            if isinstance(plugin, Plugin) and plugin.plugin_uuid != requester:
                try:
                    await self._wait_for_plugin_ready(plugin)
                except asyncio.TimeoutError:
                    timeout = getattr(
                        self,
                        "plugin_ready_timeout",
                        DEFAULT_PLUGIN_READY_TIMEOUT,
                    )
                    await self._set_gen_request_result(
                        request,
                        f"Plugin {plugin.plugin_name!r} not ready within "
                        f"{timeout}s",
                        True,
                    )
                    return

            host_label = (
                f"(local) {self.hostname}"
                if isinstance(plugin, Plugin)
                else f"{node.IP}#{node.hostname}"
            )
            self._logger.debug(
                f"Found {plugin_name} (ID: {plugin.plugin_uuid}) for Request with ID {request.id} on host {host_label}"
            )

            if isinstance(plugin, RemotePlugin):
                # Stamp _is_remote BEFORE the network check (cycle 1
                # HIGH-1) so the rebuild drain catches in-flight
                # streaming-remote requests via the filter. Symmetry
                # with the non-stream path's stamp.
                request._is_remote = True
                # C-092: symmetry with the non-stream path —
                # _mark_node_dead's fast-fail filter compares this
                # against the dead-peer hostname.
                request.target_host = node.hostname
                # Snapshot nm. Per Commit 2b cycle 3 HIGH-A + HIGH-β:
                # mid-rebuild self.network is None; resolve the
                # generator request with an error so the consumer sees
                # a clean RequestException via B-044 chain rather than
                # hanging on an empty queue. Also gate on
                # ``is_ready=False`` to cover the post-rebuild window
                # where NM has been assigned but ``start()`` hasn't
                # completed (cycle 6 fresh-eyes MED — symmetry with
                # _process_request guard).
                nm = self.network
                if nm is None or not getattr(nm, "is_ready", False):
                    await self._set_gen_request_result(
                        request,
                        "Network unavailable mid-rebuild",
                        True,
                    )
                    return
                async for result in nm.execute_remote_stream(
                    IP=node.IP,
                    plugin=plugin_name,
                    method=function_name,
                    args=request.args,
                    plugin_uuid=request.target_plugin_uuid,
                    author=f"{self.hostname} - {request.author}#{request.author_id}",
                    author_id=request.author_id,
                    # R2-LL-2: send the timeout DURATION only — see the
                    # matching note on the non-stream execute_remote call
                    # above for the peer-clock-skew rationale.
                    timeout=request.timeout_duration,
                    request_id=request.id,
                ):
                    await request.queue.put((result, False, False))

            else:
                # if not plugin.remote and request.author_id:
                #    await self._set_request_result(request, NetworkRequestException(f"Plugin {plugin_name} is not accessable anymore"), True)
                #    return
                # PR2: internal_name is optional in plugin_config; defaults to
                # access_name (the dict key, also the request target_method).
                internal_name = endpoint.get("internal_name") or function_name
                func = getattr(plugin, internal_name, None)
                if not callable(func):  # or not inspect.isfunction(func):
                    # await request.queue.put((result, False, False))
                    await self._set_gen_request_result(
                        request,
                        f"Function {function_name}({internal_name}) not found in plugin {plugin_name}",
                        True,
                    )
                    return

                # Caller identity: stamp the target plugin's identity for
                # the generator's lifetime (its code runs the plugin's). Local
                # branch only -- a RemotePlugin stream runs on the peer and is
                # gated by Nodes-IN there, not a local identity here. Identity
                # comes from the resolved ``plugin`` instance (real name + uuid),
                # NOT request.target_plugin_uuid (None on name-only addressing).
                # The sync seed is captured on the loop and written into the
                # worker by _next_with_chain below.
                _stream_active = self._identity_active
                _stream_ident = (
                    CallerIdentity(plugin.plugin_name, plugin.plugin_uuid)
                    if _stream_active else None
                )
                _stream_seed = seeded_sync_chain(_stream_active, _stream_ident)

                if asyncio.iscoroutinefunction(func):
                    await self._set_gen_request_result(
                        request,
                        f"For Request {request.id}: The method you requested is a non-generator async function. Use execute for non-generators",
                        True,
                    )
                    return

                # Step 3d: IN (delivery) admit for the stream OPEN, charged ONCE
                # at cost = stream_weight (Section 7, IN-only) before the first
                # pull. Gated on func actually being a generator so the
                # coroutine-error path above and any sync non-generator callable
                # never charge. Reject by resolving the gen-request with an error
                # (mirrors the sibling guards); the consumer sees a clean
                # RequestException. The OUT admit already charged 1 at open
                # (attempt-vs-delivery): a dry IN-set still spent the OUT token.
                if inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(
                    func
                ):
                    _w = endpoint.get("stream_weight") if isinstance(endpoint, dict) else None
                    # Defensive belt: validate_stream_weight already fails LOUD at
                    # build, but guard the float() so a value that slipped through
                    # (post-build mutation / pre-rebuild race) names the endpoint
                    # instead of an opaque TypeError deep in the producer.
                    try:
                        _cost = float(_w) if _w is not None else 1.0
                    except (TypeError, ValueError):
                        await self._set_gen_request_result(
                            request,
                            f"stream_weight for {plugin.plugin_name}.{function_name} "
                            f"is not numeric: {_w!r}",
                            True,
                        )
                        return
                    _dry = self._rl_admit_in(
                        plugin.plugin_name,
                        function_name,
                        request.origin_sub_uuid,
                        _cost,
                        time.monotonic(),
                    )
                    if _dry is not None:
                        await self._set_gen_request_result(
                            request, self._rl_reject_message(_dry, _cost), True
                        )
                        return

                if inspect.isasyncgenfunction(func):
                    with caller_chain_scope(_stream_ident, _stream_active):
                        if isinstance(request.args, tuple):
                            async for result in func(*request.args):
                                await request.queue.put((result, False, False))
                        elif isinstance(request.args, dict):
                            async for result in func(**request.args):
                                await request.queue.put((result, False, False))
                        elif request.args is None:
                            async for result in func():
                                await request.queue.put((result, False, False))
                        else:
                            async for result in func(request.args):
                                await request.queue.put((result, False, False))

                elif inspect.isgeneratorfunction(func):
                    if isinstance(request.args, tuple):
                        generator = func(*request.args)
                    elif isinstance(request.args, dict):
                        generator = func(**request.args)
                    elif request.args is None:
                        generator = func()
                    else:
                        generator = func(request.args)

                    # B-041 fix: thread the caller's sync call chain
                    # into the threadpool worker before each next() so
                    # cycle detection works for sync generators that
                    # call execute_sync internally. The chain comes
                    # from request._call_chain (stamped by
                    # execute_stream_sync); falls back to () for
                    # async-loop callers that bypass the sync wrapper.
                    #
                    # Switched from asyncio.to_thread (default loop
                    # executor) to self._plugin_executor — the
                    # framework's dedicated pool for sync ENDPOINT
                    # methods, matching _call_endpoint's sync branch.
                    # The default pool was a pre-existing inconsistency:
                    # sync gen endpoints competed with framework-
                    # internal default-pool work and risked starvation.
                    # NOT sync_dispatcher.executor — that's for sync
                    # SUBSCRIBER handlers (Q17 + C3) and used by
                    # request_event_stream, not endpoint dispatch.
                    chain = getattr(request, "_call_chain", ())

                    def _next_with_chain(g, sent, ch):
                        _sync_call_chain.chain = ch
                        if _stream_seed is not None:
                            _sync_identity_chain.chain = _stream_seed
                        try:
                            return next(g, sent)
                        finally:
                            _sync_call_chain.chain = ()
                            if _stream_seed is not None:
                                _sync_identity_chain.chain = ()

                    sentinel = object()
                    while True:
                        # W2-F5: honour the per-call timeout on the
                        # sync-gen branch. Sibling block in
                        # ``request_event_stream`` (core.py ~5691-5709)
                        # already wraps ``run_in_executor`` with
                        # ``asyncio.wait_for``; sync-gen was the outlier.
                        # Without this wrap a slow sync producer can hang
                        # the asyncio task indefinitely.
                        executor_call = self.main_event_loop.run_in_executor(
                            self._plugin_executor,
                            _next_with_chain,
                            generator,
                            sentinel,
                            chain,
                        )
                        if request.timeout_duration is not None:
                            remaining = (
                                request.timeout_duration
                                - (time.time() - request.created_at)
                            )
                            if remaining <= 0:
                                await self._set_gen_request_result(
                                    request,
                                    f"Request {request.id} timed out (sync-gen branch)",
                                    True,
                                )
                                return
                            result = await asyncio.wait_for(
                                executor_call, timeout=remaining
                            )
                        else:
                            result = await executor_call
                        if result is sentinel:
                            break
                        await request.queue.put(
                            (result, False, False)
                        )

                else:
                    await self._set_gen_request_result(
                        request,
                        f"For Request {request.id}: The method you requested is a non-generator sync function. Use execute for non-generators",
                        True,
                    )
                    return
                    # result = await self.main_event_loop.run_in_executor(self._plugin_executor, func, request.args)

            await self._set_gen_request_result(request)

        except BaseException as e:
            # C-048: catch BaseException (not just Exception) so a
            # CancelledError that propagates through this function
            # still gets a chance to resolve the future before
            # exiting. The previous ``except Exception`` left the
            # consumer hanging on an unresolved future when the
            # producer task was cancelled (the commented-out
            # @async_handle_errors decorator above the def used to
            # paper over the symptom for non-Cancel errors only).
            if not request._future.done():
                try:
                    await self._set_gen_request_result(
                        request,
                        f"Stream request {request.id} aborted: "
                        f"{type(e).__name__}: {e}",
                        True,
                    )
                except Exception:
                    # Best-effort: we're already mid-cancellation /
                    # mid-shutdown. The finally below still pops the
                    # request entry so the framework state stays clean.
                    pass
            # Re-raise so a CancelledError propagates to the task
            # supervisor (otherwise the framework swallows
            # cancellation, which is incorrect).
            if isinstance(e, asyncio.CancelledError):
                raise
            # For regular Exception, do not re-raise — preserves the
            # original "safety-net" semantics (consumer sees the error
            # via the resolved future, not via an unhandled task
            # exception).
        finally:
            # B-073 Session 2 Step 2: done-callback eviction. Symmetric
            # with ``_process_request``'s finally — pop on any completion
            # path. Sync, GIL-atomic, idempotent.
            self.requests.pop(request.id, None)

    async def _process_request_event_stream(
        self,
        request: GeneratorRequest,
        target_plugin: Plugin,
        endpoint: dict,
        event_meta: Event,
        timeout: Optional[float] = None,
        caller_chain: Optional[tuple] = None,
        verbose_notifier: bool = False,
    ) -> None:
        """Producer for request_event_stream LOCAL fan-out (B-054 fix).

        Mirrors _process_request_stream but for the topic-based
        streaming path. Iterates the handler (async or sync generator),
        wraps the first chunk in Event metadata (LOCKED I), and pushes
        chunks into request.queue. The consumer side
        (request_event_stream) reads from request.get_queue_stream()
        and yields to the caller.

        Spawned via _spawn_tracked, so close()'s 30s drain catches
        in-flight streams and pop_plugin's pending-request walk can
        fail the GeneratorRequest entry.

        timeout is passed as a parameter (NOT read from
        request.timeout_duration which is intentionally None to disable
        get_queue_stream's redundant consumer-side timeout enforcement
        — see consumer-site comment in request_event_stream).

        B-073 Session 2 Step 2: ``finally`` block evicts the
        GeneratorRequest from ``self.requests`` on every completion path
        (success, RequestException, generic Exception). Symmetric with
        ``_process_request`` and ``_process_request_stream``. Sync
        GIL-atomic ``pop``.
        """
        try:
            internal = endpoint.get("internal_name") or request.target_method
            func = getattr(target_plugin, internal, None)
            if func is None or not (
                inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(func)
            ):
                # Defense-in-depth — request_event_stream's consumer
                # body checks this before spawning, so this branch is
                # normally unreachable.
                await self._set_gen_request_result(
                    request,
                    "request_event_stream: handler is not a generator function",
                    True,
                )
                return

            # Step 3d: IN (delivery) admit for the streaming SUB-dispatch open,
            # charged ONCE at cost = stream_weight before the first pull (and
            # before the phase="first_chunk" emit, preserving the Event-first
            # invariant: a throttled stream rejects before any chunk). func is
            # confirmed a generator above. Sub-dispatch -> request.origin_sub_uuid
            # selects the sub IN-set. Reject by resolving the gen-request with an
            # error (the consumer sees a clean RequestException).
            _w = endpoint.get("stream_weight") if isinstance(endpoint, dict) else None
            # Defensive belt (see _process_request_stream): name the endpoint
            # rather than crash the producer with an opaque TypeError.
            try:
                _cost = float(_w) if _w is not None else 1.0
            except (TypeError, ValueError):
                await self._set_gen_request_result(
                    request,
                    f"stream_weight for {target_plugin.plugin_name}."
                    f"{request.target_method} is not numeric: {_w!r}",
                    True,
                )
                return
            _dry = self._rl_admit_in(
                target_plugin.plugin_name,
                request.target_method,
                request.origin_sub_uuid,
                _cost,
                time.monotonic(),
            )
            if _dry is not None:
                await self._set_gen_request_result(
                    request, self._rl_reject_message(_dry, _cost), True
                )
                return

            # Q8: timeout = whole-stream budget. Tracked via per-chunk
            # asyncio.wait_for with the residual deadline.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout if timeout is not None else None
            # B-074 Step 10: producer-side first-chunk timing baseline.
            producer_t0 = loop.time()

            def _residual() -> Optional[float]:
                if deadline is None:
                    return None
                rem = deadline - loop.time()
                if rem <= 0:
                    raise RequestException(
                        f"request_event_stream timed out after "
                        f"{timeout}s (whole-stream budget per Q8)"
                    )
                return rem

            first = True

            # Caller identity: identity of the subscriber plugin whose
            # streaming handler we are about to pull. Stamped around each
            # generator pull (where the plugin's code runs), not across the
            # queue.put between pulls (framework code).
            _es_active = self._identity_active
            _es_ident = (
                CallerIdentity(
                    target_plugin.plugin_name, target_plugin.plugin_uuid
                )
                if _es_active else None
            )
            _es_seed = seeded_sync_chain(_es_active, _es_ident)

            if inspect.isasyncgenfunction(func):
                ait = func(event_meta).__aiter__()
                try:
                    while True:
                        rem = _residual()
                        try:
                            with caller_chain_scope(_es_ident, _es_active):
                                if rem is None:
                                    chunk = await ait.__anext__()
                                else:
                                    chunk = await asyncio.wait_for(
                                        ait.__anext__(), timeout=rem
                                    )
                        except StopAsyncIteration:
                            break
                        except asyncio.TimeoutError as e:
                            raise RequestException(
                                f"request_event_stream timed out after "
                                f"{timeout}s (whole-stream budget per Q8)"
                            ) from e
                        if first:
                            first = False
                            wrapped = Event(
                                topic=event_meta.topic,
                                payload=chunk,
                                author=event_meta.author,
                                author_id=event_meta.author_id,
                                author_host=event_meta.author_host,
                                subscription_id=event_meta.subscription_id,
                                timestamp=event_meta.timestamp,
                            )
                            # B-073 Step 8 emit: event streamed first chunk.
                            self._internal_emit(
                                "_core/event/streamed",
                                publisher=event_meta.author,
                                topic=event_meta.topic,
                                phase="first_chunk",
                                ts=time.time(),
                            )
                            # B-074 Step 10 verbose log: first chunk timing.
                            if verbose_notifier:
                                self._logger.debug(
                                    "request_event_stream topic=%r first chunk "
                                    "yielded after %.3fs",
                                    event_meta.topic,
                                    loop.time() - producer_t0,
                                )
                            await request.queue.put((wrapped, False, False))
                        else:
                            await request.queue.put((chunk, False, False))
                finally:
                    with contextlib.suppress(Exception):
                        # Generator cleanup may run the plugin's finally blocks
                        # (which could call execute); keep identity stamped.
                        with caller_chain_scope(_es_ident, _es_active):
                            await ait.aclose()
            else:
                # Sync generator branch — chain propagation +
                # sync_stream_dispatcher.executor (C-072: dedicated
                # stream pool so a slow streaming generator cannot
                # starve the RPC sync-subscriber pool which uses
                # sync_dispatcher.executor). Both pools are
                # SyncDispatcher instances managed by Plexus.
                sentinel = object()
                gen = func(event_meta)
                # Mirrors current inline code (core.py:4780-4784):
                # request_event_stream_sync passes non-None caller_chain;
                # Plugin.request_event_stream (utils.py:1572) does NOT,
                # so async callers leave it as None — fallback reads
                # the loop thread's threadlocal (always () in current
                # code, kept defensively for forward-compat).
                stream_chain = (
                    caller_chain
                    if caller_chain is not None
                    else getattr(_sync_call_chain, "chain", ())
                )

                def _next_with_chain(g, sent, ch):
                    _sync_call_chain.chain = ch
                    if _es_seed is not None:
                        _sync_identity_chain.chain = _es_seed
                    try:
                        return next(g, sent)
                    finally:
                        _sync_call_chain.chain = ()
                        if _es_seed is not None:
                            _sync_identity_chain.chain = ()

                try:
                    while True:
                        rem = _residual()
                        fut = loop.run_in_executor(
                            self.sync_stream_dispatcher.executor,
                            _next_with_chain,
                            gen,
                            sentinel,
                            stream_chain,
                        )
                        try:
                            if rem is None:
                                chunk = await fut
                            else:
                                chunk = await asyncio.wait_for(fut, timeout=rem)
                        except asyncio.TimeoutError as e:
                            raise RequestException(
                                f"request_event_stream timed out after "
                                f"{timeout}s (whole-stream budget per Q8)"
                            ) from e
                        if chunk is sentinel:
                            break
                        if first:
                            first = False
                            wrapped = Event(
                                topic=event_meta.topic,
                                payload=chunk,
                                author=event_meta.author,
                                author_id=event_meta.author_id,
                                author_host=event_meta.author_host,
                                subscription_id=event_meta.subscription_id,
                                timestamp=event_meta.timestamp,
                            )
                            # B-073 Step 8 emit: event streamed first chunk.
                            self._internal_emit(
                                "_core/event/streamed",
                                publisher=event_meta.author,
                                topic=event_meta.topic,
                                phase="first_chunk",
                                ts=time.time(),
                            )
                            # B-074 Step 10 verbose log: first chunk timing.
                            if verbose_notifier:
                                self._logger.debug(
                                    "request_event_stream topic=%r first chunk "
                                    "yielded after %.3fs",
                                    event_meta.topic,
                                    loop.time() - producer_t0,
                                )
                            await request.queue.put((wrapped, False, False))
                        else:
                            await request.queue.put((chunk, False, False))
                finally:
                    with contextlib.suppress(Exception):
                        gen.close()

            # Normal completion — push EndOfQueue terminator + resolve future.
            await self._set_gen_request_result(request)
        except RequestException as e:
            if not request._future.done():
                await self._set_gen_request_result(request, str(e), True)
        except BaseException as e:
            # R2-AA-1: mirror the C-048 fix in _process_request_stream.
            # Catch BaseException (not just Exception) so a CancelledError
            # that propagates through this producer still resolves the
            # future + puts an EndOfQueue sentinel on request.queue before
            # we propagate. Without this, the consumer in
            # request_event_stream hangs forever on an unresolved future.
            if not request._future.done():
                try:
                    await self._set_gen_request_result(
                        request,
                        f"Stream request {request.id} aborted: "
                        f"{type(e).__name__}: {e}",
                        True,
                    )
                except Exception:
                    # Best-effort: mid-cancellation / mid-shutdown. The
                    # finally below still pops the request entry so
                    # framework state stays clean.
                    pass
            # Re-raise CancelledError so the task supervisor sees the
            # cancellation (swallowing it would mask shutdown). Plain
            # Exception preserves the legacy "safety-net" semantics —
            # consumer sees the error via the resolved future, not via
            # an unhandled task exception.
            if isinstance(e, asyncio.CancelledError):
                raise
        finally:
            # B-073 Session 2 Step 2: done-callback eviction. Symmetric
            # with ``_process_request`` and ``_process_request_stream``
            # finally blocks — pop the GeneratorRequest from
            # ``self.requests`` on every completion path. Sync, GIL-atomic,
            # idempotent.
            self.requests.pop(request.id, None)

    @async_handle_errors(None)
    async def _set_request_result(
        self, request: Request, result: Any, error: bool = False
    ) -> None:
        """Set the result of a request."""
        if isinstance(result, asyncio.Future):
            try:
                result = await result
            except Exception as e:
                # B-013 fix: a returned Future whose await raises must
                # still resolve the request — otherwise @async_handle_errors
                # swallows here and the caller hangs on request._future.
                # CancelledError (BaseException) propagates uncaught so
                # task cancellation tears down cleanly.
                await request.set_result(f"{type(e).__name__}: {e}", True)
                return
        await request.set_result(result, error)

    @async_handle_errors(None)
    async def _set_gen_request_result(
        self, request: GeneratorRequest, result: Any = None, error: bool = False
    ) -> None:
        """Set the result of a request."""

        await request.set_result(result, error)

    def _spawn_tracked(self, coro, *, name: str) -> asyncio.Task:
        """Create + register a tracked async task (B-047 fix).

        Must be called from the event loop thread — uses
        asyncio.create_task which requires a running loop in the
        current thread. All current call sites are inside async def
        methods that always run on the loop thread; sync entry points
        (create_request_sync, publish_event_sync) bridge via
        run_coroutine_threadsafe so the actual _spawn_tracked call
        still happens on the loop. Calling from a worker thread
        raises RuntimeError("no running event loop").

        Returns the task. Callers should hold the returned reference
        if they need it (e.g. request._producer_task = task); the
        framework already holds a strong reference via self.task_list
        so the task will not be GC'd mid-flight (per asyncio docs:
        save a strong reference to created tasks).

        The done_callback evicts from self.task_list on completion
        (any terminal state — normal return, raise, cancel),
        increments tasks_completed_total, and appends a record to
        self.recent_completed (bounded deque). cancelled() is
        checked BEFORE exception() because exception() raises
        CancelledError on cancelled tasks. The whole introspection
        block is wrapped in try/except so a pathological failure
        cannot break asyncio's internal callback dispatch.

        C-062: ``asyncio.create_task`` inherits the caller's
        ContextVar state, so a task spawned mid-emit would start with
        ``_EMIT_DEPTH > 0`` and hit ``_MAX_EMIT_DEPTH`` early. The
        ``_emit_depth_isolated`` wrapper below resets the depth at task
        entry so each spawned task gets a fresh emit budget. The
        wrapper is a thin pass-through; the task's externally-visible
        behaviour is identical except for the ContextVar isolation.
        """
        async def _emit_depth_isolated():
            token = _EMIT_DEPTH.set(0)
            try:
                # Caller-identity note: the caller-identity chain is
                # deliberately NOT isolated here. create_task copies the parent
                # context, and every _spawn_tracked callee is a PER-OPERATION
                # task (request dispatch, fan-out delivery, stream producer), so
                # the copied chain is genuine caller ancestry -- exactly what the
                # capability "ancestor" scope and exemption propagation read.
                # Isolating would sever it (a sync-bridge / fan-out target would
                # lose its caller). _EMIT_DEPTH is a recursion guard and DOES
                # reset; identity is ancestry and must not.
                return await coro
            finally:
                _EMIT_DEPTH.reset(token)
        task = asyncio.create_task(_emit_depth_isolated(), name=name)
        self.task_list.add(task)
        self.tasks_started_total += 1
        started = time.monotonic()

        def _on_done(t: asyncio.Task, _name=name, _started=started) -> None:
            self.task_list.discard(t)
            self.tasks_completed_total += 1
            err: Optional[str] = None
            try:
                if t.cancelled():
                    err = "cancelled"
                else:
                    exc = t.exception()
                    if exc is not None:
                        err = f"{type(exc).__name__}: {exc}"
            except Exception:
                err = "introspection_failed"
            self.recent_completed.append(
                {
                    "name": _name,
                    "started": _started,
                    "completed": time.monotonic(),
                    "error": err,
                }
            )

        task.add_done_callback(_on_done)
        return task

    def _check_not_loop_thread(self, method_name: str) -> None:
        """C-004 helper: raise RuntimeError if the sync mirror is invoked
        from the framework's event-loop thread.

        Every sync mirror (``execute_sync``, ``publish_event_sync``,
        ``request_event_sync``, ``request_event_stream_sync``,
        ``create_request_sync``, ``create_gen_request_sync``) ends in
        ``asyncio.run_coroutine_threadsafe(coro, self.main_event_loop)
        .result()``. If the calling thread IS ``self.main_event_loop``'s
        thread, ``.result()`` blocks waiting for the loop to advance the
        coroutine — but the loop is blocked waiting for ``.result()``.
        Deadlock.

        Worker threads (the framework's ``_plugin_executor`` /
        ``sync_dispatcher.executor`` pools, or any thread the user has
        spawned) have NO running loop — ``get_running_loop`` raises
        ``RuntimeError`` and this helper returns cleanly. The single
        forbidden case is a coroutine on ``main_event_loop`` calling a
        sync mirror.
        """
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            return  # No running loop = worker thread, fine
        if running is getattr(self, "main_event_loop", None):
            raise RuntimeError(
                f"{method_name} called from the framework event-loop "
                f"thread; would deadlock. Use the async variant from "
                f"this context, or call from a worker thread / sync "
                f"endpoint dispatched via the plugin executor."
            )

    def _spawn_fire_and_forget(
        self, coro, *, name: Optional[str] = None
    ) -> "Optional[asyncio.Task]":
        """Spawn a fire-and-forget task with strong-ref retention.

        Loop-thread only. Holds the task in ``self._fire_and_forget``
        so it cannot be GC'd while pending (per asyncio docs: "Save
        a reference to the result of this function, to avoid a task
        disappearing mid-execution"). Done-callback evicts so the
        set stays bounded.

        Returns None if no event loop is running (shutdown race).
        Safe to call from done-callbacks; no caller-side try/except
        needed for the RuntimeError path.

        Distinct from ``_spawn_tracked``: fire-and-forget tasks do
        NOT join ``task_list`` (no completion metrics, no recent
        record). They participate in ``close()``'s 5s tail-drain
        (separate from task_list's 30s drain) and are cancelled on
        timeout.

        Use for short cleanup work (per-peer publish dereg, NM
        accounting cleanup, advert acks). NOT for fan-out dispatch —
        those go through ``_spawn_tracked``.

        C-062: matches the _EMIT_DEPTH isolation pattern used by
        _spawn_tracked — see that helper for rationale.
        """
        async def _emit_depth_isolated():
            token = _EMIT_DEPTH.set(0)
            try:
                # Caller-identity note: the caller-identity chain is
                # deliberately NOT isolated here. create_task copies the parent
                # context, and every _spawn_tracked callee is a PER-OPERATION
                # task (request dispatch, fan-out delivery, stream producer), so
                # the copied chain is genuine caller ancestry -- exactly what the
                # capability "ancestor" scope and exemption propagation read.
                # Isolating would sever it (a sync-bridge / fan-out target would
                # lose its caller). _EMIT_DEPTH is a recursion guard and DOES
                # reset; identity is ancestry and must not.
                return await coro
            finally:
                _EMIT_DEPTH.reset(token)
        # R4-VV-6 / R4-YY-9: instantiate the wrapper coroutine and bind
        # it to a local variable BEFORE scheduling so we hold a reference
        # on the RuntimeError path. Previously the wrapper was built
        # inline as the call argument; when scheduling raised (no
        # running loop) the wrapper was already instantiated but lost,
        # and only the inner ``coro`` was closed. The leaked wrapper
        # triggered "coroutine was never awaited" RuntimeWarning at GC
        # time. Both wrapper and inner coro are explicitly closed in
        # the except branch below.
        wrapper_coro = _emit_depth_isolated()
        try:
            task = asyncio.create_task(wrapper_coro, name=name)
        except RuntimeError:
            # No running loop — close BOTH the wrapper and the inner coro
            # to avoid "coroutine was never awaited" warnings.
            try:
                wrapper_coro.close()
            except Exception:
                pass
            try:
                coro.close()
            except Exception:
                pass
            return None
        self._fire_and_forget.add(task)
        task.add_done_callback(self._fire_and_forget.discard)
        return task

    # B-073 Session 2 Step 4: ``running_loop`` + ``cleanup_requests``
    # removed. Pre-Step-2 the maintenance loop ticked every
    # ``cleanup_request_interval`` seconds and reaped Request entries
    # whose ``collected`` flag was set. Steps 2+3 replaced the polling
    # reap with done-callback eviction at all 7 framework Request sites
    # (3 producer-finally pops in ``_process_request*`` + 6 outer-finally
    # pops at ``execute``/``request_event``/etc.). The maintenance loop
    # has no work to do — eviction is now O(1) at completion time, no
    # sweep needed. ``cleanup_request_interval`` config knob also
    # removed from ``apply_configvalues`` in utils.py.

    def _validate_host_args(self, hosts, blocked_hosts):
        """Normalize hosts/blocked_hosts and warn on redundant combos.

        Returns (hosts, blocked_hosts) ready to pass to find_endpoint.
        Raises ValueError on structural input errors. Idempotent — safe to
        call on already-normalized values.
        """
        hosts = _normalize_hosts(hosts, param_name="hosts", default="local")
        blocked_hosts = _normalize_hosts(
            blocked_hosts,
            param_name="blocked_hosts",
            default=None,
            is_blocked=True,
        )
        _warn_redundant_host_combos(hosts, blocked_hosts, self._logger)
        return hosts, blocked_hosts

    # One-liner methods for plugin communication
    # @async_handle_errors(default_return=None)
    # async def execute(self, target: str, args: Any = None, author: str = "system", timeout: Optional[float] = None) -> Any:
    @async_log_errors
    async def execute(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Any:
        """
        One-liner to execute a plugin method and get its result with built-in error handling.
        This combines request creation, processing, and result retrieval in one method.

        Args:
            plugin: Name of the target plugin (str).
            method: Endpoint method name on the target plugin (str).
            args: Arguments to pass to the method (tuple, dict, or None).
            plugin_uuid: Optional uuid to disambiguate when multiple plugin instances share a name.
            hosts: Where to run — "any", "local", "remote", a hostname, or a list of hostnames.
            blocked_hosts: Hosts to exclude — same shape as ``hosts``, or None.
            author: The name of the caller (defaults to "system").
            author_id: Caller identifier (defaults to "system").
            timeout: Optional timeout in seconds.

        Returns:
            The result from the plugin method.

        Raises:
            RequestException: when the underlying request reports an error.
        """
        hosts, blocked_hosts = self._validate_host_args(hosts, blocked_hosts)

        # The capability gate, system->hostname rewrite, asserted-identity
        # scope, request creation, await, and eviction all live in the shared
        # _dispatch_request body -- the single capability-gate point for the
        # execute family. execute() validates hosts here (loop-side) and
        # delegates; execute_sync validates worker-side and bridges the same
        # body onto the loop.
        return await self._dispatch_request(
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            author_host,
            request_id,
        )

    @log_errors
    def execute_sync(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Any:
        """
        Synchronous one-liner to execute a plugin method with built-in error handling.

        Args:
            plugin: Name of the target plugin (str).
            method: Endpoint method name on the target plugin (str).
            args: Arguments to pass to the method (tuple, dict, or None).
            plugin_uuid: Optional uuid to disambiguate when multiple plugin instances share a name.
            hosts: Where to run — "any", "local", "remote", a hostname, or a list of hostnames.
            blocked_hosts: Hosts to exclude — same shape as ``hosts``, or None.
            author: The name of the caller (defaults to "system").
            author_id: Caller identifier (defaults to "system").
            timeout: Optional timeout in seconds.

        Returns:
            The result from the plugin method.

        Raises:
            RequestException: when the underlying request reports an error.
        """

        # Phase 2b: if this carrier was poisoned (it gave up its execution
        # permit under saturation/shutdown), fail fast so the call chain
        # unwinds instead of doing more bridge work permit-less.
        if getattr(_held_permit, "poisoned", False):
            raise RequestException(
                "sync bridge gave up its execution permit under "
                "saturation/shutdown; this call chain must unwind (do not "
                "make further sync-bridge calls)."
            )

        # C-004: same-thread deadlock guard. See _check_not_loop_thread
        # for rationale.
        self._check_not_loop_thread("execute_sync")

        hosts, blocked_hosts = self._validate_host_args(hosts, blocked_hosts)

        # The system->hostname rewrite is deliberately NOT done here: the RAW
        # author is carried across the bridge so _dispatch_request can gate the
        # raw claim loop-side (the gate's evaluate_capability branches on
        # author=="system"), THEN rewrite. Rewriting here would hide the claim
        # from the gate.

        # Detect circular sync calls that would deadlock the threadpool
        chain = getattr(_sync_call_chain, "chain", ())
        target = f"{plugin}.{method}"
        if target in chain:
            raise RequestException(
                f"Circular sync call: {' -> '.join(chain)} -> {target}"
            )

        # R2-FF-4: Pool-exhaustion guard. Mirrors _EMIT_DEPTH /
        # _MAX_EMIT_DEPTH for the sync-execute path. A non-circular
        # but deeply nested fan-in of sync calls (>= _MAX_EXECUTE_DEPTH)
        # can fill the sync-endpoint pool before any worker drains,
        # producing a silent deadlock that the cycle-check above
        # cannot detect. Abort here with a typed exception so the
        # caller sees the cause instead of the symptom.
        execute_depth = _EXECUTE_DEPTH.get()
        if execute_depth >= _MAX_EXECUTE_DEPTH:
            self._logger.warning(
                "R2-FF-4 EXECUTE DEPTH EXCEEDED at %d for %s — aborting. "
                "Nested sync execute fan-out exceeded max depth %d; "
                "check call chain for non-circular runaway recursion.",
                execute_depth, target, _MAX_EXECUTE_DEPTH,
            )
            raise RequestException(
                f"Execute depth exceeded: {execute_depth} >= "
                f"{_MAX_EXECUTE_DEPTH} while dispatching {target}. "
                f"Nested sync execute fan-out risks exhausting the "
                f"fixed-size endpoint thread pool."
            )

        depth_token = _EXECUTE_DEPTH.set(execute_depth + 1)
        try:
            # Caller identity: capture the originating sync handler's identity
            # worker-side, re-seat it loop-side across the bridge. The RAW
            # author is passed through; _dispatch_request gates then rewrites
            # loop-side. call_chain carries the sync cycle-detection chain.
            _exec_coro = self._dispatch_request(
                plugin,
                method,
                args,
                plugin_uuid,
                hosts,
                blocked_hosts,
                author,
                author_id,
                timeout,
                author_host,
                request_id,
                call_chain=chain + (target,),
            )
            future = asyncio.run_coroutine_threadsafe(
                self._with_caller_chain(current_caller_chain(), _exec_coro),
                self.main_event_loop,
            )
            # R2-FF-1: bound the worker-thread wait — see create_request_sync.
            request_timeout = timeout[0] if isinstance(timeout, tuple) else timeout
            wait_timeout = (request_timeout + 5.0) if isinstance(request_timeout, (int, float)) else 60.0
            # Phase 2b: route through _bridge_wait so this carrier frees its
            # execution permit while parked (nested work always finds a slot)
            # and re-acquires on resume. _bridge_wait owns cancel-on-timeout.
            return _bridge_wait(future, wait_timeout)
        finally:
            _EXECUTE_DEPTH.reset(depth_token)

    async def _dispatch_request(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
        call_chain: tuple = (),
    ) -> Any:
        """Shared loop-side dispatch body for execute() and execute_sync().

        The single capability-gate point for the execute family: gate the RAW
        author claim, THEN apply the system->hostname rewrite (the gate reasons
        about the raw claim, so the rewrite must follow it), scope the asserted
        identity over the whole dispatch, create the request, await the result,
        raise on error, and evict the request in ``finally``.

        ``call_chain`` is the sync cycle-detection chain (``_sync_call_chain``
        shape: ``"plugin.method"`` strings) stamped onto the request for the
        sync-bridge path. The async ``execute()`` path passes the default
        ``()`` -- equivalent to not setting it, since both ``_call_chain``
        consumers read it via ``getattr(request, "_call_chain", ())``.

        Callers validate hosts BEFORE delegating here (``execute()`` loop-side,
        ``execute_sync()`` worker-side); this body does NOT call
        ``_validate_host_args`` so the sync path does not double-validate /
        double-warn.

        Deadlock-safety: the gate is synchronous loop-side work (dict lookup +
        pure ``evaluate_capability`` + fire-and-forget audit emit); it never
        awaits, acquires a sync-bridge permit, or calls a ``*_sync`` mirror. A
        denied assertion raises ``CapabilityException`` loop-side, which crosses
        the sync bridge through ``future.result()`` exactly like a handler
        ``RequestException``.
        """
        # Gate the RAW author claim BEFORE the system->hostname rewrite (the
        # gate's evaluate_capability branches on author=="system"). No-op when
        # capability is inactive or the call is framework-origin (empty chain).
        author, author_id, asserted = self._gate_author(author, author_id)

        if author == "system":
            author = self.hostname
            author_id = self.hostname

        # asserted is scoped over the whole dispatch so nested calls inherit it
        # (the no-chaining check + Step 3 charge-the-asserted attribution).
        with asserted_identity_scope(asserted):
            # Step 3c: OUT (attempt) admit BEFORE the request is created. Charges
            # plugin_out(asserted-or-caller) + framework_in. Raising here is clean
            # -- no request exists yet, the asserted scope unwinds on raise, and
            # the exception crosses the sync bridge via future.result like the
            # CapabilityException already does.
            dry = self._rl_admit_out(asserted, now=time.monotonic())
            if dry is not None:
                self._rl_reject(dry)
            request = await self.create_request(
                plugin,
                method,
                args,
                plugin_uuid,
                hosts,
                blocked_hosts,
                author,
                author_id,
                timeout,
                author_host,
                request_id,
            )
            # Sync cycle-detection chain; () for the async path (no-op, both
            # consumers getattr-default to ()).
            request._call_chain = call_chain
            try:
                result, error, _ = await request.wait_for_result_async()
                if error:
                    self._logger.warning(
                        "Error executing %s.%s (Req-ID: %s): %s. You can check the logs for this Req-ID.",
                        plugin,
                        method,
                        request.id,
                        result,
                    )
                    raise RequestException(result)
                return result
            finally:
                # B-073 Session 2 Step 3: done-callback eviction. Runs on
                # normal return, RequestException, AND CancelledError. Sync,
                # GIL-atomic, idempotent with the producer-side pop in
                # _process_request.
                self.requests.pop(request.id, None)

    async def _create_gen_request_gated(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
        _post_construct_hook: Optional[Callable[["GeneratorRequest"], None]] = None,
    ) -> GeneratorRequest:
        """Shared loop-side gated construction for the stream entries.

        The single capability-gate point for execute_stream / execute_stream_sync
        (mirrors `_dispatch_request` for the value-returning execute family): gate
        the RAW author claim, THEN apply the system->hostname rewrite, then build
        the GeneratorRequest + spawn its producer INSIDE `asserted_identity_scope`
        so the producer task inherits the asserted identity by ContextVar
        copy-at-`create_task`.

        Construction-only scope is sufficient: the producer task is the only thing
        that dispatches the endpoint and it captures the asserted identity at
        spawn; the consume loop (which pulls already-produced items) dispatches
        nothing and needs no scope.

        Callers validate hosts BEFORE delegating; this body does NOT call
        `_validate_host_args`. `_post_construct_hook` is forwarded to
        `create_gen_request` (the sync path stamps `request._call_chain`
        pre-spawn).

        Deadlock-safety: the gate is synchronous loop-side work (dict lookup +
        pure `evaluate_capability` + fire-and-forget audit emit); it never awaits,
        takes a sync-bridge permit, or calls a `*_sync` mirror. A denied assertion
        raises `CapabilityException` loop-side, which crosses the sync bridge via
        `future.result()` exactly like a handler error.
        """
        # Gate the RAW author claim BEFORE the system->hostname rewrite (the
        # gate's evaluate_capability branches on author=="system"). No-op when
        # capability is inactive or the call is framework-origin (empty chain).
        author, author_id, asserted = self._gate_author(author, author_id)

        if author == "system":
            author = self.hostname
            author_id = self.hostname

        # The producer is spawned inside create_gen_request, so wrapping it in the
        # asserted scope makes the producer inherit the assertion at create_task.
        with asserted_identity_scope(asserted):
            # Step 3c: OUT (attempt) admit BEFORE the gen-request is built (one
            # admit per stream-open, OUT cost 1.0; the stream_weight charge is
            # IN-only, Section 7). Same clean raise point as _dispatch_request.
            dry = self._rl_admit_out(asserted, now=time.monotonic())
            if dry is not None:
                self._rl_reject(dry)
            return await self.create_gen_request(
                plugin,
                method,
                args,
                plugin_uuid,
                hosts,
                blocked_hosts,
                author,
                author_id,
                timeout,
                author_host,
                request_id,
                _post_construct_hook=_post_construct_hook,
            )

    @async_gen_log_errors
    async def execute_stream(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Any:
        """
        One-liner to execute a streaming plugin method and yield results with built-in error handling.
        This combines gen-request creation, processing, and result streaming in one method.

        Args:
            plugin: Name of the target plugin (str).
            method: Endpoint method name on the target plugin (str).
            args: Arguments to pass to the method (tuple, dict, or None).
            plugin_uuid: Optional uuid to disambiguate when multiple plugin instances share a name.
            hosts: Where to run — "any", "local", "remote", a hostname, or a list of hostnames.
            blocked_hosts: Hosts to exclude — same shape as ``hosts``, or None.
            author: The name of the caller (defaults to "system").
            author_id: Caller identifier (defaults to "system").
            timeout: Optional timeout in seconds.

        Yields:
            Each value yielded by the target streaming method.

        Raises:
            RequestException: when the underlying request reports an error.
        """

        hosts, blocked_hosts = self._validate_host_args(hosts, blocked_hosts)

        # Gate + system->hostname rewrite + producer spawn happen in the shared
        # _create_gen_request_gated body (the single gate point for the stream
        # entries). The request assignment stays ABOVE the try below so a
        # gate-deny never reaches the finally with request unbound.
        request = await self._create_gen_request_gated(
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            author_host,
            request_id,
        )
        try:
            async for result, error, _ in request.get_queue_stream():
                if error:
                    self._logger.warning(
                        "Error executing %s.%s (GenReq-ID: %s): %s. You can check the logs for this Req-ID.",
                        plugin,
                        method,
                        request.id,
                        result,
                    )
                    raise RequestException(result)
                yield result
        finally:
            # Mark for cleanup. Runs on normal completion, RequestException,
            # AND CancelledError (e.g. when caller breaks out of `async for`
            # early) — without this, cancelled stream consumers would leave
            # the GeneratorRequest lingering forever.
            await request.set_collected()

    @gen_log_errors
    def execute_stream_sync(
        self,
        plugin: str,
        method: str,
        args: Union[tuple, dict, None] = None,
        plugin_uuid: Optional[str] = None,
        hosts: Union[
            str, list, None
        ] = "any",  # "any", "remote", "local", or list of allowed hosts
        blocked_hosts: Union[
            str, list, None
        ] = None,  # blocked hosts (str keyword, list, or None)
        author: str = "system",
        author_id: str = "system",
        timeout: Union[float, tuple] = None,
        author_host: str = None,
        request_id: str = None,
    ) -> Any:
        """
        Synchronous one-liner to execute a streaming plugin method with built-in error handling.

        Args:
            plugin: Name of the target plugin (str).
            method: Endpoint method name on the target plugin (str).
            args: Arguments to pass to the method (tuple, dict, or None).
            plugin_uuid: Optional uuid to disambiguate when multiple plugin instances share a name.
            hosts: Where to run — "any", "local", "remote", a hostname, or a list of hostnames.
            blocked_hosts: Hosts to exclude — same shape as ``hosts``, or None.
            author: The name of the caller (defaults to "system").
            author_id: Caller identifier (defaults to "system").
            timeout: Optional timeout in seconds.

        Yields:
            Each value yielded by the target streaming method.

        Raises:
            RequestException: when the underlying request reports an error.
        """

        # Phase 2b: poison fail-fast (see execute_sync). Fires on the first
        # next() of this generator.
        if getattr(_held_permit, "poisoned", False):
            raise RequestException(
                "sync bridge gave up its execution permit under "
                "saturation/shutdown; this call chain must unwind (do not "
                "make further sync-bridge calls)."
            )

        # C-004: same-thread deadlock guard. Previously inherited from
        # create_gen_request_sync (which this method no longer calls); added here
        # so a loop-thread caller still fails fast with a clear RuntimeError
        # instead of parking the loop on the construction bridge below.
        self._check_not_loop_thread("execute_stream_sync")

        hosts, blocked_hosts = self._validate_host_args(hosts, blocked_hosts)

        # The system->hostname rewrite is deliberately NOT done here: the RAW
        # author is carried across the bridge so _create_gen_request_gated can
        # gate the raw claim loop-side (the gate branches on author=="system"),
        # THEN rewrite. Rewriting here would hide the claim from the gate.

        # Detect circular sync calls that would deadlock the threadpool
        chain = getattr(_sync_call_chain, "chain", ())
        target = f"{plugin}.{method}"
        if target in chain:
            raise RequestException(
                f"Circular sync call: {' -> '.join(chain)} -> {target}"
            )

        # R2-FF-4: Pool-exhaustion guard — mirror execute_sync. Stream
        # producers compete for the same sync-endpoint pool, so a
        # nested fan-in of execute_stream_sync calls hits the same
        # ceiling. Generator function — note the per-yield depth has
        # already been incremented by this point; the reset in the
        # finally below restores parent-task state.
        execute_depth = _EXECUTE_DEPTH.get()
        if execute_depth >= _MAX_EXECUTE_DEPTH:
            self._logger.warning(
                "R2-FF-4 EXECUTE DEPTH EXCEEDED at %d for %s (stream) — "
                "aborting. Nested sync execute_stream fan-out exceeded "
                "max depth %d.",
                execute_depth, target, _MAX_EXECUTE_DEPTH,
            )
            raise RequestException(
                f"Execute depth exceeded: {execute_depth} >= "
                f"{_MAX_EXECUTE_DEPTH} while dispatching stream {target}."
            )

        # R2-FF-7: pre-stamp request._call_chain via a hook that runs
        # inside create_gen_request BEFORE the producer task spawns.
        # Without this, the producer task can begin executing and read
        # request._call_chain == () before the post-creation stamp
        # lands, bypassing the sync-gen branch's cycle detection.
        # B-041 fix: the chain is the caller's sync chain plus the
        # current target, so a sync→stream→sync cycle (sync caller
        # calls execute_stream_sync, stream handler is a sync gen that
        # calls execute_sync back into the caller) gets caught by
        # _process_request_stream's _next_with_chain and raises
        # "Circular sync call" instead of deadlocking the threadpool.
        new_chain = chain + (target,)

        def _stamp_chain(request):
            request._call_chain = new_chain

        # Bridge the GATED construction loop-side — mirrors execute_sync's inline
        # bridge of _dispatch_request, and deliberately does NOT call
        # create_gen_request_sync (which hard-codes an UNGATED create_gen_request
        # coro): the gate must land loop-side where the re-seated caller chain is
        # visible. Do NOT DRY these two bridges back together.
        coro = self._create_gen_request_gated(
            plugin,
            method,
            args,
            plugin_uuid,
            hosts,
            blocked_hosts,
            author,
            author_id,
            timeout,
            author_host,
            request_id,
            _post_construct_hook=_stamp_chain,
        )
        # Caller identity: re-seat the worker-captured caller chain loop-side so
        # the gate reads the originating handler as the real caller.
        coro = self._with_caller_chain(current_caller_chain(), coro)
        # R2-FF-1: bound the construction wait — see create_request_sync.
        request_timeout = timeout[0] if isinstance(timeout, tuple) else timeout
        wait_timeout = (request_timeout + 5.0) if isinstance(request_timeout, (int, float)) else 60.0
        # Construction-only park; _bridge_wait frees E during the sub-ms wait and
        # owns cancel-on-timeout. A gate-deny CapabilityException crosses here via
        # future.result() and propagates out. Stays ABOVE the try below so a deny
        # never reaches the finally with `request` unbound.
        request = _bridge_wait(
            asyncio.run_coroutine_threadsafe(coro, self.main_event_loop),
            wait_timeout,
        )

        # R2-FF-4: increment _EXECUTE_DEPTH for the streaming body
        # and reset on exit. Wraps the produce/finally so the depth
        # counter is balanced even on early caller break / exception.
        depth_token = _EXECUTE_DEPTH.set(execute_depth + 1)
        try:
            for result, error, _ in request.get_queue_stream_sync():
                if error:
                    self._logger.warning(
                        "Error executing %s.%s (GenReq-ID: %s): %s. You can check the logs for this Req-ID.",
                        plugin,
                        method,
                        request.id,
                        result,
                    )
                    raise RequestException(result)
                yield result
        finally:
            # R2-EE-8: actually wait for set_collected() to complete on
            # the main loop before returning to the caller. The previous
            # fire-and-forget scheduled the coroutine but discarded the
            # Future — the producer task cancellation that
            # set_collected performs (B-002) could land AFTER the caller
            # continued, and any exception was silently swallowed. Mirror
            # the bounded .result(timeout=...) pattern from
            # request_event_stream_sync.
            #
            # Kept as a single flat ``finally`` (no nested try/finally for
            # the R2-FF-4 depth reset) so source-inspect tests that scope
            # to the last ``finally:`` see both the .result(timeout=...)
            # cleanup AND the depth-counter reset in one body.
            try:
                collected_fut = asyncio.run_coroutine_threadsafe(
                    request.set_collected(), self.main_event_loop
                )
                try:
                    # Phase 2b: free E during the cleanup wait; _bridge_wait
                    # owns cancel-on-timeout.
                    _bridge_wait(collected_fut, 5.0)
                except concurrent.futures.TimeoutError:
                    self._logger.warning(
                        "execute_stream_sync: set_collected() exceeded 5s for "
                        "request %s — cancelled orphan task",
                        request.id,
                    )
                except Exception:
                    pass
            except Exception:
                pass
            _EXECUTE_DEPTH.reset(depth_token)

    # ── Notifier system ───────────────────────────────────────────────

    async def subscribe(
        self,
        topic: str,
        plugin_name: str,
        plugin_uuid: str,
        target_plugin: Optional[str] = None,
        target_access_name: Optional[str] = None,
        target_plugin_uuid: Optional[str] = None,
        hosts: Union[str, list, None] = "any",
        blocked_hosts: Union[str, list, None] = None,
        authors: Union[str, list, None] = None,
        blocked_authors: Union[str, list, None] = None,
        declared_id: Optional[str] = None,
        enabled: bool = True,
    ) -> str:
        """Legacy subscribe alias — delegates to :meth:`subscribe_event`.

        C-076: the previous implementation called
        ``topic_registry.subscribe`` directly, bypassing the
        ``broadcast_local_sub_added`` peer-advert hook and the
        ``_sub_uuids`` per-plugin tracking that ``subscribe_event``
        provides. Test plugins still call ``self._plexus.subscribe``
        (e.g. TestLifecycleSuite, TestRemoteTarget) so the method stays
        as a deprecation-aliased shim that routes through the canonical
        path. The ``declared_id`` and ``enabled`` kwargs are dropped on
        the alias path; both default to the same values that
        ``subscribe_event`` produces internally.
        """
        self._logger.warning(
            "Plexus.subscribe is a legacy alias for Plexus.subscribe_event "
            "(C-076); please migrate the caller. Aliasing now."
        )
        return await self.subscribe_event(
            topic=topic,
            plugin_name=plugin_name,
            plugin_uuid=plugin_uuid,
            target_plugin=target_plugin,
            target_access_name=target_access_name or "",
            target_plugin_uuid=target_plugin_uuid,
            hosts=hosts,
            blocked_hosts=blocked_hosts,
            authors=authors,
            blocked_authors=blocked_authors,
            # W5-Q1: forward declared_id + enabled (previously dropped).
            declared_id=declared_id,
            enabled=enabled,
        )

    async def unsubscribe(self, subscription_id: str) -> bool:
        """Legacy unsubscribe alias — delegates to :meth:`unsubscribe_event`.

        C-076: the previous implementation called
        ``topic_registry.unsubscribe`` directly, bypassing the
        ``broadcast_local_sub_removed`` peer-advert hook. Kept as a
        deprecation-aliased shim for the same reason as
        :meth:`subscribe`.
        """
        self._logger.warning(
            "Plexus.unsubscribe is a legacy alias for Plexus.unsubscribe_event "
            "(C-076); please migrate the caller. Aliasing now."
        )
        return await self.unsubscribe_event(subscription_id)
