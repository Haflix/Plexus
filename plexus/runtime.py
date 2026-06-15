"""Cross-cutting runtime primitives for Plexus.

Mutable module-level runtime state shared by both the event subsystem and
the request/execute dispatch paths: the per-worker-thread sync-call-chain
threadlocal, the emit/execute recursion-guard ContextVars, and the plugin
lifecycle timeout defaults. Kept in a neutral module that imports nothing
from the plexus package, so core.py (and the events.py mixin) can import
these without a circular dependency. core.py re-exports every name for
back-compat (utils.py pulls the timeouts; bare-name references inside
class Plexus methods keep resolving).
"""

import threading
from contextvars import ContextVar


# Tracks the sync call chain on each threadpool worker thread.
# Used by execute_sync / _call_endpoint to detect circular sync calls
# that would deadlock the ThreadPoolExecutor.
_sync_call_chain = threading.local()


# Default plugin-readiness gate timeout (seconds). Used by
# _wait_for_plugin_ready before dispatching to a plugin endpoint;
# raises asyncio.TimeoutError on expiry. Per spec must not be reduced
# below 30 in normal operation. Configurable via
# general.plugin_ready_timeout in config.yml; tests may override
# self.plugin_ready_timeout directly.
DEFAULT_PLUGIN_READY_TIMEOUT: float = 60.0

# Default plugin-disable timeout (seconds). Wraps user on_disable in
# asyncio.wait_for in disable_plugin / _pop_plugin_under_lock so a
# misbehaving on_disable can't hang pop_plugin / _reload_plugin /
# purge_plugins indefinitely. close() already had its own 30s; this
# brings runtime hot-reload paths to parity. Configurable via
# general.plugin_disable_timeout in config.yml; tests may override
# self.plugin_disable_timeout directly.
DEFAULT_PLUGIN_DISABLE_TIMEOUT: float = 30.0

# C-017: Default plugin-enable timeout (seconds). Wraps user on_enable
# in asyncio.wait_for in _enable_plugin_under_lock so a misbehaving
# on_enable can't pin lifecycle_lock indefinitely (saturating
# _plugin_executor with 32 hung sync handlers was a documented DoS in
# the C-017 audit). Symmetric with the disable side; configurable via
# general.plugin_enable_timeout in config.yml; tests may override
# self.plugin_enable_timeout directly.
DEFAULT_PLUGIN_ENABLE_TIMEOUT: float = 30.0


# B-073: Internal event bus recursion guard. Module-level ContextVar
# (NOT instance attr) so the per-task counter is shared across emit
# calls in the same task while remaining isolated between tasks via
# Python's contextvars task-inheritance. Increment with
# ``token = _EMIT_DEPTH.set(...)``; restore with ``_EMIT_DEPTH.reset(token)``
# — naive ``set(get() - 1)`` corrupts inherited parent-task state under
# nested ``asyncio.create_task`` fan-out. ``_MAX_EMIT_DEPTH = 5`` aborts
# pathological recursive observer chains.
_EMIT_DEPTH: ContextVar[int] = ContextVar("_aio_emit_depth", default=0)
_MAX_EMIT_DEPTH: int = 5

# R2-FF-4: Execute-side recursion guard. Mirrors ``_EMIT_DEPTH`` for
# the sync-execute path. The framework's sync-endpoint thread pool has
# a fixed worker count (default 32); a chain of nested execute_sync
# calls fanning in faster than workers can drain deadlocks the pool.
# This ContextVar tracks per-task nesting depth so the framework can
# abort a runaway chain BEFORE the pool fills. ``_MAX_EXECUTE_DEPTH``
# is set conservatively below the worker count so other framework
# work (observer dispatch, networking) still gets pool slots.
# Increment with ``token = _EXECUTE_DEPTH.set(...)``; restore with
# ``_EXECUTE_DEPTH.reset(token)`` — naive ``set(get() - 1)`` corrupts
# inherited parent-task state under nested ``asyncio.create_task``
# fan-out, same trap _EMIT_DEPTH avoids.
_EXECUTE_DEPTH: ContextVar[int] = ContextVar("_aio_execute_depth", default=0)
_MAX_EXECUTE_DEPTH: int = 16
