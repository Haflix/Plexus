from plexus.utils import Plugin
from plexus.decorators import (
    log_errors,
    async_log_errors,
    async_handle_errors,
    async_gen_log_errors,
    gen_log_errors,
)
from plexus.exceptions import CapabilityException
import asyncio


class AveragePlugin(Plugin):
    """Demo orchestrator/aggregator: averages the readings SensorPlugin emits.

    Pairs with SensorPlugin to form the runnable two-plugin demo in this folder
    (boot it with ``copypasta/run_demo.py`` against ``copypasta/config.yml``). In
    one plugin it demonstrates most of the framework surface:
      - lifecycle (on_load / on_enable / on_disable) + the ``self.ready`` gate
      - SUBSCRIBING to another plugin's event           -> handle_reading
      - a SYNC method (@log_errors)                      -> average
      - a SYNC GENERATOR (@gen_log_errors, NOT @log_errors) -> recorded_values
      - calling another plugin via execute()             -> pull_reading
      - asserting an identity via execute(author=...)    -> try_act_as (capabilities)
      - endpoint discovery with find_endpoints_by_tag    -> discover_sensors
      - an async streaming endpoint                      -> example_stream
    Its manifest also declares a ``dependencies:`` block (it needs SensorPlugin)
    and a self-declared ``rate_limits:`` block.
    """

    # ── Lifecycle ─────────────────────────────────────────────────────
    @log_errors
    def on_load(self, *args, **kwargs):
        """Sync init: declare instance state only. No I/O or awaits here."""
        self._logger.debug("AveragePlugin loaded")
        self._count = 0
        self._sum = 0.0
        self._values = []

    @async_log_errors
    async def on_enable(self):
        """Async setup. Close the readiness gate while setting up so cross-plugin
        calls into this plugin wait, then open it when ready. (Trivial here, but
        this is where you would open connections / start background tasks.)"""
        self.ready.clear()
        self._logger.debug("AveragePlugin enabling...")
        # ... real async setup would go here ...
        self.ready.set()
        self._logger.debug("AveragePlugin enabled")

    @async_log_errors
    async def on_disable(self):
        """Undo exactly what on_enable did (close resources, cancel tasks)."""
        self._logger.debug("AveragePlugin disabled")

    # ── Event subscriber ──────────────────────────────────────────────
    @async_log_errors
    async def handle_reading(self, event):
        """Subscribed to the ``sensor/reading`` topic (see ``subscriptions:`` in
        the manifest). Receives an ``Event`` and folds the reading into the
        running average. Topic routing decouples us from WHO publishes -- we
        never name SensorPlugin here."""
        value = float(event.payload["value"])
        self._count += 1
        self._sum += value
        self._values.append(value)
        self._logger.info(f"handle_reading: {value} (n={self._count})")
        return {"n": self._count, "average": self._sum / self._count}

    # ── A SYNC method (dispatched on the sync thread pool) ─────────────
    @log_errors
    def average(self) -> dict:
        """Return the running average. A plain SYNC endpoint -- pure computation,
        no awaits. The framework runs it on the sync bridge thread pool."""
        avg = (self._sum / self._count) if self._count else None
        return {"count": self._count, "average": avg}

    # ── A SYNC GENERATOR (must use @gen_log_errors) ───────────────────
    @gen_log_errors
    def recorded_values(self):
        """Yield every reading recorded so far. A SYNC generator MUST use
        ``@gen_log_errors`` -- the framework rejects a sync generator decorated
        with ``@log_errors`` at load (use the matching gen/async-gen decorator)."""
        for v in list(self._values):
            yield v

    # ── Calling another plugin via execute() ──────────────────────────
    @async_log_errors
    async def pull_reading(self) -> dict:
        """Pull a reading on demand by calling SensorPlugin.read() directly. A
        1:1 ``execute()`` to a NAMED plugin. We declare SensorPlugin as a
        dependency (see ``dependencies:``), so the framework guarantees it is
        enabled before us."""
        return await self.execute("SensorPlugin", "read", hosts="local")

    # ── Capabilities: assert an identity ──────────────────────────────
    @async_log_errors
    async def try_act_as(self, author: str, author_id: str = None) -> dict:
        """Attempt to call SensorPlugin.read() AS ``author`` (impersonation).

        Whether this is allowed depends on the ``capabilities:`` grant in the
        main config. The demo grants this plugin
        ``impersonation_allowed: [SensorPlugin]``, so asserting ``SensorPlugin``
        is allowed (the operation proceeds under that identity, and a rate-limit
        charge would attribute to it); asserting anything else raises
        ``CapabilityException``. With no grant at all the gate is inert and
        ``author`` is just a routing label."""
        try:
            r = await self.execute(
                "SensorPlugin", "read",
                author=author, author_id=author_id or author, hosts="local",
            )
            return {"allowed": True, "result": r}
        except CapabilityException as e:
            return {"allowed": False, "reason": str(e)}

    # ── Endpoint discovery by tag ─────────────────────────────────────
    @async_log_errors
    async def discover_sensors(self) -> list:
        """Discover every enabled endpoint tagged ``demo-sensor`` across all
        loaded plugins, without hardcoding names -- how an orchestrator finds
        tools/capabilities at runtime. ``find_endpoints_by_tag`` is a Plexus
        method reached through ``self._plexus`` (the escape hatch), and it is
        async."""
        found = await self._plexus.find_endpoints_by_tag("demo-sensor")
        return [f"{e['plugin_name']}.{e['access_name']}" for e in found]

    # ── Generic helpers / simple examples (template boilerplate) ──────
    @async_log_errors
    async def example_method(self, value):
        """Simple async endpoint: doubles its input and returns it."""
        return value * 2

    @async_handle_errors(default_return=None)
    async def call_other_plugin(self, plugin_name, method_name, args=None):
        """Generic 1:1 ``execute()`` helper to any named plugin/method. Returns
        None on error (``@async_handle_errors`` swallows + logs)."""
        return await self.execute(plugin_name, method_name, args, hosts="any")

    @async_gen_log_errors
    async def example_stream(self, count):
        """Async streaming endpoint: yields ``count`` items."""
        for i in range(count):
            await asyncio.sleep(0.05)  # simulate async work
            yield f"Item {i + 1} of {count}"
