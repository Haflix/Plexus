from plexus.utils import Plugin
from plexus.decorators import (
    log_errors,
    async_log_errors,
    async_gen_log_errors,
)
import asyncio


class SensorPlugin(Plugin):
    """Demo data source: a fake temperature sensor.

    Pairs with AveragePlugin (which averages the readings this plugin emits) to
    form the runnable two-plugin demo in this folder. In one small plugin it
    shows:
      - a plain async endpoint callable via execute()           -> read
      - PUBLISHING a declared event (the `events:` block)        -> emit_reading
      - a streaming endpoint with a rate-limit `stream_weight`   -> read_stream
      - a self-declared `rate_limits:` block in plugin_config.yml
      - an endpoint `tags:` entry for find_endpoints_by_tag discovery
    """

    @log_errors
    def on_load(self, *args, **kwargs):
        """Sync init: declare instance state only (no I/O, no awaits)."""
        self._logger.debug("SensorPlugin loaded")
        self._tick = 0

    @async_log_errors
    async def on_enable(self):
        """Async setup goes here (open connections, start tasks). Nothing to do
        for this fake sensor."""
        self._logger.debug("SensorPlugin enabled")

    @async_log_errors
    async def on_disable(self):
        """Undo exactly what on_enable did."""
        self._logger.debug("SensorPlugin disabled")

    def _next_reading(self) -> float:
        # Deterministic fake reading so the demo output is stable across runs.
        self._tick += 1
        return round(20.0 + (self._tick % 5) * 0.5, 2)

    @async_log_errors
    async def read(self) -> dict:
        """Return the current sensor reading.

        Callable by other plugins via ``execute("SensorPlugin", "read")``.
        Tagged ``demo-sensor`` in the manifest, so it can be discovered with
        ``find_endpoints_by_tag("demo-sensor")`` without hardcoding the name.
        """
        value = self._next_reading()
        self._logger.info(f"read -> {value}")
        return {"sensor": self.plugin_name, "value": value}

    @async_log_errors
    async def emit_reading(self, value: float = None) -> int:
        """PUBLISH a reading to the ``sensor/reading`` topic (fire-and-forget,
        1:N). Every subscriber (here: ``AveragePlugin.handle_reading``) receives
        an ``Event``. Returns the number of subscribers the event was scheduled
        to (0 if none matched).

        The ``reading`` event is DECLARED in plugin_config.yml under ``events:``;
        ``publish_event`` references it by that id, not by the raw topic.
        """
        if value is None:
            value = self._next_reading()
        count = await self.publish_event(
            "reading", payload={"sensor": self.plugin_name, "value": value}
        )
        self._logger.info(f"emit_reading({value}) -> {count} subscriber(s)")
        return count

    @async_gen_log_errors
    async def read_stream(self, count: int = 3):
        """Stream ``count`` sequential readings.

        Declared with ``stream_weight: 2`` in the manifest, so opening this
        stream costs 2 IN tokens under the rate limiter (a heavier operation
        than a 1-token call). An async generator uses ``@async_gen_log_errors``.
        """
        for _ in range(count):
            await asyncio.sleep(0.05)  # simulate async I/O
            yield self._next_reading()
