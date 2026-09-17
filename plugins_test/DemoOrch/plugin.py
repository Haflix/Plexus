"""Demo orchestrator: the wiring-variety end of the demo set.

  - 4 declared subscriptions across 3 topics, one of them routed
    cross-plugin via `target_plugin` so a topic lands on ANOTHER
    plugin's endpoint
  - `handle_ask` answers the 1:1 `demo.ask` request_event, and is the
    endpoint a host scopes an `endpoint_in` rate limit to
  - `count_stream` is an async-generator endpoint, exercising the
    streaming dispatch path
"""

import asyncio

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, async_gen_log_errors, log_errors


class DemoOrch(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self.description = (
            "Demo orchestrator: multi-target subscriber plus "
            "streaming endpoint."
        )
        self._counts: dict = {
            "heartbeat": 0,
            "burst": 0,
            "greeted_via_orch": 0,
            "ask": 0,
        }

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def handle_heartbeat(self, event):
        self._counts["heartbeat"] += 1
        return {"counter": self._counts["heartbeat"]}

    @async_log_errors
    async def handle_burst(self, event):
        self._counts["burst"] += 1
        return {"counter": self._counts["burst"]}

    @async_log_errors
    async def handle_greeted_via_orch(self, event):
        self._counts["greeted_via_orch"] += 1
        return {"counter": self._counts["greeted_via_orch"]}

    @async_log_errors
    async def handle_ask(self, event):
        """1:1 request_event handler for topic demo.ask. Returns a value
        so a request_event fired on this topic gets an answer. When the
        asking plugin runs on another node and nothing subscribes
        demo.ask locally there, the request falls through to this handler
        across the wire. This is also the endpoint a host scopes a tight
        endpoint_in rate limit to, so DemoPub.beat3_flood can trip it."""
        self._counts["ask"] += 1
        return {"answer": "pong", "from": self._plexus.hostname}

    @async_log_errors
    async def stats(self):
        return dict(self._counts)

    @async_gen_log_errors()
    async def count_stream(self, n: int = 5):
        """Async generator endpoint yielding integers 1..n with a small
        delay between each, exercising the framework's execute_stream
        dispatch path.
        """
        n = max(1, min(int(n), 50))
        for i in range(1, n + 1):
            await asyncio.sleep(0.2)
            yield {"i": i, "of": n}
