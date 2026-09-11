"""Demo subscriber: the receiving end of DemoPub's 1:N publishes.

Declares two subscriptions (`demo.greeted`, `demo.ticked`) and counts
every event that reaches it, so fan-out is verifiable from a counter
rather than from logs."""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class DemoSub(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self.description = (
            "Demo subscriber: counts events published by DemoPub."
        )
        self._counter = 0

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def handle_greeted(self, event):
        self._counter += 1
        return {"counter": self._counter}

    @async_log_errors
    async def handle_ticked(self, event):
        self._counter += 1
        return {"counter": self._counter}

    @async_log_errors
    async def count(self):
        return {"counter": self._counter}
