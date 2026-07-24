"""TestLifecycleDepBase — HUNT-076 fixture.

Trivial dependency BASE. TestLifecycleDepChild declares a required dependency
on this plugin in its own manifest. The HUNT-076 reload-precheck regression
disables this base, reloads the child, and asserts the child does NOT come back
ENABLED against a down required dependency (it is marked FAILED_LOAD instead).
"""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class TestLifecycleDepBase(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self.loaded: bool = True

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def ping(self) -> bool:
        return True
