"""TestLifecycleDepChild — HUNT-076 fixture.

Declares a REQUIRED dependency on TestLifecycleDepBase in its manifest. At boot
DepBase is ENABLED, so this child boots ENABLED too. The HUNT-076 regression
disables DepBase and reloads this child: the reload dependency precheck must
refuse to re-enable it against a not-ENABLED required dependency (FAILED_LOAD).
"""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class TestLifecycleDepChild(Plugin):
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
