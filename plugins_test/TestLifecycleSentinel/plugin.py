"""TestLifecycleSentinel — Phase 4 static fixture.

Trivial plugin. Was the boot-time half of the B-007 fixture pair: listed
after TestLifecycleBrokenVersion, its absence from core.plugins would show
that the missing-version KeyError had aborted get_plugins's load loop.

CURRENTLY UNUSED. The B-007 case now loads BrokenVersion on demand, and an
on-demand load never goes through that loop, so Sentinel cannot witness it.
Kept for a future B-093 guard (the loop still aborts on any on_load raise).
"""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class TestLifecycleSentinel(Plugin):
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
    async def get_loaded(self) -> bool:
        return self.loaded
