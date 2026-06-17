"""Rate-limit charge-set fixture: a cross-plugin subscription/endpoint target.

Gives TestRateLimitSuite a SECOND plugin to target, so the suite can prove a
cross-plugin sub's IN-set keys on the TARGET plugin/endpoint, not the owner.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402


class TestRateLimitTarget(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def sink(self, value: Any = None) -> str:
        return "sink"
