"""TestIdentityTarget — rate-limiter Step 2a lifecycle-exempt fixture.

A minimal plugin the suite can disable + re-enable while
``_identity_active`` is forced on, so its ``on_enable`` / ``on_disable``
run under stamping and capture the caller chain. Step 2a stamps an EXEMPT
frame for lifecycle scope (design Section 8); these captures let the suite
assert that.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.runtime import current_caller_chain  # noqa: E402


def _chain_list() -> List[list]:
    return [[i.name, i.uuid, i.exempt] for i in current_caller_chain()]


class TestIdentityTarget(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._enable_capture: Optional[list] = None
        self._disable_capture: Optional[list] = None

    @log_errors
    def on_enable(self):
        # SYNC on_enable on purpose: it runs via run_in_executor wrapped by
        # _seed_sync_hook, so this captures the sync-lifecycle seed path (the
        # async path is structurally identical to the proven _call_endpoint
        # async push). Captured under stamping when the suite re-enables this.
        self._enable_capture = _chain_list()

    @async_log_errors
    async def on_disable(self):
        self._disable_capture = _chain_list()

    @async_log_errors
    async def get_enable_capture(self) -> Optional[list]:
        return self._enable_capture

    @async_log_errors
    async def get_disable_capture(self) -> Optional[list]:
        return self._disable_capture
