"""TestLifecycleLoadCrash — static fixture whose on_load raises.

Loaded ONLY on demand, by
lifecycle.state_machine.failed_load_state_visible, which calls
load_plugin_with_conf on this entry and then pops it again. It stays
enabled:false in test_config.yml so no boot leaves a FAILED_LOAD entry
sitting in plugin_states for every other suite to trip over.
"""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class TestLifecycleLoadCrashError(RuntimeError):
    """Distinct type so the case can assert the recorded exception_type."""


class TestLifecycleLoadCrash(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        raise TestLifecycleLoadCrashError("deliberate on_load failure")

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass
