"""TestLifecycleBrokenVersion — Phase 4 static fixture for B-007.

The plugin_config.yml deliberately omits the `version` field.

B-007 (FIXED): load_plugin_with_conf used to subscript plugin_config['version'], and the resulting KeyError aborted the entire `for plugin_entry in self.yaml_config.get('plugins', [])` loop in get_plugins, so any plugin listed AFTER this one never loaded. core.py now warns and falls back to "0.0.0" (a valid PEP 440 string, so version-constrained dependency checks still work).

This fixture stays enabled:false and is loaded ON DEMAND by lifecycle.B-007.missing_version_defaults, which asserts that load_plugin_with_conf does not raise. Booting it would make a regression fatal before any case reported (B-093: the load loop still has no per-entry guard), i.e. the regression could never surface as a red cell.
"""

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


class TestLifecycleBrokenVersion(Plugin):
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
    async def ping(self) -> str:
        return "ok"
