"""TestRateLimitConfigUnitSuite — pure-function unit tests for the rate-limit config parsers.

Ported from the former root-level ``test_rate_limit_config.py``. Self-contained:
imports ``parse_rate_limits`` / ``parse_plugin_rate_limits`` and the DIM_* / key
helpers from plexus.ratelimiter, and exercises them with synthetic configs.
No Plexus boot, no event loop semantics needed -- the end-to-end load +
plugin-declared merge path is integration-tested by TestRateLimitSuite.

Categories: ``parse`` (valid flatten of all seven dimensions) and
``malformed`` (ValueError cases that enforce the KeyError-prevention contract).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.helpers.config import parse_rate_limits, parse_plugin_rate_limits  # noqa: E402
from plexus.ratelimiter import (  # noqa: E402
    DIM_FRAMEWORK_IN,
    DIM_PLUGIN_IN,
    DIM_PLUGIN_OUT,
    DIM_ENDPOINT_IN,
    DIM_EVENT_OUT,
    FRAMEWORK_IN_KEY,
    endpoint_key,
    event_key,
)

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


def _raises_value_error(fn):
    """Return True if fn() raises ValueError, else return False."""
    try:
        fn()
    except ValueError:
        return True
    except Exception:
        return False
    return False


class TestRateLimitConfigUnitSuite(Plugin):
    """Pure-function unit suite for parse_rate_limits + parse_plugin_rate_limits."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestRateLimitConfigUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestRateLimitConfigUnitSuite disabled")

    @async_log_errors
    async def run(
        self,
        category: Optional[str] = None,
        host: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        bug_ids: Optional[List[str]] = None,
        skip_slow: bool = False,
        allow_destructive: bool = True,
    ) -> Dict[str, Any]:
        rec = CaseRecorder("TestRateLimitConfigUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        # parse.* cases
        await self._none_is_empty(rec, kw)
        await self._full_flatten_all_seven_dims(rec, kw)
        await self._nodes_in_default_only(rec, kw)
        await self._nodes_in_peers_only(rec, kw)
        await self._float_values_preserved(rec, kw)
        # malformed.* cases
        await self._top_not_mapping(rec, kw)
        await self._unknown_top_key(rec, kw)
        await self._missing_max(rec, kw)
        await self._missing_window(rec, kw)
        await self._zero_max(rec, kw)
        await self._negative_window(rec, kw)
        await self._bool_max_rejected(rec, kw)
        await self._non_numeric_max(rec, kw)
        await self._string_numeric_max_rejected(rec, kw)
        await self._peer_named_default_rejected(rec, kw)
        await self._non_finite_max(rec, kw)
        await self._unknown_bucket_key(rec, kw)
        await self._bucket_not_mapping(rec, kw)
        await self._nodes_in_not_mapping(rec, kw)
        await self._nodes_in_unknown_key(rec, kw)
        await self._nodes_in_peers_not_mapping(rec, kw)
        await self._plugins_not_mapping(rec, kw)
        await self._plugin_block_not_mapping(rec, kw)
        await self._plugin_unknown_section(rec, kw)
        await self._plugin_endpoints_not_mapping(rec, kw)
        await self._framework_in_in_plugin_block_rejected(rec, kw)
        # parse_plugin_rate_limits cases
        await self._plugin_parser_none_empty(rec, kw)
        await self._plugin_parser_flatten(rec, kw)
        await self._plugin_parser_rejects_global_dims(rec, kw)
        await self._plugin_parser_block_not_mapping(rec, kw)

        return rec.to_dict()

    # ---------------- parse cases ----------------

    async def _none_is_empty(self, rec, kw):
        async def body(c):
            cfg, sub, nodes = parse_rate_limits(None)
            assert cfg == {}, "None -> empty cfg"
            assert sub == {}, "None -> empty sub"
            assert nodes == {}, "None -> empty nodes"

        await rec.run_case(
            "ratelimit_config.none_is_empty", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _full_flatten_all_seven_dims(self, rec, kw):
        async def body(c):
            cfg, sub, nodes = parse_rate_limits({
                "framework_in": {"max": 1000, "window": 1},
                "nodes_in": {
                    "default": {"max": 200, "window": 1},
                    "peers": {"node-b": {"max": 2000, "window": 1}},
                },
                "plugins": {
                    "Orch": {
                        "out": {"max": 50, "window": 1},
                        "in": {"max": 100, "window": 1},
                        "endpoints": {"llm": {"max": 20, "window": 1}},
                        "events": {"resp": {"max": 30, "window": 1}},
                        "subs": {"my_sub": {"max": 40, "window": 1}},
                    },
                },
            })
            # framework_in
            assert cfg.get((DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)) == {"max": 1000, "window": 1}, \
                "framework_in key"
            # plugin out / in
            assert cfg.get((DIM_PLUGIN_OUT, "Orch")) == {"max": 50, "window": 1}, \
                "plugin_out key"
            assert cfg.get((DIM_PLUGIN_IN, "Orch")) == {"max": 100, "window": 1}, \
                "plugin_in key"
            # endpoint / event (composite keys)
            assert cfg.get((DIM_ENDPOINT_IN, endpoint_key("Orch", "llm"))) == {"max": 20, "window": 1}, \
                "endpoint_in key"
            assert cfg.get((DIM_EVENT_OUT, event_key("Orch", "resp"))) == {"max": 30, "window": 1}, \
                "event_out key"
            # sub (separate store, keyed by (plugin, declared_id))
            assert sub.get(("Orch", "my_sub")) == {"max": 40, "window": 1}, \
                "sub key"
            # nodes (separate store)
            assert nodes.get("default") == {"max": 200, "window": 1}, \
                "nodes default"
            assert nodes.get("node-b") == {"max": 2000, "window": 1}, \
                "nodes peer"
            # nothing leaked across stores
            assert all(k[0] != "sub_in" for k in cfg), \
                "sub not in cfg"
            assert len(cfg) == 5, f"five cfg entries (got {len(cfg)})"

        await rec.run_case(
            "ratelimit_config.full_flatten_all_seven_dims", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _nodes_in_default_only(self, rec, kw):
        async def body(c):
            _, _, nodes = parse_rate_limits({"nodes_in": {"default": {"max": 5, "window": 1}}})
            assert nodes == {"default": {"max": 5, "window": 1}}, "default-only nodes"

        await rec.run_case(
            "ratelimit_config.nodes_in_default_only", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _nodes_in_peers_only(self, rec, kw):
        # both default and peers are optional; peers-only is valid (caps only
        # named peers, all others unlimited).
        async def body(c):
            _, _, nodes = parse_rate_limits({"nodes_in": {"peers": {"h": {"max": 1, "window": 1}}}})
            assert nodes == {"h": {"max": 1, "window": 1}}, "peers-only nodes"

        await rec.run_case(
            "ratelimit_config.nodes_in_peers_only", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _float_values_preserved(self, rec, kw):
        async def body(c):
            cfg, _, _ = parse_rate_limits({"framework_in": {"max": 2.5, "window": 0.5}})
            assert cfg.get((DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)) == {"max": 2.5, "window": 0.5}, \
                "fractional max/window kept"

        await rec.run_case(
            "ratelimit_config.float_values_preserved", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    # ---------------- malformed cases ----------------

    async def _top_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(lambda: parse_rate_limits([1, 2])) is True, \
                "top non-dict raises"

        await rec.run_case(
            "ratelimit_config.top_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _unknown_top_key(self, rec, kw):
        async def body(c):
            assert _raises_value_error(lambda: parse_rate_limits({"nope": 1})) is True, \
                "unknown top key raises"

        await rec.run_case(
            "ratelimit_config.unknown_top_key", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _missing_max(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"window": 1}})
            ) is True, "missing max raises"

        await rec.run_case(
            "ratelimit_config.missing_max", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _missing_window(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": 5}})
            ) is True, "missing window raises"

        await rec.run_case(
            "ratelimit_config.missing_window", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _zero_max(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": 0, "window": 1}})
            ) is True, "max=0 raises"

        await rec.run_case(
            "ratelimit_config.zero_max", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _negative_window(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": 5, "window": -1}})
            ) is True, "window<0 raises"

        await rec.run_case(
            "ratelimit_config.negative_window", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _bool_max_rejected(self, rec, kw):
        # bool is an int subclass -- True must not slip through as a 1-token bucket.
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": True, "window": 1}})
            ) is True, "max=True raises"

        await rec.run_case(
            "ratelimit_config.bool_max_rejected", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _non_numeric_max(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": "x", "window": 1}})
            ) is True, "max='x' raises"

        await rec.run_case(
            "ratelimit_config.non_numeric_max", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _string_numeric_max_rejected(self, rec, kw):
        # A quoted YAML number ("5") is an operator mistake -- the config layer must
        # reject it loud, not silently coerce via float() the way runtime _validate
        # would. (review finding A1.)
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": "5", "window": 1}})
            ) is True, "max='5' (quoted number) raises"
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": 5, "window": "1"}})
            ) is True, "window='1' (quoted number) raises"

        await rec.run_case(
            "ratelimit_config.string_numeric_max_rejected", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _peer_named_default_rejected(self, rec, kw):
        # A peer literally named "default" collides with the nodes_in.default
        # fallback key -- reject it. (review finding A2.)
        async def body(c):
            assert _raises_value_error(lambda: parse_rate_limits({
                "nodes_in": {"default": {"max": 10, "window": 1},
                             "peers": {"default": {"max": 5, "window": 1}}}})) is True, \
                "peer named 'default' raises"

        await rec.run_case(
            "ratelimit_config.peer_named_default_rejected", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _non_finite_max(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": float("inf"), "window": 1}})
            ) is True, "max=inf raises"

        await rec.run_case(
            "ratelimit_config.non_finite_max", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _unknown_bucket_key(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": {"max": 5, "window": 1, "x": 9}})
            ) is True, "extra bucket key raises"

        await rec.run_case(
            "ratelimit_config.unknown_bucket_key", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _bucket_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"framework_in": 5})
            ) is True, "bucket non-dict raises"

        await rec.run_case(
            "ratelimit_config.bucket_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _nodes_in_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"nodes_in": 5})
            ) is True, "nodes_in non-dict raises"

        await rec.run_case(
            "ratelimit_config.nodes_in_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _nodes_in_unknown_key(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"nodes_in": {"foo": {"max": 1, "window": 1}}})
            ) is True, "nodes_in unknown key raises"

        await rec.run_case(
            "ratelimit_config.nodes_in_unknown_key", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _nodes_in_peers_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"nodes_in": {"peers": 5}})
            ) is True, "nodes_in.peers non-dict raises"

        await rec.run_case(
            "ratelimit_config.nodes_in_peers_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _plugins_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"plugins": 5})
            ) is True, "plugins non-dict raises"

        await rec.run_case(
            "ratelimit_config.plugins_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _plugin_block_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"plugins": {"X": "nope"}})
            ) is True, "plugin block non-dict raises"

        await rec.run_case(
            "ratelimit_config.plugin_block_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _plugin_unknown_section(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"plugins": {"X": {"bogus": {"max": 1, "window": 1}}}})
            ) is True, "plugin unknown section raises"

        await rec.run_case(
            "ratelimit_config.plugin_unknown_section", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _plugin_endpoints_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"plugins": {"X": {"endpoints": 5}}})
            ) is True, "plugin endpoints non-dict raises"

        await rec.run_case(
            "ratelimit_config.plugin_endpoints_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _framework_in_in_plugin_block_rejected(self, rec, kw):
        # framework_in is operator-global -- not valid inside a plugin block.
        async def body(c):
            assert _raises_value_error(
                lambda: parse_rate_limits({"plugins": {"X": {"framework_in": {"max": 1, "window": 1}}}})
            ) is True, "framework_in in plugin block raises"

        await rec.run_case(
            "ratelimit_config.framework_in_in_plugin_block_rejected", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    # ---------------- parse_plugin_rate_limits cases ----------------

    async def _plugin_parser_none_empty(self, rec, kw):
        async def body(c):
            cfg, sub = parse_plugin_rate_limits("X", None)
            assert cfg == {}, "plugin None -> empty cfg"
            assert sub == {}, "plugin None -> empty sub"

        await rec.run_case(
            "ratelimit_config.plugin_parser_none_empty", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _plugin_parser_flatten(self, rec, kw):
        async def body(c):
            cfg, sub = parse_plugin_rate_limits("X", {
                "out": {"max": 5, "window": 1},
                "endpoints": {"e": {"max": 2, "window": 1}},
                "subs": {"s": {"max": 1, "window": 1}},
            })
            assert cfg.get((DIM_PLUGIN_OUT, "X")) == {"max": 5, "window": 1}, \
                "plugin out key"
            assert cfg.get((DIM_ENDPOINT_IN, endpoint_key("X", "e"))) == {"max": 2, "window": 1}, \
                "plugin endpoint key"
            assert sub.get(("X", "s")) == {"max": 1, "window": 1}, \
                "plugin sub key"

        await rec.run_case(
            "ratelimit_config.plugin_parser_flatten", body,
            tags=("ratelimit_config", "parse"), category="parse", **kw
        )

    async def _plugin_parser_rejects_global_dims(self, rec, kw):
        # a manifest may NOT declare framework_in / nodes_in (operator-global).
        async def body(c):
            assert _raises_value_error(
                lambda: parse_plugin_rate_limits("X", {"framework_in": {"max": 1, "window": 1}})
            ) is True, "manifest framework_in raises"
            assert _raises_value_error(
                lambda: parse_plugin_rate_limits("X", {"nodes_in": {"default": {"max": 1, "window": 1}}})
            ) is True, "manifest nodes_in raises"

        await rec.run_case(
            "ratelimit_config.plugin_parser_rejects_global_dims", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )

    async def _plugin_parser_block_not_mapping(self, rec, kw):
        async def body(c):
            assert _raises_value_error(
                lambda: parse_plugin_rate_limits("X", "nope")
            ) is True, "manifest non-dict block raises"

        await rec.run_case(
            "ratelimit_config.plugin_parser_block_not_mapping", body,
            tags=("ratelimit_config", "malformed"), category="malformed", **kw
        )
