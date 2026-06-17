"""Unit tests for the pure rate-limit config parsers.

Exercises ``parse_rate_limits`` and ``parse_plugin_rate_limits`` in isolation:
the valid flatten of all seven dimensions into the three flat stores, and the
malformed-config ValueError cases that make a bad limit fail LOUD at load (the
KeyError-prevention contract -- a malformed nodes_in / bucket spec must raise
here, never as a runtime ``params["max"]`` KeyError in the admit hot path). No
Plexus, no event loop -- the end-to-end load + plugin-declared merge is
integration-tested by TestRateLimitSuite.

Standalone: ``python test_rate_limit_config.py`` (exit 0 = pass).
"""
import sys

from plexus.helpers.config import parse_rate_limits, parse_plugin_rate_limits
from plexus.ratelimiter import (
    DIM_FRAMEWORK_IN,
    DIM_PLUGIN_IN,
    DIM_PLUGIN_OUT,
    DIM_ENDPOINT_IN,
    DIM_EVENT_OUT,
    FRAMEWORK_IN_KEY,
    endpoint_key,
    event_key,
)

_failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        _failures.append(name)


def raises_value_error(fn):
    try:
        fn()
    except ValueError:
        return True
    except Exception as e:
        return f"wrong exc {type(e).__name__}: {e}"
    return "no raise"


# ── valid flatten ──────────────────────────────────────────────────────────

def test_none_is_empty():
    cfg, sub, nodes = parse_rate_limits(None)
    check("None -> empty cfg", cfg == {})
    check("None -> empty sub", sub == {})
    check("None -> empty nodes", nodes == {})


def test_full_flatten_all_seven_dims():
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
    check("framework_in key",
          cfg.get((DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)) == {"max": 1000, "window": 1})
    # plugin out / in
    check("plugin_out key",
          cfg.get((DIM_PLUGIN_OUT, "Orch")) == {"max": 50, "window": 1})
    check("plugin_in key",
          cfg.get((DIM_PLUGIN_IN, "Orch")) == {"max": 100, "window": 1})
    # endpoint / event (composite keys)
    check("endpoint_in key",
          cfg.get((DIM_ENDPOINT_IN, endpoint_key("Orch", "llm"))) == {"max": 20, "window": 1})
    check("event_out key",
          cfg.get((DIM_EVENT_OUT, event_key("Orch", "resp"))) == {"max": 30, "window": 1})
    # sub (separate store, keyed by (plugin, declared_id))
    check("sub key",
          sub.get(("Orch", "my_sub")) == {"max": 40, "window": 1})
    # nodes (separate store)
    check("nodes default", nodes.get("default") == {"max": 200, "window": 1})
    check("nodes peer", nodes.get("node-b") == {"max": 2000, "window": 1})
    # nothing leaked across stores
    check("sub not in cfg", all(k[0] != "sub_in" for k in cfg))
    check("five cfg entries", len(cfg) == 5, f"got {len(cfg)}")


def test_nodes_in_default_only():
    _, _, nodes = parse_rate_limits({"nodes_in": {"default": {"max": 5, "window": 1}}})
    check("default-only nodes", nodes == {"default": {"max": 5, "window": 1}})


def test_nodes_in_peers_only():
    # both default and peers are optional; peers-only is valid (caps only
    # named peers, all others unlimited).
    _, _, nodes = parse_rate_limits({"nodes_in": {"peers": {"h": {"max": 1, "window": 1}}}})
    check("peers-only nodes", nodes == {"h": {"max": 1, "window": 1}})


def test_float_values_preserved():
    cfg, _, _ = parse_rate_limits({"framework_in": {"max": 2.5, "window": 0.5}})
    check("fractional max/window kept",
          cfg.get((DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY)) == {"max": 2.5, "window": 0.5})


# ── malformed -> ValueError (the KeyError-prevention contract) ──────────────

def test_top_not_mapping():
    check("top non-dict raises", raises_value_error(lambda: parse_rate_limits([1, 2])) is True)


def test_unknown_top_key():
    check("unknown top key raises",
          raises_value_error(lambda: parse_rate_limits({"nope": 1})) is True)


def test_missing_max():
    check("missing max raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"window": 1}})) is True)


def test_missing_window():
    check("missing window raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": 5}})) is True)


def test_zero_max():
    check("max=0 raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": 0, "window": 1}})) is True)


def test_negative_window():
    check("window<0 raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": 5, "window": -1}})) is True)


def test_bool_max_rejected():
    # bool is an int subclass -- True must not slip through as a 1-token bucket.
    check("max=True raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": True, "window": 1}})) is True)


def test_non_numeric_max():
    check("max='x' raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": "x", "window": 1}})) is True)


def test_string_numeric_max_rejected():
    # A quoted YAML number ("5") is an operator mistake -- the config layer must
    # reject it loud, not silently coerce via float() the way runtime _validate
    # would. (review finding A1.)
    check("max='5' (quoted number) raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": "5", "window": 1}})) is True)
    check("window='1' (quoted number) raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": 5, "window": "1"}})) is True)


def test_peer_named_default_rejected():
    # A peer literally named "default" collides with the nodes_in.default
    # fallback key -- reject it. (review finding A2.)
    check("peer named 'default' raises",
          raises_value_error(lambda: parse_rate_limits({
              "nodes_in": {"default": {"max": 10, "window": 1},
                           "peers": {"default": {"max": 5, "window": 1}}}})) is True)


def test_non_finite_max():
    check("max=inf raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": float("inf"), "window": 1}})) is True)


def test_unknown_bucket_key():
    check("extra bucket key raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": {"max": 5, "window": 1, "x": 9}})) is True)


def test_bucket_not_mapping():
    check("bucket non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"framework_in": 5})) is True)


def test_nodes_in_not_mapping():
    check("nodes_in non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"nodes_in": 5})) is True)


def test_nodes_in_unknown_key():
    check("nodes_in unknown key raises",
          raises_value_error(lambda: parse_rate_limits({"nodes_in": {"foo": {"max": 1, "window": 1}}})) is True)


def test_nodes_in_peers_not_mapping():
    check("nodes_in.peers non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"nodes_in": {"peers": 5}})) is True)


def test_plugins_not_mapping():
    check("plugins non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"plugins": 5})) is True)


def test_plugin_block_not_mapping():
    check("plugin block non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"plugins": {"X": "nope"}})) is True)


def test_plugin_unknown_section():
    check("plugin unknown section raises",
          raises_value_error(lambda: parse_rate_limits({"plugins": {"X": {"bogus": {"max": 1, "window": 1}}}})) is True)


def test_plugin_endpoints_not_mapping():
    check("plugin endpoints non-dict raises",
          raises_value_error(lambda: parse_rate_limits({"plugins": {"X": {"endpoints": 5}}})) is True)


def test_framework_in_in_plugin_block_rejected():
    # framework_in is operator-global -- not valid inside a plugin block.
    check("framework_in in plugin block raises",
          raises_value_error(lambda: parse_rate_limits({"plugins": {"X": {"framework_in": {"max": 1, "window": 1}}}})) is True)


# ── parse_plugin_rate_limits (the manifest path) ────────────────────────────

def test_plugin_parser_none_empty():
    cfg, sub = parse_plugin_rate_limits("X", None)
    check("plugin None -> empty cfg", cfg == {})
    check("plugin None -> empty sub", sub == {})


def test_plugin_parser_flatten():
    cfg, sub = parse_plugin_rate_limits("X", {
        "out": {"max": 5, "window": 1},
        "endpoints": {"e": {"max": 2, "window": 1}},
        "subs": {"s": {"max": 1, "window": 1}},
    })
    check("plugin out key", cfg.get((DIM_PLUGIN_OUT, "X")) == {"max": 5, "window": 1})
    check("plugin endpoint key",
          cfg.get((DIM_ENDPOINT_IN, endpoint_key("X", "e"))) == {"max": 2, "window": 1})
    check("plugin sub key", sub.get(("X", "s")) == {"max": 1, "window": 1})


def test_plugin_parser_rejects_global_dims():
    # a manifest may NOT declare framework_in / nodes_in (operator-global).
    check("manifest framework_in raises",
          raises_value_error(lambda: parse_plugin_rate_limits("X", {"framework_in": {"max": 1, "window": 1}})) is True)
    check("manifest nodes_in raises",
          raises_value_error(lambda: parse_plugin_rate_limits("X", {"nodes_in": {"default": {"max": 1, "window": 1}}})) is True)


def test_plugin_parser_block_not_mapping():
    check("manifest non-dict block raises",
          raises_value_error(lambda: parse_plugin_rate_limits("X", "nope")) is True)


def main():
    tests = [
        test_none_is_empty,
        test_full_flatten_all_seven_dims,
        test_nodes_in_default_only,
        test_nodes_in_peers_only,
        test_float_values_preserved,
        test_top_not_mapping,
        test_unknown_top_key,
        test_missing_max,
        test_missing_window,
        test_zero_max,
        test_negative_window,
        test_bool_max_rejected,
        test_non_numeric_max,
        test_string_numeric_max_rejected,
        test_peer_named_default_rejected,
        test_non_finite_max,
        test_unknown_bucket_key,
        test_bucket_not_mapping,
        test_nodes_in_not_mapping,
        test_nodes_in_unknown_key,
        test_nodes_in_peers_not_mapping,
        test_plugins_not_mapping,
        test_plugin_block_not_mapping,
        test_plugin_unknown_section,
        test_plugin_endpoints_not_mapping,
        test_framework_in_in_plugin_block_rejected,
        test_plugin_parser_none_empty,
        test_plugin_parser_flatten,
        test_plugin_parser_rejects_global_dims,
        test_plugin_parser_block_not_mapping,
    ]
    for t in tests:
        print(t.__name__)
        t()
    print()
    if _failures:
        print(f"FAILED: {len(_failures)} -> {_failures}")
        sys.exit(1)
    print("ALL PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
