"""Config-load / validation helpers for Plexus.

Pure, stateless functions and constants extracted from core.py. They take
no Plexus instance and import nothing from the plexus package, so core.py
can re-import them without a circular dependency. core.py re-exports every
name here for back-compat (``from plexus.core import <helper>`` and the
bare-name references inside class Plexus methods keep resolving).

Lives under plexus/helpers/ so future stateless extractions from core.py
have a home alongside it rather than scattering top-level modules.
"""

import re
from typing import Any, Optional, Union, List


# Reserved identifier names — disallowed as plugin names AND endpoint
# access_names because they are framework-reserved keywords used in
# config/system contexts. Future-proof: extend as new framework-reserved
# names are introduced.
# Stage M (B-051): "any"/"remote" reserved by _normalize_hosts as host
# keywords; "local" reserved as the loopback hostname keyword. Reusing
# these as plugin names creates ambiguity in `authors:` and
# `blocked_authors:` subscription filter lists (which delegate validation
# to _normalize_hosts and would silently reject the literal name).
_RESERVED_IDENTIFIER_NAMES = frozenset(
    {"system", "general", "any", "remote", "local", "plexus"}
)
# Adding "plexus" reserves the name across every surface where
# _validate_identifier_name is called in core.py: plugin names,
# endpoint access_names, event_ids, subscription declared_ids. The
# name is the sentinel for framework self-version checks in
# dependencies.py. Verified no existing plugin / endpoint / event /
# subscription uses the bare lowercase "plexus".


def _validate_identifier_name(
    name, *, context: str, disallow_underscore_prefix: bool = False
) -> None:
    """Validate that ``name`` is a Python-identifier-style string and not in
    the reserved blacklist. Used for plugin names from config.yml and for
    endpoint access_names (= dict keys in plugin_config.yml endpoints:).

    Raises ValueError with a message that begins with ``context`` (e.g.
    ``"plugin name"`` or ``"endpoint access_name"``) so the caller can tag
    the error site without reformatting.

    C-059: ``disallow_underscore_prefix=True`` rejects names that start
    with an underscore. Used for PLUGIN NAMES because the framework
    composes topics as ``{prefix}/...`` with ``prefix`` defaulting to
    the plugin name, and ``_<anything>`` collides with the reserved
    framework-internal topic prefix (``_core/...``). Other identifier
    surfaces (endpoint access_names, event_ids, declared_ids) do not
    enter the topic-prefix path and may keep underscore-prefixed names.
    """
    if not isinstance(name, str):
        raise ValueError(
            f"{context} {name!r} invalid: must be a string, got {type(name).__name__}"
        )
    if not name.isidentifier():
        raise ValueError(
            f"{context} {name!r} invalid: must be a valid Python identifier "
            f"(letters, digits, underscores; cannot start with a digit)"
        )
    if disallow_underscore_prefix and name.startswith("_"):
        raise ValueError(
            f"{context} {name!r} invalid: cannot start with an underscore — "
            f"the framework reserves ``_<anything>/...`` topic prefixes "
            f"(``_core/...`` in particular) for internal events; allowing "
            f"a plugin to claim that prefix would collide with framework "
            f"emits"
        )
    if name in _RESERVED_IDENTIFIER_NAMES:
        raise ValueError(
            f"{context} {name!r} invalid: reserved name "
            f"(reserved: {sorted(_RESERVED_IDENTIFIER_NAMES)})"
        )


# Sections of plugin_config.yml that get DEEP-MERGED by apply_overrides.
# Each section is a top-level mapping; per-key entries are merged via
# _deep_merge_args. PR3 Stage B adds "events" and "subscriptions".
_OVERRIDE_SECTIONS = ("arguments", "endpoints", "events", "subscriptions")

# Sections that enforce STRICT unknown-subkey handling: an override naming
# a subkey not present in the base plugin_config is a fail-load ERROR.
# Other sections fall back to lenient (additive) deep-merge per Q14.
# Per Q14 events/subscriptions are LENIENT — overrides may add new keys.
_STRICT_OVERRIDE_SECTIONS = frozenset({"endpoints"})

# Plugin-level scalar/list fields (top-level fields of plugin_config.yml)
# that an `overrides:` block may VALUE-REPLACE. PR3 Stage B adds "prefix"
# and "verbose_notifier".
_PLUGIN_LEVEL_OVERRIDE_FIELDS = (
    "description",
    "remote",
    "version",
    "prefix",
    "verbose_notifier",
)

# Reserved topic_vars / load-time-templating names.
_RESERVED_TEMPLATE_VARS = frozenset(
    {"prefix", "plugin_name", "hostname", "plugin_uuid"}
)

# {var}-style placeholder regex. Matches {name} where name is identifier-style.
_TEMPLATE_VAR_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve_load_time_template(
    template: str,
    *,
    prefix: str,
    plugin_name: str,
    hostname: str,
    plugin_uuid: str,
) -> str:
    """Resolve the four reserved placeholders in a topic template at config-load
    time per PR3 LOCKED J. UNKNOWN ``{var}`` placeholders are LEFT INTACT for
    runtime resolution via topic_vars (PR3 LOCKED L).

    NOT a generic ``str.format()`` — that would error on unresolved
    ``{var}`` placeholders that should stay templated.
    """
    if not isinstance(template, str) or "{" not in template:
        return template

    substitutions = {
        "prefix": prefix,
        "plugin_name": plugin_name,
        "hostname": hostname,
        "plugin_uuid": plugin_uuid,
    }

    def _repl(match: re.Match) -> str:
        name = match.group(1)
        if name in substitutions:
            return substitutions[name]
        return match.group(0)  # leave untouched for runtime templating

    return _TEMPLATE_VAR_RE.sub(_repl, template)


def _validate_topic_static(
    topic: str,
    *,
    context: str,
    allow_wildcards: bool,
) -> str:
    """Validate a topic string per PR3 LOCKED L + Q15/Q16/C20.

    Returns the normalized topic (leading/trailing slashes stripped).

    Validation rules applied here:
      * Must be non-empty after stripping (Q15).
      * No empty middle segments (e.g. "a//b") — C20 rejection.
      * If allow_wildcards is False, ``*`` characters anywhere are
        rejected (events.topic field — wildcards are subscriber-side
        only, LOCKED L #1).
      * If allow_wildcards is True, the only allowed ``*`` form is a
        FULL-segment wildcard (e.g. "ai/*"). Embedded ``*`` mid-segment
        like "sensor/abc*" is rejected (C20 / LOCKED L #2a).

    Raises ValueError with ``context`` prefix on violation.
    """
    if not isinstance(topic, str):
        raise ValueError(
            f"{context}: topic must be a string; got {type(topic).__name__}"
        )

    stripped = topic.strip("/")
    if not stripped or not stripped.strip():
        raise ValueError(f"{context}: topic must not be empty (Q15)")

    # B-073 Step 9: reject topics starting with the framework-internal
    # prefix ``_``. ``_core/...`` is reserved for the internal event bus
    # (Plexus._internal_emit, exempt from this validator). Plugin
    # authors must use a non-underscore-prefixed namespace.
    if stripped.startswith("_"):
        raise ValueError(
            f"{context}: topic {topic!r} starts with reserved framework "
            f"prefix '_' — '_core/' is framework-internal (B-073)"
        )

    segments = stripped.split("/")
    for seg in segments:
        if not seg:
            raise ValueError(
                f"{context}: empty middle segment in topic {topic!r} (C20)"
            )
        if "*" in seg:
            if not allow_wildcards:
                raise ValueError(
                    f"{context}: wildcards not allowed in topic {topic!r} "
                    f"(LOCKED L #1 — wildcards are subscriber-side only)"
                )
            if seg != "*":
                raise ValueError(
                    f"{context}: embedded '*' mid-segment in topic {topic!r} "
                    f"(C20 — '*' must be a complete segment)"
                )

    # NOTE: subscriptions.topic also forbids {var} runtime templating;
    # that check lives in _validate_subscription_topic (different fn).
    # events.topic *allows* {var} runtime placeholders. So this fn
    # only validates: non-empty + (events-only) no wildcards + no
    # embedded * mid-segment + no empty middle segments.

    return stripped


def _validate_subscription_topic(topic: str, *, context: str) -> str:
    """Subscription topic validator. Same shape as
    _validate_topic_static(allow_wildcards=True) PLUS subscription-only
    rule LOCKED L #2: ``{var}`` runtime templating syntax is REJECTED in
    subscriptions.topic (subscribers use ``*`` wildcards instead).
    """
    if not isinstance(topic, str):
        raise ValueError(
            f"{context}: topic must be a string; got {type(topic).__name__}"
        )
    if _TEMPLATE_VAR_RE.search(topic) is not None:
        raise ValueError(
            f"{context}: '{{var}}' templating syntax not allowed in "
            f"subscription topic {topic!r} (LOCKED L #2 — subscribers use "
            f"'*' wildcards, not {{var}} placeholders)"
        )
    return _validate_topic_static(topic, context=context, allow_wildcards=True)


def _deep_merge_args(
    base: dict,
    override: dict,
    plugin_name: str,
    logger,
    counters: dict,
    _path: str = "",
) -> dict:
    """Deep-merge override into a copy of base. Lists fully replaced.
    Logs each change at DEBUG (key path only — never values).
    `counters` is mutated with {'added','replaced','type_mismatched'}.

    Single-level shallow copy at each recursion. Keys present only in `base`
    keep their original reference. Plugins must not mutate `self.arguments`
    in place — consistent with the existing contract.

    A dict containing `__replace__: true` is treated as a wholesale-replace
    directive: the rest of that dict (with the marker stripped) becomes the
    value at this position, bypassing deep merge. Use it to clear a subtree
    (`{__replace__: true}` -> `{}`) or replace it (`{__replace__: true, k: v}` -> `{k: v}`).
    """
    if override.get("__replace__") is True:
        replacement = {k: v for k, v in override.items() if k != "__replace__"}
        counters["replaced"] += 1
        logger.debug(
            f"Plugin '{plugin_name}': arg subtree replaced '{_path or '<root>'}'"
        )
        return replacement

    out = dict(base)
    for key, ov in override.items():
        path = f"{_path}.{key}" if _path else key
        if key not in out:
            out[key] = ov
            counters["added"] += 1
            logger.debug(f"Plugin '{plugin_name}': arg added '{path}'")
        elif isinstance(out[key], dict) and isinstance(ov, dict):
            out[key] = _deep_merge_args(
                out[key], ov, plugin_name, logger, counters, path
            )
        elif type(out[key]) == type(ov) and out[key] == ov:
            # No-op: same type AND same value. Type guard prevents `True == 1`
            # (bool vs int) from being treated as no-op — that pair must reach
            # the type-mismatch branch below.
            pass
        else:
            # Base-was-None is NOT a mismatch — overriding a previously-null
            # key is normal. Everything else with a type change warns.
            if out[key] is not None and type(out[key]) != type(ov):
                counters["type_mismatched"] += 1
                logger.warning(
                    f"Plugin '{plugin_name}': arg '{path}' type mismatch "
                    f"({type(out[key]).__name__} -> "
                    f"{type(ov).__name__ if ov is not None else 'NoneType'}); override applied"
                )
            else:
                counters["replaced"] += 1
                logger.debug(f"Plugin '{plugin_name}': arg replaced '{path}'")
            out[key] = ov
    return out


def apply_overrides(
    plugin_config: dict,
    overrides_block: Optional[dict],
    plugin_name: str,
    logger,
) -> dict:
    """Apply a main-config `overrides:` block to a copy of plugin_config.

    Walks `overrides_block`'s top-level keys:

      * Known SECTION (``arguments``, ``endpoints``) — deep-merged against
        plugin_config[section] via ``_deep_merge_args``. For STRICT sections
        (currently ``endpoints``), unknown subkeys (entries not present in
        the base plugin_config[section]) are a fail-load ERROR per Q2.
        For other sections, unknown subkeys are added per existing
        ``_deep_merge_args`` behavior (lenient, Q14).
      * Known PLUGIN-LEVEL FIELD (``description``, ``remote``, ``version``)
        — value-replaces plugin_config[field] outright.
      * Anything else at the top level — WARN and ignore (Q22).

    Returns a new dict (does not mutate ``plugin_config``). On strict-section
    error, raises ValueError so the caller can fail-load the plugin.

    Existing behavior preserved across the generalization:
      - ``__replace__: true`` directive (handled inside _deep_merge_args)
      - type-mismatch warning + counter
      - same DEBUG/INFO log shape as the previous narrow `arguments`
        override path (logged here at the section level so the user still
        sees the per-plugin "applied N override(s)" summary)
    """
    if overrides_block is None:
        return dict(plugin_config)
    if not isinstance(overrides_block, dict):
        # Caller is expected to type-check `overrides:` itself and convert
        # to None on warning. Defensive guard for direct callers (tests).
        raise ValueError(
            f"apply_overrides: overrides must be a mapping, "
            f"got {type(overrides_block).__name__}"
        )

    merged = dict(plugin_config)
    if not overrides_block:
        # Empty `overrides: {}` block — no-op shallow copy.
        return merged

    counters = {"added": 0, "replaced": 0, "type_mismatched": 0}

    for key, ov in overrides_block.items():
        if key in _OVERRIDE_SECTIONS:
            base_section = merged.get(key)
            # Sections must be mappings (or None / absent). A list-valued
            # override targeting a section is a hard error — covered for
            # the `endpoints:` case explicitly to surface the migration
            # mistake, applies generally to all sections.
            if not isinstance(ov, dict):
                raise ValueError(
                    f"override section '{key}' must be a mapping; "
                    f"got {type(ov).__name__}"
                )
            base_dict = base_section if isinstance(base_section, dict) else {}

            if key in _STRICT_OVERRIDE_SECTIONS:
                # Strict: every override subkey must exist in the base.
                # Unknown subkey → fail-load (Q2).
                unknown = [sk for sk in ov.keys() if sk not in base_dict]
                if unknown:
                    raise ValueError(
                        f"override section '{key}' references unknown "
                        f"entries {unknown!r}; known entries are "
                        f"{sorted(base_dict.keys())!r}"
                    )

            merged[key] = _deep_merge_args(
                base_dict, ov, plugin_name, logger, counters, _path=key
            )
        elif key in _PLUGIN_LEVEL_OVERRIDE_FIELDS:
            base_val = merged.get(key)
            if base_val is not None and type(base_val) != type(ov):
                # Mirrors _deep_merge_args type-mismatch warning behavior
                # for plugin-level fields. Override still applied (lenient).
                counters["type_mismatched"] += 1
                logger.warning(
                    f"Plugin '{plugin_name}': override field '{key}' type "
                    f"mismatch ({type(base_val).__name__} -> "
                    f"{type(ov).__name__ if ov is not None else 'NoneType'}); "
                    f"override applied"
                )
            else:
                if key in merged:
                    counters["replaced"] += 1
                else:
                    counters["added"] += 1
            merged[key] = ov
        else:
            # Unknown top-level override key — Q22: warn + ignore.
            logger.warning(
                f"Plugin '{plugin_name}': unknown top-level override key "
                f"'{key}'; ignored "
                f"(known sections: {list(_OVERRIDE_SECTIONS)}, "
                f"known plugin-level fields: {list(_PLUGIN_LEVEL_OVERRIDE_FIELDS)})"
            )

    total = counters["added"] + counters["replaced"] + counters["type_mismatched"]
    if total:
        logger.info(
            f"Plugin '{plugin_name}': applied {total} override(s) "
            f"({counters['added']} added, "
            f"{counters['replaced']} replaced, "
            f"{counters['type_mismatched']} type-mismatched)"
        )

    return merged


def _normalize_str_or_list(
    value: Any,
    *,
    param_name: str,
    default: Optional[Union[str, List[str]]],
) -> Optional[Union[str, List[str]]]:
    """Shared mechanics for normalizing a str/list-of-str/None value.

    Performs:
      - None -> default
      - str non-empty -> str
      - list -> reject empty list, reject non-str entries, reject
        empty strings in list, dedup preserving order, collapse a
        single-element list to a bare str.

    Returns the cleaned scalar/list/None. Raises ValueError on
    structural errors. Does NOT apply any vocabulary-specific keyword
    guard — callers in the hosts family layer that on top.
    """
    if value is None:
        return default

    if isinstance(value, str):
        if not value.strip():
            raise ValueError(f"{param_name}: empty string not allowed")
        return value

    if isinstance(value, list):
        if not value:
            raise ValueError(f"{param_name}: empty list not allowed")
        for item in value:
            if not isinstance(item, str):
                raise ValueError(
                    f"{param_name}: list entries must be str, "
                    f"got {type(item).__name__}"
                )
            if not item.strip():
                raise ValueError(f"{param_name}: empty string in list not allowed")

        # Dedup first (preserves first-occurrence order).
        seen = set()
        deduped = []
        for item in value:
            if item not in seen:
                seen.add(item)
                deduped.append(item)

        # Single-element list collapses to bare string.
        if len(deduped) == 1:
            return deduped[0]

        return deduped

    raise ValueError(
        f"{param_name}: must be str, list[str], or None, " f"got {type(value).__name__}"
    )


def _normalize_hosts(
    value: Any,
    *,
    param_name: str = "hosts",
    default: Optional[Union[str, List[str]]],
    is_blocked: bool = False,
) -> Optional[Union[str, List[str]]]:
    """Normalize a hosts / blocked_hosts value.

    Builds on ``_normalize_str_or_list`` then applies the hosts-vocabulary
    keyword guard: ``"any"`` / ``"remote"`` cannot appear inside a
    multi-element list alongside other entries (they already cover them).

    When ``is_blocked=True`` (blocked_hosts context), ``"any"`` is
    additionally rejected as a bare scalar — blocking "any" host is
    equivalent to blocking everything, which is a configuration error
    and used to be silently asymmetric with the ``"any" in list`` case
    in ``_hosts_match._blocked`` vs ``_blocked_excludes_local``.

    Returns canonical value (str, list, or None). Raises ValueError on
    structural errors.
    """
    cleaned = _normalize_str_or_list(
        value, param_name=param_name, default=default
    )

    # Hosts-vocabulary keyword-in-list guard. Applies post-dedup, so
    # the value is either a scalar str / list of >= 2 entries / None.
    if isinstance(cleaned, list):
        for keyword in ("any", "remote"):
            if keyword in cleaned:
                raise ValueError(
                    f"{param_name}: keyword '{keyword}' cannot appear in "
                    f"a list with other elements (it already covers them)"
                )

    # blocked_hosts: reject "any" entirely (even as a bare scalar). A
    # blocked_hosts that names "any" excludes every possible peer
    # including local, which is a config error rather than a useful
    # filter.
    if is_blocked and cleaned == "any":
        raise ValueError(
            f"{param_name}: keyword 'any' is not a valid blocked-host "
            f"value (it would exclude every peer including local)"
        )

    return cleaned


def _normalize_authors(
    value: Any,
    *,
    param_name: str = "authors",
    default: Optional[Union[str, List[str]]],
) -> Optional[Union[str, List[str]]]:
    """Normalize an authors / blocked_authors value.

    Authors use a different vocabulary than hosts: a literal plugin
    name may equal a reserved hosts keyword in theory, and lists like
    ``["any", "OtherPlugin"]`` are legitimate patterns (broad allow
    plus explicit name) rather than overlaps to reject. So only the
    shared mechanics in ``_normalize_str_or_list`` apply — no
    keyword-in-list guard.

    Returns canonical value (str, list, or None). Raises ValueError on
    structural errors.
    """
    return _normalize_str_or_list(
        value, param_name=param_name, default=default
    )


def _warn_redundant_host_combos(hosts, blocked_hosts, logger) -> None:
    """Warn on hosts/blocked_hosts combinations that simplify to a single
    keyword OR exclude every possible target. Run AFTER both values are
    normalized.

    Handled cases:
      * hosts == "any": blocked-list naming "local" => use "remote";
        naming "remote" => use "local". (Pre-existing behavior.)
      * hosts == "local" (or None — the default): blocked-list naming
        "local" / "any" excludes the only target the caller chose to
        reach. Warn that the combination delivers nowhere.
      * hosts == "remote": blocked-list naming "remote" / "any"
        excludes every remote target the caller chose to reach. Same
        nowhere-delivery warning.
    """
    block_set = (
        {blocked_hosts} if isinstance(blocked_hosts, str) else set(blocked_hosts or [])
    )

    # hosts=None is the default at most call sites and resolves to
    # "local" further down the pipeline; treat the warning logic the
    # same so an operator config of bare ``blocked_hosts: ["local"]``
    # surfaces a warning rather than silently dropping all delivery.
    effective = hosts if hosts is not None else "local"

    if effective == "any":
        if "local" in block_set:
            logger.warning(
                "hosts='any' + blocked_hosts contains 'local' — simpler form is "
                "hosts='remote'."
            )
        if "remote" in block_set:
            logger.warning(
                "hosts='any' + blocked_hosts contains 'remote' — simpler form is "
                "hosts='local'."
            )
    elif effective == "local":
        if "local" in block_set or "any" in block_set:
            logger.warning(
                "hosts='local' + blocked_hosts contains 'local' or 'any' — "
                "the only allowed target is also blocked; no delivery will occur."
            )
    elif effective == "remote":
        if "remote" in block_set or "any" in block_set:
            logger.warning(
                "hosts='remote' + blocked_hosts contains 'remote' or 'any' — "
                "every allowed target is also blocked; no delivery will occur."
            )


def parse_capabilities(raw: Any) -> dict:
    """Rate-limiter Step 2b: validate + normalise the top-level main-config
    ``capabilities:`` section into the runtime grant store shape:

        {plugin_name: {"system_caller": bool,
                       "impersonation": "caller" | "ancestor" | [names]}}

    The operator-facing key is ``impersonation_allowed``; it is stored as
    ``impersonation`` (what ``runtime.evaluate_capability`` reads). Returns ``{}``
    when the section is absent. Raises ``ValueError`` (the config-layer
    convention) on a malformed entry so a bad grant fails LOUD at load, never as
    a silent missing/over-broad privilege. Grants are OPERATOR authority: a
    plugin manifest may document a request elsewhere, but only main config here
    confers a capability.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(
            "`capabilities` must be a mapping of plugin-name -> grant"
        )
    grants: dict = {}
    for pname, spec in raw.items():
        if not isinstance(spec, dict):
            raise ValueError(
                f"capabilities[{pname!r}] must be a mapping "
                f"(system_caller / impersonation_allowed)"
            )
        g: dict = {}
        if "system_caller" in spec:
            sc = spec["system_caller"]
            if not isinstance(sc, bool):
                raise ValueError(
                    f"capabilities[{pname!r}].system_caller must be true/false, "
                    f"got {sc!r}"
                )
            g["system_caller"] = sc
        if "impersonation_allowed" in spec:
            imp = spec["impersonation_allowed"]
            if imp in ("caller", "ancestor"):
                g["impersonation"] = imp
            elif isinstance(imp, list) and imp and all(
                isinstance(x, str) for x in imp
            ):
                g["impersonation"] = list(imp)
            else:
                raise ValueError(
                    f"capabilities[{pname!r}].impersonation_allowed must be "
                    f"'caller', 'ancestor', or a non-empty list of plugin names; "
                    f"got {imp!r}"
                )
        unknown = set(spec) - {"system_caller", "impersonation_allowed"}
        if unknown:
            raise ValueError(
                f"capabilities[{pname!r}] has unknown key(s) {sorted(unknown)}; "
                f"allowed: system_caller, impersonation_allowed"
            )
        # Only store an entry that actually CONFERS a capability. A
        # ``{system_caller: false}`` (or otherwise empty) entry grants nothing,
        # so it must NOT land in the store -- otherwise it would flip
        # _capability_active on (and force default-deny + identity stamping
        # node-wide) while granting the plugin nothing, a silent operator
        # foot-gun. ``system_caller: false`` is thus a no-op, same as omitting it.
        if g.get("system_caller") or "impersonation" in g:
            grants[pname] = g
    return grants
