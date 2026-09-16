# Configuration

*Last updated for Plexus 0.81.0*

Reference for the top-level `config.yml` — the file Plexus reads on
startup to find plugins, configure the runtime, and (when enabled) wire
up networking. The shipped `config.example.yml` is the starting point;
copy it to `config.yml` (which is gitignored) and edit.

For per-plugin manifests (`plugin_config.yml`), see
[plugin authoring](./plugin_authoring.md). For the operational side of
the cluster, see [networking](./networking.md). For framework
internals, see [architecture](./architecture.md).

Two optional top-level config sections have their own deep-dives: the
token-bucket rate limiter (`rate_limits:`) is documented in
[rate limiting](./rate_limiting.md), and the caller-identity capability
grants (`capabilities:`) in [capabilities](./capabilities.md). Both are
off by default.

---

## Top-level shape

```yaml
plugins:        # list of plugin entries
  - name: ...
    enabled: ...
    path: ...
    overrides: ...

general:        # framework-wide settings
  hostname: ...
  plugin_package: ...
  console_log_level: ...
  ...

networking:     # cluster topology
  enabled: ...
  port: ...
  peers: ...
  ...
```

All three keys are required. `ConfigUtil.check_config_integrity`
raises `ConfigException` on startup if any of the three is missing.

---

## `plugins:` (list of dicts)

Each entry describes one plugin to load. Config order does **not**
control shutdown: plugins are disabled in reverse **dependency** order
(the reverse of the resolved topological order), so express ordering
with a `dependencies:` declaration rather than list position.

```yaml
plugins:
  - name: PostgreSQL
    enabled: true
    path: ./plugins/PlexusPostgreSQL

  - name: AveragePlugin
    enabled: true
    path: ./copypasta/AveragePlugin
    overrides:
      version: "1.1.0+local"
      verbose_notifier: true
```

### Per-entry fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | identifier | YES | — | Validated by `_validate_identifier_name`. Must be a valid Python identifier. Reserved names rejected: `system`, `general`, `any`, `remote`, `local`, `plexus`. |
| `enabled` | bool | YES | — | If `false`, the entry is parsed and immediately popped — the plugin is never loaded. |
| `path` | str | optional | `{plugin_package}/{name}` | If absent, auto-resolved from `general.plugin_package`. |
| `overrides` | dict / null | optional | `null` | Deep-merged into the plugin's own `plugin_config.yml`. See [overrides mechanics](#overrides-mechanics). |

Unknown entry-level keys log a warning and are ignored. A legacy
top-level `arguments:` field on the plugin entry (as opposed to inside
`overrides:`) is ignored with a renamed-key warning — `arguments:`
belongs in the plugin's own `plugin_config.yml` or in an `overrides:`
block.

### Multiple instances of the same class

A class can be loaded multiple times under different `name` values.
Each instance gets its own `plugin_uuid` and its own copy of state —
useful for two Discord bots, two MQTT clients, etc.

```yaml
plugins:
  - name: DiscordBotMain
    enabled: true
    path: ./plugins/example_plugin
    overrides:
      arguments:
        token: "<prod-token>"

  - name: DiscordBotDev
    enabled: true
    path: ./plugins/example_plugin
    overrides:
      arguments:
        token: "<dev-token>"
```

Plugin `name`s must be unique within a host — two `plugins:` entries that
share a `name` are rejected at config load (`ConfigException`). Other plugins
target a specific instance by name; `plugin_uuid` disambiguates only when the
same name legitimately exists on multiple NODES:

```python
# Target by name (the common case):
await self.execute("DiscordBotDev", "send_message", args=("hello",))

# Target by plugin_uuid (when name alone is ambiguous):
await self.execute("DiscordBot", "send_message",
                   args=("hello",), plugin_uuid=some_uuid)
```

---

## Overrides mechanics

Each `plugins:` entry can carry an `overrides:` block that deep-merges
into the plugin's own `plugin_config.yml` at load time. Use this when
you want to customize a single instance of a class without forking the
plugin folder. Implemented by `apply_overrides`.

```yaml
plugins:
  - name: DiscordBotMain
    enabled: true
    path: ./plugins/example_plugin
    overrides:
      description: "Production Discord bot"
      version: "1.4.2"               # value-replace
      remote: false
      verbose_notifier: true
      arguments:                     # forwarded to on_load
        token: "<prod-token>"
        guild_id: 123456789
      endpoints:
        send_message:
          remote: true               # raise the per-endpoint remote flag
      events:
        new_message:
          enabled: false             # silence this event
      subscriptions:
        on_command:
          authors: ["AI_Interaction"]
```

Override semantics:

- **Plugin-level scalars** (`description`, `remote`, `version`,
  `prefix`, `verbose_notifier`) — value-replace.
- **`endpoints:`** — STRICT. Unknown sub-keys under an endpoint
  override are fail-load errors. Protects against typos that would
  silently change nothing. Driven by the module-level
  `_STRICT_OVERRIDE_SECTIONS = frozenset({"endpoints"})` in
  `plexus/helpers/config.py`.
- **`arguments:`**, **`events:`**, **`subscriptions:`** — LENIENT.
  Unknown subkeys merge in.
- **`__replace__: true`** in any sub-mapping triggers wholesale
  replace of that sub-mapping instead of merge.

```yaml
overrides:
  arguments:
    __replace__: true                # wipe the original arguments
    api_key: "..."
    region: "eu-west-1"
```

Without `__replace__`, the override is merged on top of the original.

### `endpoints:` strict-failure example

The strict mode catches override typos that would otherwise change
nothing silently. Suppose `plugin_config.yml` declares an endpoint
named `send_message`, and the override misspells it as `send_mesage`:

```yaml
overrides:
  endpoints:
    send_mesage:                     # typo — no such endpoint in base
      remote: true
```

Load fails with a `ConfigException` naming the unknown subkey. The
This strictness covers endpoint **names** only. Keys *inside* a known
endpoint are not validated:

```yaml
overrides:
  endpoints:
    send_message:
      remoet: true                   # typo for "remote" — silently merged in
```

A misspelled key inside an endpoint body is added to the merged endpoint
with a DEBUG log and no error, and the endpoint keeps its real `remote`
value. Check override bodies against the plugin's manifest yourself. Reserved endpoint `access_name` values follow the
same forbidden list as plugin names: `system`, `general`, `any`,
`remote`, `local`, `plexus`.

---

## `general:` (dict)

Framework-wide settings. Read by `ConfigUtil.apply_configvalues` and `Plexus.__init__`.

```yaml
general:
  hostname: ""
  plugin_package: plugins
  console_log_level: "DEBUG"
  file_log_level: "DEBUG"
  asyncio_debug: false
  logger_levels:
    asyncio: "MUTE"
    httpx: "WARNING"
  plugin_ready_timeout: 60.0
  plugin_disable_timeout: 30.0
  plugin_enable_timeout: 30.0
  sync_executor_workers: 32
  sync_executor_thread_ceiling: 128
  sync_dispatcher_workers: 4
  sync_dispatcher_thread_ceiling: 32
  sync_stream_workers: 4
  sync_stream_thread_ceiling: 16
```

### Reference

| Key | Type | Default | Notes |
|---|---|---|---|
| `hostname` | str | `socket.gethostname()` if empty | This node's identity for `local` / `remote` host filtering and the canonical routing key for cross-node dispatch. |
| `plugin_package` | str | `"plugins"` | Default base directory for plugin entries that omit `path:`. |
| `console_log_level` | str | `"DEBUG"` | Level for the stdout/stderr handler. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `MUTE`. |
| `file_log_level` | str | `"DEBUG"` | Level for the file handler. Same valid set. |
| `logger_levels` | dict | `{}` | Per-logger thresholds. See below. |
| `asyncio_debug` | bool | `false` | Enables `loop.set_debug(True)` and `slow_callback_duration=0.5`. |
| `plugin_ready_timeout` | float | `60.0` | Cross-plugin readiness gate budget. |
| `plugin_disable_timeout` | float | `30.0` | Per-plugin `on_disable` cap during runtime disable / pop / reload. |
| `plugin_enable_timeout` | float | `30.0` | Per-plugin `on_enable` cap during runtime enable / load. |
| `sync_executor_workers` | int | `32` | Execution concurrency (E) of the main sync-endpoint pool: how many sync plugin endpoints run at once. |
| `sync_executor_thread_ceiling` | int | `128` | Hard thread ceiling (M) of the main sync-endpoint pool. Runaway backstop; on saturation the call loud-rejects. Auto-raised to `sync_executor_workers` if set lower. |
| `sync_dispatcher_workers` | int | `4` | Execution concurrency (E) of the sync event-handler pool (the `SyncDispatcher`). |
| `sync_dispatcher_thread_ceiling` | int | `32` | Hard thread ceiling (M) of the sync event-handler pool. Auto-raised to `sync_dispatcher_workers` if set lower. |
| `sync_stream_workers` | int | `4` | Execution concurrency (E) of the sync streaming-generator pool. |
| `sync_stream_thread_ceiling` | int | `16` | Hard thread ceiling (M) of the sync streaming-generator pool. Auto-raised to `sync_stream_workers` if set lower. |

### `plugin_ready_timeout` (default 60.0)

Budget for `_wait_for_plugin_ready`. When plugin A calls
`await self.execute("B", ...)`, the call blocks until plugin B's
`_lifecycle_ready` (framework-set after `on_enable` returns) AND
`ready` (author-controlled) flags are both set — or this timeout
elapses, in which case the call raises `RequestException`.

Don't drop below ~30s in normal operation. A bad value falls back to
the default with a warning.

### `plugin_disable_timeout` (default 30.0)

Per-plugin cap on `on_disable` execution during runtime
disable / pop / reload (`_disable_plugin_under_lock`, `_pop_plugin_under_lock`).
Shutdown's per-plugin cap is hardcoded 30s separately and is not
affected by this knob.

If `on_disable` raises, times out, or returns, the framework still
transitions the plugin to `INACTIVE` and unregisters its subs —
bookkeeping is in `try/finally`. (`enabled` is a read-only property
derived from state; assigning to it raises `AttributeError`.) The timeout exists so a hanging `on_disable` does
not block reload of other plugins.

### `plugin_enable_timeout` (default 30.0)

Per-plugin cap on `on_enable` execution during runtime enable / load
(`_enable_plugin_under_lock`). If `on_enable` exceeds this budget the
plugin is force-rolled back to `INACTIVE`. Note that
`last_errors[Phase.ENABLE]` is **not** written in this case —
`asyncio.TimeoutError` is excluded from the error record along with
`CancelledError`, so a hung enable leaves no entry behind.

Bookkeeping (subscription/observer cleanup) still runs via the same
`try/finally` chain as the success path, so a hung `on_enable` does not
leak observers or subs.

> Caveat: for a **sync** `on_enable`, the timeout cancels the asyncio
> task wrapping the `run_in_executor` call, NOT the underlying executor
> thread. A hung sync `on_enable` keeps its slot in `_plugin_executor`
> (the framework's per-plugin thread pool — separate from
> `sync_dispatcher_workers`) busy until the thread returns naturally (or
> the executor is shut down at framework close). The rollback `on_disable`
> runs in the same `_plugin_executor` and is bounded by
> `plugin_disable_timeout`, so a hung sync `on_enable` plus its rollback
> can occupy two pool slots until natural return. The plugin's state still
> transitions to `INACTIVE` on time.

### Sync-bridge thread pools (E and M)

The framework runs sync plugin code on three thread pools. Each pool has
two budgets:

- **E (execution concurrency)** — how many sync bodies run at once. This
  is the `*_workers` knob. A parked sync body (one that called
  `execute_sync` / `publish_event_sync` / etc. and is waiting on the
  result) releases its E slot while parked, so nested sync calls always
  find a slot. This is what keeps re-entrant sync fan-out from
  deadlocking.
- **M (thread ceiling)** — the maximum live threads before the pool
  loud-rejects with a `RequestException` instead of spawning more. A pure
  runaway-prevention backstop. E and M are independent: M must stay >= E
  (the framework auto-raises it if you set workers higher).

| pool | what runs on it | E knob (default) | M knob (default) |
|---|---|---|---|
| main sync-endpoint | sync `execute()` endpoint bodies | `sync_executor_workers` (32) | `sync_executor_thread_ceiling` (128) |
| event-handler | sync subscriber handlers (`publish_event` / `request_event`) | `sync_dispatcher_workers` (4) | `sync_dispatcher_thread_ceiling` (32) |
| streaming | sync streaming-generator producers | `sync_stream_workers` (4) | `sync_stream_thread_ceiling` (16) |

Every pool exposes both E and M as config. The defaults suit a personal
deployment; you rarely need to touch the M ceilings (they only cap a
runaway, never the steady state).

- All keys: min 1, bad values warn and fall back to the default.
- `sync_dispatcher_workers=1` serializes all sync subscriber handlers —
  useful when handlers share non-thread-safe state.
- Raising a `*_workers` key raises real concurrency; raising a
  `*_thread_ceiling` key only raises the runaway backstop. M is auto-raised
  to its pool's E if you set the ceiling below the worker count.

### `logger_levels` — per-logger thresholds

Per-logger threshold overrides. Matches a logger by name with
prefix-and-dot-boundary semantics — longest prefix that matches a
logger's name wins. Implementation in
`LogUtil.apply_logger_levels_config`.

The value can be a single level string (applied to both console and
file handlers) or a split dict `{console: ..., file: ...}` for an
independent split:

```yaml
general:
  logger_levels:
    asyncio: "MUTE"                  # both handlers
    urllib3: "MUTE"
    httpx: "WARNING"
    psycopg: "WARNING"
    psycopg.pool: "DEBUG"            # longer prefix wins for psycopg.pool.X

    PluginA:                         # split form
      console: "INFO"                # only console raised
      file: "DEBUG"                  # file still records all
```

Valid levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `MUTE`.
Wildcards are NOT accepted. Dot boundary is required for prefix
matching: `"httpx"` matches `httpx` and `httpx.SOMETHING`, but NOT
`httpxSOMETHING`.

#### Runtime overrides — `set_logger_level` / `clear_logger_level`

In addition to config-driven `logger_levels`, plugins can adjust
thresholds at runtime via two helpers on the `Plugin` base class:

```python
self.set_logger_level("noisy_lib", console="MUTE", file="DEBUG")
self.clear_logger_level("noisy_lib")
```

Survival semantics:

- **Plugin-source runtime overrides survive config reloads** — a
  `load_config_yaml` does not wipe them.
- They ARE auto-cleared on hot-swap, pop, purge, and
  shutdown — the framework tracks them by `(plugin_name, plugin_uuid)`.
- Each plugin's overrides are independent — clearing one plugin's
  override does not affect another plugin's override of the same
  logger.

`self.list_logger_levels()` returns a snapshot of all configured
thresholds (config + plugin sources combined).

---

## `networking:` (dict)

Cluster topology. See [networking](./networking.md) for the
operational reference (trust model, peer setup, the directory-pull
routing model). This section documents the YAML keys.

When `enabled: false`, the rest of this section is mostly inert —
`NetworkManager` is never created, and only `enabled` is consulted.

```yaml
networking:
  enabled: true
  port: 2510
  hostname: ""
  keys_dir: "keys"
  discoverable: false        # opt in to §4.7 vouch-discovery
  peers:
    - hostname: "node-b"
      address: "10.0.0.2"
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBg...
        -----END CERTIFICATE-----
      fingerprint: "sha256:abcd..."
```

### Top-level networking keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Toggles all networking. When `false`, `NetworkManager` is not created. |
| `port` | int | `2510` | Default TCP port for the mTLS server. Per-peer port overrides via `address: ip:port`. |
| `hostname` | str | — | **Not read.** Retained only as a rebuild-trigger field for backward compatibility; netcore takes its identity from `general.hostname`. Setting it has no effect on the wire hostname. |
| `keys_dir` | str | `"keys"` | Where this node's `cert.pem` / `key.pem` live (auto-generated on first run). Resolved relative to the config file's directory if not absolute. |
| `peers` | list[dict] | `[]` | Peer trust list (see below). Empty is tolerated: the acceptor binds and swaps in the live TLS context on the first `add_peer`; the SPKI pin + roster gate still reject any unpinned inbound. |
| `discoverable` | bool | `false` | Opt in to §4.7 vouch-discovery: accept peers vouched by an already-trusted peer, so a star can grow edges. Explicit `peers:` pins work regardless of this. Legacy `auto_discoverable` / `direct_discoverable` are accepted as aliases (either `true` → `discoverable`). |
| `vouch_active_cap` | int | `64` | Max peers a single voucher may introduce via discovery (only relevant when `discoverable`). `<= 0` → default. |
| `heartbeat_interval` | float | `10.0` | Seconds between heartbeat/liveness pulses to each peer. **Adopted on rebuild/restart** (see the adoption note below), not live. Bad values → default. |
| `probe_timeout` | float | `2.0` | Per-probe budget for a single heartbeat ping. Adopted on rebuild/restart. Bad values → default. |
| `liveness_timeout` | float | `30.0` | A peer whose last successful contact is older than this is unreachable (effective miss tolerance ≈ `liveness_timeout / heartbeat_interval`). Should be `>= heartbeat_interval`; 2-3× typical. Adopted on rebuild/restart. Bad values → default. |
| `idle_read_deadline` | float | `max(2 × heartbeat_interval, 20)` | Idle-read deadline on an inbound link: no frame for this long tears the link and fast-fails its pending requests. Legacy alias: `inbound_idle_timeout`. Bad values → default. |
| `stream_idle_deadline` | float | `30.0` | Per-chunk idle bound on a cross-node stream: a producer that stalls longer than this between chunks fails the stream closed. Raise it for a legitimately slow producer (e.g. a >30s time-to-first-token model). Legacy alias: `request_timeout`. `<= 0` → default. |
| `connect_timeout` | float | `10.0` | Per-attempt budget for a single outbound TCP + TLS connect, so a black-holed peer cannot hang a dialer forever. `<= 0` → default. Adopted on rebuild/restart. |
| `ping_floor_interval` | float | `max(0.5, heartbeat_interval × 0.5)` | Minimum spacing between directory-snapshot serves to one peer (rate-limits pull churn). Bad values → default. |
| `per_cid_reassembly_cap` | int | `8388608` (8 MB) | Max reassembly bytes held for ONE in-flight message (per-message DoS guard). `<= 0` → default. |
| `per_peer_reassembly_cap` | int | `16777216` (16 MB) | Max reassembly bytes across all in-flight messages from ONE peer. The biggest single value you can receive = `min(per_cid, per_peer)`, so raise BOTH to move larger single payloads. `<= 0` → default. |
| `node_reassembly_cap` | int | `134217728` (128 MB) | Aggregate reassembly ceiling across all peers — size it to the node's memory budget. `<= 0` → default. |
| `per_peer_cid_cap` | int | `64` | Max concurrent in-flight inbound CALLs from one peer; the next one gets an immediate `NETWORK` error. Raise for a busy orchestrator that fans many parallel calls at one node. `<= 0` → default. |
| `lan_cidrs` | list[str] | built-in LAN ranges | CIDR ranges a vouched peer's advertised address must fall within before it is dialed (discovery safety). |

**Adoption:** all networking knobs are read once, at `NetworkManager` construction.
A rebuild is triggered only by a change to `peers` / `port` / `enabled` / `hostname` /
`keys_dir`. So a config change to a timing / discovery / timeout / cap knob **alone**
is adopted on the next rebuild (one of those trigger fields also changing) or on a full
restart — it does **not** take effect live mid-run.

The presence-check validators warn on the LEGACY discovery keys
(`auto_discoverable` / `direct_discoverable`, and the retired `discover_nodes`),
not the current `discoverable`. A config that sets only `discoverable:` still
works (the legacy names are accepted as aliases), but expect a harmless "missing"
warning for the legacy keys.

### Per-peer fields (`peers:` entries)

| Field | Type | Required | Notes |
|---|---|---|---|
| `hostname` | str | YES | Canonical routing key (survives reconnect / IP change). |
| `address` | str | YES | `ip` or `ip:port`. Bare IP uses cluster default port. |
| `cert_pem` | str | YES | Inline PEM string (YAML block scalar). The only supported form — there is no `cert_file` option for a peer; an entry without `cert_pem` is rejected as malformed and skipped with a warning. |
| `fingerprint` | str | optional | `sha256:<hex>` of the SubjectPublicKeyInfo DER. Derived from the cert at parse time; if supplied, must match (mismatch is a hard error). |
| `system_caller` | bool | optional | When `true`, this peer's calls inherit `"system"` author privileges (bypasses author whitelists). Default `false`. |
| `dial` | str | optional | Per-edge dialer override for a NAT edge. Its PRESENCE (any value) flips this side into a dialer when hostname-lex election would otherwise make it the acceptor; the peer is dialed at its configured `address` (the `dial` value itself is never read). Rarely needed. |

```yaml
peers:
  - hostname: alpha
    address: "10.0.0.1"              # bare IP -> cluster default port
    cert_pem: |
      -----BEGIN CERTIFICATE-----
      MIIBIjANBg...
      -----END CERTIFICATE-----
    system_caller: false

  - hostname: beta
    address: "10.0.0.2:2511"         # explicit port override
    cert_pem: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    fingerprint: "sha256:abcd..."
```

An empty `peers:` list with `networking.enabled: true` is tolerated: the
node loads or generates its own identity, binds the acceptor with an
empty-cadata listener, and simply has nothing to talk to until a peer is
added (via a config reload or, with `discoverable`, a vouch). The SPKI
post-check plus the roster gate still reject any unpinned inbound. This
makes first-boot productive: a fresh node comes up and logs its
fingerprint and cert so you can populate the other nodes' `peers:`.

### Removed / legacy fields

| Key | Status | Migration |
|---|---|---|
| `node_ips` | REMOVED. Hard error if present. | Use `peers:`. |
| `secret` | accepted but no longer used | Remove from config. |
| `cert_file` (top-level, not per-peer) | accepted but no longer used | Remove from config. |
| `key_file` (top-level, not per-peer) | accepted but no longer used | Remove from config. |

When migrating an older config, replace the top-level `node_ips:` list
with a `peers:` list (one entry per peer with `hostname`, `address`,
and `cert_pem`).

---

## A complete minimal `config.yml`

```yaml
plugins:
  - name: AveragePlugin
    enabled: true
    path: ./copypasta/AveragePlugin

general:
  hostname: ""              # empty = system hostname
  plugin_package: plugins
  console_log_level: "INFO"
  file_log_level: "DEBUG"
  asyncio_debug: false
  plugin_ready_timeout: 60.0
  plugin_disable_timeout: 30.0
  plugin_enable_timeout: 30.0
  sync_dispatcher_workers: 4
  logger_levels:
    asyncio: "MUTE"
    httpx: "WARNING"

networking:
  enabled: false
  port: 2510
  peers: []                 # tolerated empty; add peers (or enable discoverable) to connect
```

This is enough to boot. Defaults handle everything else: hostname is
`socket.gethostname()`, log level is `DEBUG`, no networking, no
multi-node concerns.

---

## A complete two-node `config.yml`

```yaml
plugins:
  - name: AveragePlugin
    enabled: true
    path: ./copypasta/AveragePlugin

general:
  hostname: alpha
  plugin_package: plugins
  console_log_level: "INFO"
  file_log_level: "DEBUG"
  asyncio_debug: false
  plugin_ready_timeout: 60.0
  plugin_disable_timeout: 30.0
  plugin_enable_timeout: 30.0
  sync_dispatcher_workers: 4

networking:
  enabled: true
  hostname: alpha
  port: 2510
  keys_dir: "keys"
  discoverable: false        # opt in to §4.7 vouch-discovery
  peers:
    - hostname: beta
      address: "10.0.0.2:2510"
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBg...
        -----END CERTIFICATE-----
    - hostname: gamma
      address: "10.0.0.3:2511"
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBgk...
        -----END CERTIFICATE-----
      system_caller: false
```

The corresponding `config.yml` on `beta` would have `hostname: beta`
and a `peers:` entry pointing at `alpha` with `alpha`'s cert. See
[networking](./networking.md) for the operator workflow that produces
those cert files.

---

## Hot-reloading config

`Plexus.load_config_yaml(path)` re-reads the config file,
validates it, and re-applies it. The async wrapper is
`async_load_config_yaml(path)`. Behaviour:

- The `plugins:` list is **not** reconciled. Entries that newly appear are
  not loaded, entries that disappear are not popped, and a changed
  `overrides:` block does not trigger a hot-swap. To add, remove or
  reload a specific plugin, call `_reload_plugin` or `pop_plugin` +
  `load_plugin_with_conf` explicitly.
- Plugin-source per-logger runtime overrides survive the reload (they
  are auto-cleared only on disable / pop / purge / shutdown).
- **Networking** knobs are read once at `NetworkManager` construction. A reload
  rebuilds networking only when `peers` / `port` / `enabled` / `hostname` /
  `keys_dir` changes; a reload that touches only timing / discovery / timeout /
  cap knobs adopts them on the next such rebuild or on restart, not live (see the
  networking-keys table above).

`save_config_file(path, content, backup=True)` validates a YAML
payload and writes it to disk (with a `.bak` if `backup=True`). It
does NOT trigger a reload — call `load_config_yaml` afterwards if
that's what you want.

For a forced full-cycle reload of one plugin without changing config,
use `Plexus._reload_plugin(name)` directly.

---

## What's NOT a config knob

A few things that look like they ought to be tunable but aren't:

- The **shutdown-time per-plugin `on_disable` budget** is hardcoded to
  30 seconds. Use `plugin_disable_timeout` for the runtime per-plugin
  cap (which `_disable_plugin_under_lock` / `_pop_plugin_under_lock` honour).
- The **30-second wait for in-flight tracked tasks at `close()` time**
  is hardcoded.

These are deliberate caps. If a deployment needs them tunable, raise
it as a feature request.
