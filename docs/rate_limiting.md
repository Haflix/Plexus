# Rate Limiting

*Last updated for Plexus 0.66.0*

Plexus has a built-in, multi-dimensional token-bucket rate limiter. It is
**opt-in and off by default**: a node with no `rate_limits:` configured pays
zero overhead per dispatch and behaves exactly as it did before the limiter
existed. Configure a limit and the framework starts charging the relevant
operations, rejecting calls that exceed their bucket.

This page covers the model, the seven dimensions, the `rate_limits:` config, what
gets thrown on a reject, and the observability surface. The capability/identity
model the limiter uses to decide *who* a call is charged to lives in
[capabilities.md](./capabilities.md). The per-peer (Nodes-IN) dimension is part of
multi-node operation, see [networking.md](./networking.md).

---

## The model

Each limit is a **token bucket**: it holds up to `max` tokens and refills
continuously at `max / window` tokens per second (so `max: 100, window: 1` is
"100 per second", `max: 60, window: 60` is "60 per minute"). An operation spends
one token (a stream open can spend more, see [stream_weight](#stream-weight)). A
bucket with enough tokens admits the call and deducts them; an empty bucket
rejects.

Two properties matter:

- **Lazy, continuous refill.** Tokens are recomputed from a monotonic clock only
  when the bucket is touched. There is no background timer.
- **All-or-nothing admission.** A single operation may charge several buckets at
  once (for example an endpoint call charges both its per-endpoint and its
  per-plugin bucket). The limiter checks them all first and only deducts if every
  bucket can pay. If any one is empty, nothing is deducted and that bucket is
  reported as the binding limit. A reject never half-drains the others.

---

## The seven dimensions

A limit is keyed by a `(dimension, key)` pair. The seven dimensions answer
different questions:

| Dimension | Keyed by | Caps |
| --- | --- | --- |
| `framework_in` | global (one bucket) | every operation entering the framework |
| `nodes_in` | remote peer hostname | inbound operations from one remote peer |
| `plugin_out` | caller plugin name | outbound operations a plugin initiates |
| `plugin_in` | target plugin name | operations delivered into a plugin (aggregate) |
| `endpoint_in` | plugin + endpoint | operations delivered to one endpoint |
| `event_out` | plugin + event id | publishes/requests of one event |
| `sub_in` | subscription | deliveries into one subscription |

The dimensions compose. A call to endpoint `E` on plugin `Q` charges both
`endpoint_in(Q, E)` and `plugin_in(Q)`; if both are configured, the tighter one
rejects first. The intended use is asymmetric: a generous `plugin_in` aggregate
cap plus a tight `endpoint_in` on one expensive endpoint, not the same number on
both (which would make the endpoint limit redundant).

**Nodes-IN is the one dynamic dimension.** Its key is a remote peer's
cert-pinned hostname, which is not known at config-write time, so its bucket is
created lazily on first contact with that peer (see
[the nodes_in config](#nodes_in-per-peer-intake)). The other six are resolved
once at registration.

---

## OUT and IN: when a call is charged

An operation is charged at two moments, by different dimensions:

- **OUT (the attempt), at the operation's entry.** When a plugin calls
  `execute()`, `publish_event()`, `request_event()`, or a streaming variant, the
  framework charges the OUT dimensions for the *caller*: `plugin_out` (the
  calling plugin), `event_out` (for an event publish/request), and the global
  `framework_in`. A dry OUT bucket raises before the call is dispatched.
- **IN (the delivery), at the target.** When the operation is delivered into a
  plugin endpoint or a subscription handler, the framework charges the IN
  dimensions for the *target*: `sub_in` (if it is a subscription delivery),
  `endpoint_in`, and `plugin_in`. A dry IN bucket rejects the delivery.

This two-admit split is deliberate. The OUT side caps how fast a plugin can *ask*;
the IN side caps how fast a plugin can *be asked*. A self-call (a plugin invoking
its own endpoint) charges both its `plugin_out` at OUT and its `plugin_in` at IN.

**Remote operations** add Nodes-IN. When a call arrives from a remote peer, the
inbound networking handler charges `nodes_in(peer)` once; the global
`framework_in` is charged exactly once per remote operation as well (via the
handler's re-entry into the local dispatch for execute, or directly in the event
handlers). Per-peer flooding is reported as the `nodes_in` dimension rather than
the global cap.

### Who is charged

OUT charges attribute to the operation's *asserted identity* when impersonation
is in play, otherwise to the calling plugin. If plugin `A` is granted the
capability to act as `X` and asserts it, the `plugin_out` charge lands on `X`, not
`A`. See [capabilities.md](./capabilities.md).

Two framework-origin cases differ:

- **Lifecycle scope** (`on_load` / `on_enable` / `on_disable` and the calls they
  make) is stamped *exempt* and skips the limiter entirely, `framework_in`
  included, so a plugin's startup burst cannot rate-limit the boot sequence.
  Framework-internal `_core/` events are likewise structurally exempt.
- **System-origin / empty-chain** operations (a direct framework `execute`, a
  remote re-entry) are NOT exempt. They carry no plugin frame, so there is no name
  to key `plugin_out` on and the per-plugin OUT charge is simply skipped, but the
  global `framework_in` DOES charge them. That is deliberate: `framework_in` is the
  global backstop, and system-origin traffic should count against it so a runaway
  system task cannot escape the global cap.

---

## Configuration

Limits are configured in the main `config.yml` under a top-level `rate_limits:`
section. Every dimension is expressible. **All numeric values must be unquoted
numbers** (`max: 100`, not `max: "100"`); a quoted number is rejected at load.
Both `max` and `window` are required on every bucket and must be finite numbers
greater than 0. There is no "unlimited" value; omit a dimension to leave it
unlimited.

```yaml
rate_limits:
  framework_in: { max: 1000, window: 1 }      # 1000 ops/sec entering the node

  nodes_in:                                    # per remote peer
    default: { max: 200, window: 1 }           # every peer, unless overridden
    peers:
      trusted-node-b: { max: 2000, window: 1 } # this peer specifically

  plugins:
    SomeOrchestrator:
      out:       { max: 50,  window: 1 }       # plugin_out(SomeOrchestrator)
      in:        { max: 100, window: 1 }       # plugin_in(SomeOrchestrator)
      endpoints:
        llm:     { max: 20,  window: 1 }       # endpoint_in(SomeOrchestrator, llm)
      events:
        response:{ max: 30,  window: 1 }       # event_out(SomeOrchestrator, response)
      subs:
        my_topic_sub: { max: 40, window: 1 }   # sub_in(my_topic_sub)
```

### `nodes_in` (per-peer intake)

`nodes_in.default` applies to every remote peer; `nodes_in.peers.<hostname>`
overrides it for one peer. Both are optional: a `peers`-only block caps only the
named peers and leaves the rest unlimited; a `default`-only block caps every peer
uniformly. The hostname is the peer's mTLS cert-pinned identity from your
`networking.peers:` list (see [networking.md](./networking.md)). A peer may not be
named `default` (it is the reserved fallback key).

### Subscription limits key on the declared id

A subscription's runtime identity (its `sub_uuid`) is framework-generated and
unknown when you write the config, so `subs:` limits key on the subscription's
**declared id** (the key under `subscriptions:` in the plugin manifest), which the
framework resolves to the live subscription at registration. A purely runtime
subscription (one created in code with no declared id) cannot be capped by
`sub_in` from config; it is bounded only by its target's `plugin_in` / `endpoint_in`.

### Per-plugin self-declared limits

A plugin may ship sensible default limits for itself. Its manifest
(`plugin_config.yml`) may carry a top-level `rate_limits:` block with the same
per-plugin sub-shape (`out` / `in` / `endpoints` / `events` / `subs`), scoped to
itself:

```yaml
# in a plugin's plugin_config.yml
rate_limits:
  in: { max: 100, window: 1 }
  endpoints:
    expensive_op: { max: 5, window: 1 }
```

A plugin manifest may **not** declare `framework_in` or `nodes_in`; those are
operator-global and main-config only. The operator always has final say: a limit
set in the main `rate_limits.plugins.<name>` section **wins** over the plugin's
self-declared value for the same `(dimension, key)`. Plugin-declared limits that
the operator did not override fill the gaps.

### Reconfiguration

Changing a bucket's `max` / `window` takes effect live; the bucket keeps its
current token level (clamped down if `max` shrank) rather than resetting. Plugin
self-declared limits are re-read on a **plugin hot-reload**. Changing the main
`rate_limits:` section currently requires a restart (the same as `capabilities:`).

---

## What a reject throws

`RateLimitException` is a subclass of `RequestException`. How it surfaces depends
on where the bucket ran dry:

- **OUT reject (the caller's attempt).** Raised as `RateLimitException` directly to
  the calling code, before the operation is dispatched. The message names the
  binding dimension and the remaining tokens, for example
  `rate limit exceeded on plugin_out:SomeOrchestrator (0.000/50 tokens available, need 1.0)`.
- **IN reject on a 1:1 call (`execute` / `request_event`).** Raised at the
  delivery site and surfaced to the caller through the normal request-error path,
  so the caller sees a `RequestException` whose message carries the rate-limit
  reason.
- **IN reject on a 1:N fan-out (`publish_event`).** Fire-and-forget: the throttled
  per-subscriber delivery is dropped (the handler is not invoked); `publish_event`
  still returns its scheduled count. The reject is not raised to the publisher.
- **Remote reject.** A peer's reject travels back over the wire and is re-raised on
  the caller as `RateLimitException` (it is a trusted, round-trippable exception).

Catch `RateLimitException` specifically to distinguish a throttle from any other
`RequestException`.

---

## stream_weight

A streaming endpoint may cost more than one token per open, because one open can
produce many chunks. Declare `stream_weight` on the endpoint in its manifest:

```yaml
endpoints:
  big_stream:
    stream_weight: 2          # one open spends 2 IN tokens
```

The open charges `stream_weight` tokens against the IN-set once, at stream open
(not per chunk). A weight larger than the bucket's `max` is rejected at config
load, not silently at the first open. Stream weight is IN-only; the OUT side of a
stream open always costs 1.

---

## Observability

- **Every reject names itself.** The dry bucket's dimension and key are in the
  exception message, so "why was this blocked?" is always one line.
- **Per-bucket counters.** Each bucket tracks lifetime `charged` and `rejected`
  counts. `RateLimiter.stats()` returns a snapshot list of
  `{dim, key, charged, rejected, tokens, max}` records, the read surface for a
  metrics exporter or a dashboard.
- **Reject-log suppression.** A runaway caller hitting a cap thousands of times a
  second would otherwise emit thousands of WARNING lines. Instead, the first
  reject per `(dimension, key)` per ~10s window logs a WARNING; further rejects in
  that window only bump the counter; the next reject after the window logs a
  one-line summary of how many were suppressed. The counters carry the true
  volume; the logs carry the signal. The capability gate's security audit events
  are de-duplicated the same way (see [capabilities.md](./capabilities.md)).

---

## Performance

When no limit is configured, the charge path short-circuits on a single branch
and the caller-identity machinery stays inert, so a default node pays nothing.
When limits are active, the hot path iterates a precomputed list of bucket
references (no key building or dict walks per call) and reads the clock once per
operation. The only per-call allocation is the first-contact creation of a
`nodes_in` bucket for a newly-seen peer.

---

## Quick reference

- Off by default; opt in with `rate_limits:`.
- `max` and `window` are required, unquoted, finite, and greater than 0.
- Seven dimensions: `framework_in`, `nodes_in`, `plugin_out`, `plugin_in`,
  `endpoint_in`, `event_out`, `sub_in`.
- OUT charges the caller (or asserted identity) at entry; IN charges the target at
  delivery; remote adds `nodes_in`.
- `RateLimitException` (a `RequestException`) is raised on OUT and 1:1 IN rejects;
  fire-and-forget `publish_event` deliveries are silently dropped.
- Main config overrides plugin self-declared limits by path.
