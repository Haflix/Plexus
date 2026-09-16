# Networking

*Last updated for Plexus 0.81.0*

Plexus ships with an optional `NetworkManager` that bridges plugin calls between nodes over an mTLS-pinned TCP protocol. With networking enabled, calling `await self.execute("OtherPlugin", ...)` works whether `OtherPlugin` is on this node or another node. The same applies to `publish_event` and `request_event` (and their streaming variants).

The current implementation lives in the `plexus/netcore/` package. The old import path `plexus.networking` is now a thin compatibility shim that re-exports `plexus.netcore.NetworkManager` plus a handful of legacy symbols (`PeerSpec`, `Node`, `RemotePlugin`, `safe_loads`, `generate_keypair`, `FINGERPRINT_CLI_CMD`, a retired `AdvertSub` placeholder, and nine `DEFAULT_*` timing constants) so existing importers keep working. Two of those constants are still live rather than vestigial: `plexus/utils.py` imports `DEFAULT_HEARTBEAT_INTERVAL` and `DEFAULT_LIVENESS_TIMEOUT` from this path, so the shim cannot simply be deleted. The old advert-push / connection-pool / `MSG_*` machinery is gone by design.

This document covers the trust model, peer configuration, per-node port handling, the content-hash directory-pull model, liveness, discovery, the remote-reachability gate, how remote dispatch flows, and the wire protocol for advanced readers.

For the full configuration block reference, see [configuration](./configuration.md). For local notifier semantics that the remote `publish_event` / `request_event` paths extend, see [notifier](./notifier.md).

The netcore package is split into seven modules that this document maps onto:

| Module | Responsibility |
|---|---|
| `netcore/types.py` | Wire data shapes: the `Kind`/`ErrorKind`/`Mode` byte tables, `DirectorySnapshot`, `PeerSpec`, `CallerCtx`, the link exceptions. |
| `netcore/wire.py` | Framing + codec: encode/decode frames, the pickle-value vs msgpack-control split, chunking, per-cid reassembly. |
| `netcore/membership.py` | Roster, SPKI pins, tombstones, the mTLS context provider, liveness, the heartbeat pulse, discovery ingest. |
| `netcore/directory.py` | The content-hash directory: local snapshot derivation, remote-snapshot reconcile, the `route_*` routing seam. |
| `netcore/transport.py` | One bidirectional link per peer: dial election + supervisor, the write-pump, reassembly budgets, the flap guard, SPKI authentication, `InboundReject`. |
| `netcore/dispatch.py` | The cross-node CALL senders, error mapping, and the inbound authorize/dispatch seam. |
| `netcore/manager.py` | The `NetworkManager` root that composes four of the above (`Directory`, `Membership`, `Dispatch`, `Transport`; `types` and `wire` are shared support modules), parses config peers, and exposes `route_*` / the `*_remote` senders / `snapshot()` to core. |

---

## Trust model

Every node holds its own long-lived self-signed certificate. Peers trust each other by **certificate pinning** on the SubjectPublicKeyInfo (SPKI): there is no CA, no chain, no DNS-name verification. Each node's `peers:` config lists the exact other nodes it accepts.

- Each node has `cert.pem` and `key.pem` in `keys_dir` (default `keys/`). When neither file is present, `NetworkManager` generates a self-signed pair on first boot (`_load_or_generate_identity`).
- The fingerprint is `sha256:` followed by the hex sha256 of the SPKI DER. `NetworkManager` derives it at parse time from each peer's cert PEM (`_spki_from_pem`); a peer's `fingerprint` field is derived, never declared-and-trusted, so a fingerprint that cannot be produced from the cert is unrepresentable.
- **The SPKI pin is the sole authentication gate.** The TLS layer itself is deliberately permissive: `check_hostname=False`, `verify_mode=CERT_REQUIRED`, `minimum_version=TLSv1_3`, and every peer's self-signed cert is loaded as its own CA via `cadata` (`Membership._new_context`). TLS therefore only proves "the other end holds the private key for some cert we were handed"; the AUTHORITATIVE trust decision is the post-handshake SPKI check.
- On every connection, inbound or outbound, `Transport._authenticate` extracts the peer's presented SPKI, requires it in the LIVE pin set via `Membership.resolve_pin(fingerprint)`, and maps it to the expected hostname. An absent, unextractable, or unpinned SPKI **fails closed** (the socket is dropped). On a dial, the resolved hostname must also equal the peer's configured hostname, else the link is refused.
- **Contexts are rebuilt immutably on any roster change.** `Membership` never mutates a live SSL context in place; `add_peer` / `remove_peer` build brand-new server and client contexts from the new roster's cadata and rebind them. The bound listener socket is created once with a stable context whose `sni_callback` (`_sni_swap`) swaps in the current live server context per inbound connection, so a peer added at runtime is trusted at the TLS layer without re-binding the socket.
- An empty `peers:` list is tolerated: the acceptor binds with an empty-cadata listener and picks up the live context on the first `add_peer`, and the SPKI post-check plus the roster gate still reject any unpinned inbound. (A node with no peers simply has nothing to talk to until one is added via config or a vouch.)
- Beyond the connection-level pin, every inbound CALL runs an **anti-spoof gate** (see [The inbound seam](#the-inbound-seam)): the wire-claimed `author_host` must equal the hostname this peer was cert-pinned under, else the call is dropped and `_core/peer/hostname_mismatch` fires. In practice a mismatch is almost always config drift: the peer's `general.hostname` does not match the hostname in this node's `peers:` entry.

The legacy `node_ips:` schema is removed; its presence is a hard boot error pointing at `peers:`. The legacy top-level networking fields `secret` / `cert_file` / `key_file` are accepted but ignored (SPKI pinning replaced the shared secret).

---

## Peer configuration

The `networking.peers:` list is the authoritative trust store. Each entry binds a peer hostname to an IP/port, a certificate, and an optional fingerprint assertion.

```yaml
networking:
  enabled: true
  port: 2510                  # cluster default port; per-peer overrides allowed
  hostname: ""                # empty = socket.gethostname()
  keys_dir: "keys"            # where this node's cert.pem / key.pem live
  # NOTE: there is no effective `hostname:` key here. netcore takes its
  # identity from general.hostname; a networking.hostname value is ignored
  # (it survives only as a rebuild trigger for backward compatibility).
  discoverable: false         # opt in to vouch-discovery (legacy
                              # auto_discoverable / direct_discoverable accepted as aliases)

  peers:
    - hostname: alpha
      address: "10.0.0.1"
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBg...
        -----END CERTIFICATE-----
      fingerprint: "sha256:abcd...ef"  # optional; if set must match derived
      system_caller: false             # optional

    - hostname: beta
      address: "10.0.0.2:2511"          # per-peer port
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBg...
        -----END CERTIFICATE-----
```

| Field            | Type    | Required | Notes                                                                                                          |
|------------------|---------|----------|----------------------------------------------------------------------------------------------------------------|
| `hostname`       | `str`   | yes      | Peer's logical name and the routing key. Reconnects / IP changes never invalidate routing state, which keys on hostname. |
| `address`        | `str`   | yes      | `"ip"` or `"ip:port"`. A bare IP uses the cluster default port; a trailing `:port` overrides it. The split is on the LAST colon with a digits-only suffix, so a bracketless IPv6 literal such as `::1` is misparsed — bracket it or give it an explicit port.    |
| `cert_pem`       | `str`   | yes      | Inline PEM body (YAML block scalar). This is the only supported form — there is no `cert_file` option; an entry without `cert_pem` is rejected as malformed and skipped with a warning. |
| `fingerprint`    | `str`   | optional | `sha256:<hex>`. If set, must match the fingerprint derived from the cert, else the entry is rejected.           |
| `system_caller`  | `bool`  | optional | Default `false`. When `true`, this peer's inbound calls may act as the privileged `"system"` identity. See [Cross-node identity](#cross-node-identity-and-the-system-caller). |
| `dial`           | `str`   | optional | Per-edge dialer override for a NAT edge. Its PRESENCE (any value) flips this side into a dialer when hostname-lex election would otherwise make it the acceptor; it dials the peer at its configured `address` (the field's value is never read). Rarely needed. |

Parse-time validation (a bad entry is skipped with a warning during a normal boot; the hot-reload pre-validation gate is strict and aborts the reload instead):

- Malformed entry (missing `hostname` / cert, unparseable cert PEM).
- Declared `fingerprint` does not match the derived fingerprint.
- Duplicate fingerprint across the peers list.
- Duplicate `(ip, port)` across the peers list.

A printable fingerprint helper is available via the networking CLI for paste-into-config workflows (`FINGERPRINT_CLI_CMD`).

---

## Per-node port

Most clusters use one port for everything (`networking.port`, default `2510`). When you need otherwise (for example a parent and a child node on the same host), a peer entry's `address:` overrides the port:

- `"10.0.0.1"` maps to `(10.0.0.1, cluster_default_port)`
- `"10.0.0.1:2511"` maps to `(10.0.0.1, 2511)`

There is **one long-lived bidirectional link per peer** (keyed by hostname), not a connection pool: a parent and a child on the same IP are still two distinct peers with two distinct links, distinguished by hostname and port. The old `pool_size` knob is retired.

Use cases:

- Two Plexus instances on the same host (parent plus isolated child node).
- A peer behind NAT exposing a non-standard port.

---

## The directory-pull model

Each node maintains, for every peer, a cached `DirectorySnapshot` describing what that peer exports. There is **no advert push, no delta, and no ack**: a node never volunteers its subscription table to peers. Instead, every heartbeat the pinger PULLS the peer's directory, gated by a single content hash.

### Content hash is the sole freshness token

Each heartbeat, the pinger sends `PING{have_hash}` where `have_hash` is the `content_hash` it last cached for that peer (or `""` if it has none). The peer replies `PONG{epoch, content_hash, snapshot_follows}`, where:

```
snapshot_follows = (have_hash != current content_hash)
```

- If the hashes match, the PONG is header-terminal: nothing else is sent. A steady peer costs only PING/PONG headers per heartbeat.
- If they differ, `snapshot_follows` is `true` and the full `DirectorySnapshot` trails on the SAME cid as a run of `CHUNK` frames, settled by an `END` frame. So a changed peer ships its snapshot exactly once, on the pulse after it changed.

The `content_hash` is re-derived from the LIVE plugin/subscription registry on every serve (`Directory.build_pong` → `_export_snapshot` → `_content_hash`), in one synchronous await-free pass. There is no version counter, no monotone guard, no memo. The hash is a **recursive canonical sha256** over the exported endpoints, subs, and vouched peers (strings NFC-normalized, lists ordered by canonical content, `arguments` canonicalized full-depth). The builtin `hash()` is deliberately not used.

Deliberately EXCLUDED from the hash (they are identity, not content, so a same-content reboot re-derives the SAME hash and forces no needless re-apply):

- `epoch` — a `uuid4` boot nonce.
- the per-boot `plugin_uuid` and `sub_uuid` values (regenerated every boot, never persisted).

Those fields still ride the exported wire shape; only the freshness hash omits them.

`epoch` is a restart signal only. It rides the PONG header and is tracked in `Membership` independently of the apply decision: when a peer's `epoch` changes, `_core/peer/restarted` fires even if a same-content reboot means the snapshot itself did not change.

Applying a fetched snapshot (`Directory.replace`) is one synchronous roster-gated critical section: apply only if the peer is in-roster and the content hash actually differs; on apply, atomically rebind the remote-snapshot map and fire `_core/directory/replaced`.

### What is in a snapshot

`_export_snapshot` builds the immutable snapshot from the live registry with these export filters:

- **Endpoints** (`EndpointEntry`): exported only if the endpoint is `remote` AND `enabled` AND its owner plugin is active AND `accessible_by_other_plugins` is true. Each entry carries `access_name`, `plugin_name`, `plugin_uuid`, `plugin_version`, `description`, `arguments`, `tags`, and the `remote` / `accessible_by_other_plugins` flags.
- **Subs** (`RemoteSub`): exported only if the sub is `remote`-eligible (`enabled` AND `hosts != "local"`) AND its owner plugin is active. Carries `sub_uuid`, `topic_pattern`, the raw `authors` / `blocked_authors` / `hosts` / `blocked_hosts` filter values, and `plugin_name`. The filter values are exported RAW (a bare string like `"any"` stays a single token) so the receiver's filter chain interprets them identically to a local sub.
- **`vouched_peers`** (`VouchedPeer`): the node's CONFIG-ORIGIN peers only (single-hop; learned peers are never relayed), included in EVERY snapshot regardless of this node's own `discoverable` setting and folded into the content hash. Whether a RECEIVER acts on them is the `discoverable` gate (see [Discovery](#discovery)).
- **`tagged`**: a derived index (tag → endpoints) rebuilt from the endpoint tags; it is not serialized (the receiver re-derives it on decode).

The snapshot body is encoded as **msgpack**, never through the pickle allowlist (see the [codec split](#codec-split)), so a possibly-compromised vouched peer's snapshot can never reach the unpickler. On decode, count bounds drop an over-large snapshot whole (that peer becomes un-routable rather than partially applied): at most `10000` endpoints, `10000` subs, `256` vouched peers.

### Serving is floor-gated

`Directory.serve_ping` allows at most one PONG per `ping_floor_interval` window per peer. A below-floor PING returns nothing, so a PING flood cannot flood PONGs or snapshot serves on the shared loop. An at-interval PING (at least one floor apart) is always answered.

---

## Liveness and heartbeat

Liveness is pure `last_seen` age-out on the monotonic clock. There is **no strike counter and no `_mark_node_dead`**.

- `Membership.pulse_all` is a single task that, each `heartbeat_interval`, pings every rostered peer CONCURRENTLY (`asyncio.gather`), so one slow or catatonic peer cannot delay the others. Each ping uses the smaller per-probe `probe_timeout` budget, not `liveness_timeout`.
- A successful pulse stamps `last_seen = monotonic()` (roster-gated, so a revoke mid-await is safe). A `pong.epoch` change fires `_core/peer/restarted`.
- `reachable_set` is recomputed each pulse as `roster INTERSECT { p : now - last_seen[p] < liveness_timeout }`. A peer that transitions reachable → unreachable on a pass fires `_core/peer/down` with reason `unreachable`, edge-triggered (once, on the transition).
- `reachable(peer)` is simply `(monotonic() - last_seen) < liveness_timeout`.

So transient-blip tolerance is not a separate knob: it is `liveness_timeout / heartbeat_interval` (default `30 / 10 = 3` missed pulses). Widen it by raising `liveness_timeout`. A peer that ages out or is revoked simply drops out of `reachable_set` and stops being a routing target; there is no explicit "dead" transition. Keep the pulse-timing knobs (`heartbeat_interval`, `probe_timeout`, `liveness_timeout`) sane and positive: unlike the reassembly and timeout caps (which clamp a non-positive value back to their default), the timing knobs are used as given, so a `0` busy-spins the pulse or marks every peer instantly unreachable, and a non-numeric `liveness_timeout` fails the boot.

Two failure modes are distinguished at the transport layer:

- A **refused** dial (`LinkRefused`, e.g. `ECONNREFUSED`) hard-downs the peer immediately by stamping `last_seen = -inf`, so a peer that is up-but-not-listening goes unreachable fast rather than waiting out the timeout.
- A **dropped or timed-out** link (`LinkDown` / `Timeout`) simply ages out via `last_seen`.

When a link comes up (dialed or accepted), `Membership.on_link_up` stamps `last_seen`, adds the peer to `reachable_set` immediately, fires `_core/peer/up`, and kicks a one-shot pulse to fetch the directory. This gives a routable-within-a-heartbeat-of-link-up guarantee.

---

## Discovery

Discovery is a single opt-in gate: `discoverable` (default `false`). It replaced the old three-flag model; legacy `auto_discoverable` / `direct_discoverable` are accepted as aliases (either one `true` maps to `discoverable`).

**Advertising.** EVERY node includes its CONFIG-ORIGIN peers in the `vouched_peers` list of the snapshot it serves, regardless of its own `discoverable` setting. This is single-hop only: a node never relays peers it itself learned by vouch, only ones it was configured with. The export is unconditional; the `discoverable` flag gates only the RECEIVER, below.

**Ingesting.** A `discoverable` RECEIVER, on each pulse, feeds a peer's advertised `vouched_peers` through `Membership.ingest_vouched`. An OFF node ignores them entirely (it never pins a learned peer, so a star stays a star; an edge forms only when BOTH ends are `discoverable`). Ingest is fully validated and budgeted:

- If the voucher is tombstoned or no longer in-roster at apply time, the whole batch is dropped.
- A hostname that is tombstoned is skipped.
- A CONFIG pin is never overwritten; a re-vouch of a known hostname is idempotent; a fingerprint conflict with an existing roster entry fires `_core/peer/vouch_conflict` and is otherwise ignored.
- A per-voucher ACTIVE budget cap (`vouch_active_cap`, default 64) bounds how many peers one voucher may introduce; over-budget fires `_core/peer/vouch_rejected` with reason `budget`.
- Every config-time validation is mirrored before the entry reaches the roster: the cert must parse, its derived SPKI must equal the declared fingerprint, the fingerprint must not duplicate an existing pin, the address must parse, it must fall inside `lan_cidrs`, and its `(ip, port)` must not duplicate an existing peer. Each failure fires `_core/peer/vouch_rejected` with a specific reason (`cert_parse`, `fingerprint_mismatch`, `dup_fingerprint`, `bad_address`, `cidr`, `dup_address`).
- An accepted vouched peer is added with `system_caller=False` **always**. Discovery confers no privilege escalation. Its acceptance fires `_core/peer/vouched`.

Explicit `peers:` pins work regardless of `discoverable`.

### Tombstones and revoke durability

`Membership.remove_peer` writes a HOSTNAME-keyed persisted tombstone to `revoked_peers.json` in `keys_dir` (atomic tmp-file + replace, so a crash mid-write cannot corrupt the revoke list). The revoke also removes the peer from the roster and pin set, rebuilds the SSL contexts, clears its liveness, drops its cached remote snapshot, decrements its voucher's active budget, and tears down the link.

A persisted tombstone is cleared ONLY by an explicit operator `add_peer`. `seed_config_peers` skips a hostname whose runtime-revoke is persisted, so a revoke survives a restart even if the peer is still listed in `peers:`.

---

## The remote-reachability gate

An endpoint is reachable cross-node if and only if **all three** hold:

1. The plugin's manifest has top-level `remote: true`.
2. The endpoint's entry has `remote: true`.
3. The endpoint's entry has `accessible_by_other_plugins: true`.

This is enforced at two points, both of which must agree:

- **On the exporting side**, `Directory._export_snapshot` only lists an endpoint whose exported `remote` flag (which is itself `plugin.remote AND endpoint.remote`, computed in `NetworkManager._export_endpoints`) is true AND `accessible_by_other_plugins` is true AND the endpoint is enabled AND the owner plugin is active. An endpoint failing any of these never appears in the directory a peer pulls, so peers never route to it.
- **On the callee side**, when a CALL arrives, `NetworkManager._RematchRegistry._match_execute` re-checks the LIVE registry: the plugin must be enabled, the name must match, `plugin.remote AND endpoint.remote` must hold, and `accessible_by_other_plugins` must be true. A miss raises `NoEndpointError`, which the callee returns as `NO_ENDPOINT`.

> **Correction vs. older docs.** Earlier documentation stated that `accessible_by_other_plugins` was NOT consulted for inbound peer requests (only for local cross-plugin access). That was true of the retired `plexus/networking.py`; it is FALSE for netcore. An endpoint that is `accessible_by_other_plugins: false` is **not** reachable across the wire even if `remote: true`, because both the export filter and the callee re-match require it.

**UUID targeting survives cross-node.** An `execute(..., plugin_uuid=...)` call carries the `plugin_uuid` in its selector. The callee re-rejects a call whose selector `plugin_uuid` does not exactly match the live instance with `NO_ENDPOINT` (so a same-name / different-uuid instance never answers). A `NO_ENDPOINT` reply falls through to the next candidate peer.

---

## Remote dispatch flows

Core keeps local dispatch in the untouched in-process notifier; the netcore layer supplies the routing candidates and the cross-node CALL senders. The unifying change from the old code: **fall-through order is hostname-lexicographic**, not advert insertion order.

### CALL modes

Every cross-node call is one `CALL` frame carrying a mode:

| Mode | Used by | Reply |
|---|---|---|
| `UNARY` | `execute` | single value, or an `ERROR` frame |
| `FIRST` | `request_event` | single value, or an `ERROR` frame |
| `STREAM` | `request_event_stream` / streaming `execute` | a run of `CHUNK`-carried items, `END`-terminated |
| `FANOUT` | `publish_event` | none (fire-and-forget) |

### `execute`

Core asks `route_execute(plugin, endpoint)`, which yields `(hostname, endpoint_entry)` for every reachable, in-roster peer that exports the `(plugin, endpoint)` pair, in **hostname-lexicographic** order. Core sends a `CALL{mode=UNARY}` to the first; the value comes back on `END`, or an `ERROR` frame comes back. A `NO_ENDPOINT` (uuid miss / `remote:false` / not accessible) or a `NETWORK` error falls through to the next candidate.

### `request_event`

Core tries local subscriptions first. On a local miss it asks `route_request(topic)`, which yields `(hostname, RemoteSub)` for reachable, in-roster peers whose cached subs topic-match, in **hostname-lexicographic** then declaration order. Routing is UNFILTERED beyond topic-match and reachability: core applies the author/host predicate chain (`_hosts_match`, remote-publisher, author filters) per candidate. The first surviving candidate gets a `CALL{mode=FIRST}`.

Fall-through by reply type:

- `NoLocalSubException` (peer had no matching sub either) or `NetworkRequestException` (transport failure / peer down): SKIP, try the next candidate.
- `RateLimitException` / `CapabilityException`: PROPAGATE immediately.
- A handler that ran and raised: PROPAGATE (see [Error mapping](#error-mapping)).
- Exhausted candidates: `RequestException` "no subscriber matched".

The streaming variant (`request_event_stream`) has identical fall-through semantics PRE-FIRST-CHUNK. Once the producer yields its first chunk, dispatch is committed to that peer and later errors do not redirect.

### `publish_event`

Local subscribers are dispatched in-process. For remote fan-out, core asks `route_publish(topic)`, which GROUPS matching subs per peer: `(hostname, list[RemoteSub])`. Core applies its predicates per sub, sums the surviving matches into the scheduled count, and sends **one** `CALL{mode=FANOUT}` frame per peer (not one per sub). The return value is the scheduled count (local plus the sum of matching remote subs across reachable peers), not a completion count. A FANOUT has no reply channel, so the caller observes nothing either way and a down peer is dropped silently. On the wire it is not strictly silent: a reject raised during header authorization (rate limit, spoof, revoked peer, per-peer cid cap) still emits an `ERROR` frame, which the sender discards because no `Pending` was registered. Rejects after the args arrive are mode-checked and genuinely suppressed.

### Error mapping

`Dispatch._map_error` maps an `ERROR` frame's `kind` to the exact caller-facing exception type:

| `ERROR.kind` | Raised as | Caller behavior |
|---|---|---|
| `NO_MATCH` | `NoLocalSubException` | fall through |
| `NETWORK`, `NO_ENDPOINT` | `NetworkRequestException` | fall through |
| `RATE_LIMIT` | `RateLimitException` | propagate |
| `CAPABILITY` | `CapabilityException` | propagate |
| `HANDLER_RAISED` | the deserialized exception, re-raised (with the wrapping rule below) | propagate |

Link-level failures (`LinkDown` / `LinkRefused` / `Timeout` / `ProtocolError`) surface as `NetworkRequestException` (fall through).

`HANDLER_RAISED` carries a real improvement over the old code, which flattened the exception type. Netcore re-raises the deserialized handler exception faithfully, with two guards:

- If the deserialized exception is itself a `NetworkRequestException` or `NoLocalSubException`, it is WRAPPED in a plain `RequestException`. Otherwise the notifier's fall-through arm would mistake a genuine handler failure for a network miss and silently re-run a side-effecting handler on the next peer.
- A non-`RequestException` (e.g. a bare `ValueError`) is also wrapped in `RequestException`, so `request_event`'s documented contract (raises `RequestException`) holds; a `RequestException` subtype (`RateLimit` / `Capability`) is preserved so callers can `except` it by type.

---

## The inbound seam

The callee side is a two-call seam in `Dispatch`, driven by `Transport` before and after arg buffering.

`authorize_inbound(identity, frame)` runs SYNCHRONOUS header authorization BEFORE any arg CHUNK is buffered, in this order:

1. **Charge `nodes_in`** on the authenticated hostname (this counts as an attempt, and stands even if a later step rejects). A rejection here is `RATE_LIMIT`.
2. **Anti-spoof:** the wire `caller.author_host` MUST equal the authenticated (pinned) hostname. A mismatch fires `_core/peer/hostname_mismatch`, emits `_core/net/reject`, and drops the call (`NETWORK`).
3. **Live-roster re-check** (closes the revoke window). A miss is `NETWORK`.
4. **Charge the callee's `framework_in`** — but ONLY for events (`TopicSelector`). An `execute` (`ExecuteSelector`) charges `framework_in` inside its own `core.execute` re-entry, so charging it here too would double-charge.

A success emits `_core/net/inbound`.

`dispatch_inbound(identity, frame, args)` then re-matches against the LIVE registry with the authoritative per-sub / per-endpoint filters (the registry seam owns them and charges the IN-set on the local re-entry), runs the handler bounded by `handler_timeout`, and emits the typed reply. The `identity` is built from the authenticated roster record, never the wire.

The IN-set charge happens in the registry re-entry, not in `authorize_inbound`, so a call that fails re-match is not charged the IN-set.

### Cross-node identity and the system caller

The right to act as `author="system"` is granted SOLELY from THIS node's authenticated record for the calling peer (`identity.system_caller`, set from the peer's `system_caller: true` config flag), NEVER from the wire. A spoofed `author="system"` claim on an inbound frame is downgraded (to the wire `author_id` or the peer hostname) before the registry re-entry, so no downstream seam ever observes a wire-asserted system author it did not grant. See [capabilities](./capabilities.md) for the cross-node impersonation non-goal.

---

## Wire protocol

For tooling authors and protocol debuggers. The framing and codec live in `netcore/wire.py`; the byte tables in `netcore/types.py`.

### Framing

Each frame is:

```
[4B big-endian length][1B kind][8B big-endian cid][ fields ]
```

The length prefix EXCLUDES its own 4 bytes; it counts `[kind][cid][fields]`. A declared length below the minimum, or above `MAX_FRAME_BYTES` (`CHUNK_SIZE + 1 MB`), is a malformed frame → `ProtocolError` → the link is TORN (see [Tear vs. cancel](#tear-vs-cancel)).

The `cid` (correlation id) is a per-link 63-bit counter with the high bit reserved for the DIAL ROLE (dialer allocates with the high bit set, acceptor with it clear), so the two ends never collide on a cid and a frame's owner is decidable from the bit.

### Frame kinds

There are exactly SEVEN kinds, in three roles:

| Kind | ID | Role | Purpose |
|---|---|---|---|
| `PING` | 1 | control / priority | Heartbeat + directory pull; carries `have_hash`. |
| `CALL` | 2 | app opener | Opens a cross-node call; carries the selector, mode, caller, and `handler_timeout`. Args trail as `CHUNK`s. |
| `CANCEL` | 3 | control / priority | Cancel an in-flight cid (either direction). |
| `PONG` | 4 | control / priority | PING reply; carries `epoch`, `content_hash`, `snapshot_follows`. |
| `CHUNK` | 5 | data | One fragment of a logical value (args / result / stream item / snapshot body); carries `last`. |
| `END` | 6 | terminator | Value-less; settles a unary reply, a stream, or a trailing snapshot. |
| `ERROR` | 7 | terminator | Value-less envelope carrying an `ErrorKind` and an optional pickled `exc`. |

Control frames (`PING` / `PONG` / `CANCEL`) ride a priority write lane and preempt between a value's chunks, so a large value cannot head-of-line-block a heartbeat.

### Codec split

Two codecs, chosen by what the bytes ARE:

- **Control fields, the `DirectorySnapshot`, and `vouched_peers` are msgpack.** These are inert structured data.
- **A logical VALUE — CALL args, a unary/FIRST result, a stream item, or the `ERROR.exc` payload — is `pickle` on the send side and the restricted `SafeUnpickler` allowlist (`safe_loads`, NOT raw `pickle.loads`) on the receive side, AFTER full reassembly, never per-chunk.** The `ERROR.kind` decodes independently of `exc`, so the disposition is known without touching the pickle path.

Critically, the directory snapshot is msgpack ONLY and is never routed through the pickle allowlist, so a compromised vouched peer's snapshot cannot reach the unpickler via the discovery / PONG path.

### Chunking and reassembly

Every logical value is sliced into one or more `CHUNK{cid, data, last}`. A value ≤ `CHUNK_SIZE` (64 KB) is a single `CHUNK{last=true}`; a larger value splits with `last=true` only on the final fragment. `CHUNK.data` is opaque bytes at byte offsets (no per-chunk msgpack wrap).

Reassembly is bounded at three levels; the config knob names match [configuration](./configuration.md):

| Bound | Default | Config knob |
|---|---|---|
| per in-flight message (per cid) | 8 MB | `per_cid_reassembly_cap` |
| across all in-flight messages from one peer | 16 MB | `per_peer_reassembly_cap` |
| aggregate across all peers | 128 MB | `node_reassembly_cap` |

The largest single value you can receive is `min(per_cid, per_peer)`. A per-peer guaranteed minimum (2 MB) is always admitted regardless of the node-wide total, so a newcomer can always start SOME reassembly. Independently, one peer may have at most `per_peer_cid_cap` (default 64) concurrent inbound CALLs open at once; a CALL past that cap gets an immediate `ERROR{NETWORK}` before any arg is buffered. Two per-reassembly deadlines also bound a slow drip: an absolute 60 s deadline (armed at the CALL header, not at the first chunk, so a peer that opens a cid and then withholds every arg chunk is still bounded) and a per-chunk idle deadline (`stream_idle_deadline`, default 30 s), both on the monotonic clock.

### Tear vs. cancel

The distinction matters operationally:

- A **malformed FRAME** (bad length, unknown kind byte, undecodable control payload) is a `ProtocolError` and is the ONLY condition that TEARS the link (drops it and fast-fails its pending requests).
- **Exceeding a reassembly bound or a per-reassembly deadline** FAILS CLOSED for that one cid only: send `CANCEL`, free the budget, and KEEP the link. It also emits `_core/net/reject` with reason `reassembly_bound`. A hostile or buggy oversized message costs you the message, not the link.

For a PING that promised `snapshot_follows` but then trips a bound, the header already settled the peer as reachable, so the snapshot resolves to nothing and the peer STAYS reachable; only a genuine link-down fails the pending snapshot.

---

## Network-side exceptions

| Exception | Base | When |
|---|---|---|
| `NetworkRequestException` | `RequestException` | Transport-level failure or a peer `NETWORK` / `NO_ENDPOINT` reply on a remote dispatch. Fall-through-safe. |
| `NoLocalSubException` | `RequestException` | Peer signalled "no local sub matched" (`NO_MATCH`) on a remote `request_event` / stream. Distinct subclass so fall-through can continue in hostname-lex order. |
| `RateLimitException` | `RequestException` | Peer rejected the call at its inbound rate limiter (`RATE_LIMIT`). Propagates. |
| `CapabilityException` | `RequestException` | Peer denied the call at its capability gate (`CAPABILITY`). Propagates. |
| `NodeException` | `Exception` | Generic node-level error in helper paths. |
| `RequestException` | `Exception` | Generic plugin-call error, including a wrapped remote `HANDLER_RAISED`. |

For most callers, `except RequestException:` covers all of the above (the four network subtypes descend from it). Catch `NoLocalSubException` separately only when you need to distinguish "peer-side miss" from "peer-side handler raised".

---

## Observability events

The netcore modules emit `_core/*` events through the core notifier's internal observer bus. Subscribe with `Plugin.internal_observe(topic, callback)`. This is the operational surface for a dashboard or an alerting feed.

| Event | Emitted when | Payload highlights |
|---|---|---|
| `_core/peer/up` | A link comes up (dialed or accepted). | `hostname` |
| `_core/peer/down` | A peer transitions to unreachable (reason `unreachable`, edge-triggered), or is revoked (reason `revoked`). | `hostname`, `reason` |
| `_core/peer/restarted` | A peer's `epoch` changed on a PONG (it rebooted). | `hostname`, `epoch` |
| `_core/peer/vouched` | A vouched peer was accepted by discovery. | `hostname`, `fingerprint`, `voucher_hostname` |
| `_core/peer/vouch_conflict` | A vouch's fingerprint conflicts with an existing roster entry. | `hostname`, existing / vouched fingerprints, `voucher_hostname` |
| `_core/peer/vouch_rejected` | A vouch failed validation. | `hostname`, `reason` (`budget` / `cert_parse` / `fingerprint_mismatch` / `dup_fingerprint` / `bad_address` / `cidr` / `dup_address`), `voucher_hostname` |
| `_core/peer/hostname_mismatch` | An inbound call's wire `author_host` did not match the authenticated hostname (anti-spoof). | `authenticated`, `claimed` |
| `_core/net/inbound` | An inbound call passed header authorization. | `hostname` |
| `_core/net/reject` | An inbound call or a reassembly was rejected. | `reason` (`nodes_in` / `hostname_mismatch` / `not_in_roster` / `framework_in` / `reassembly_bound`), `hostname` |
| `_core/directory/replaced` | A peer's cached directory snapshot was replaced with fresher content. | `hostname`, `content_hash` |

`NetworkManager.snapshot()` also exposes a point-in-time view for the TUI: per peer, its address, fingerprint, reachability, `last_seen` age, live epoch, cached content hash, an `unreachable_reason` (`connection_refused` vs `unreachable`), discovery `source` (`config` / `vouched`) and `vouched_by`, plus the cached routing table (subs + endpoints).

---

## Tag discovery is heartbeat-fresh

`find_endpoints_by_tag(tag)` reads the CACHED directory (`route_tagged`), collecting remote endpoints carrying the tag plus local endpoints (with the self-host normalized to `local`). Because the directory is pulled at heartbeat cadence, a tag view is at most one heartbeat stale. An orchestrator that discovers tools (for example the `ai_tool` tag) should RE-QUERY at use time, not cache the result at `on_enable` — a peer that comes up, changes, or goes away after enable would otherwise be missed or stale.

---

## Adding a new node to an existing cluster

Once at least one node already has a `cert.pem` and is in another node's `peers:` list, the normal mTLS pinning flow applies. To add a new node:

1. Decide the new node's hostname (`general.hostname`, or empty for `socket.gethostname()` — note `networking.hostname` is **not** read by netcore) and port (`networking.port`, default `2510`).
2. Obtain the new node's SPKI fingerprint with the networking CLI fingerprint helper, and read the certificate body straight out of `keys_dir/cert.pem`.
3. On every existing node, add a `peers:` entry for the new node with hostname, address, and the inline `cert_pem:` block. Optionally pin `fingerprint:` for defense in depth.
4. On the new node, add `peers:` entries for every existing node (each with its cert and address).
5. Set `networking.enabled: true` on the new node and confirm the existing nodes still have it enabled.
6. Restart the new node (or hot-reload config). Existing nodes can pick up the new peer via config reload as well. Each side now pins the other; the mTLS handshake succeeds, the directory pull runs on the next heartbeat, and calls flow.

If a peer is offline at startup, that is fine: the link comes up when it returns (the per-peer supervisor dials with capped backoff). An empty `peers:` list is also tolerated: the node simply has nothing to talk to until a peer is added via config or, with `discoverable`, a vouch.

---

## Cluster bootstrap

Standing up a brand-new cluster from zero certificates follows a one-shot first-boot pattern. `NetworkManager` loads or generates the node's identity at CONSTRUCTION, before anything is served, so the very first run on a fresh node always produces `cert.pem` and `key.pem` even with an empty `peers:` list.

### Per-node bootstrap procedure

For each node, in any order:

1. Install the framework and write `config.yml` with `networking.enabled: true` and an empty `peers: []`.
2. Run the application once. Identity is loaded or generated into `keys_dir` (default `keys/`). An empty `peers:` list does not error — the node just waits for peers — so a first start is productive: it materialises `cert.pem` and `key.pem` for you to copy to the OTHER nodes.
3. Read the `sha256:...` fingerprint with the networking CLI fingerprint helper, and copy the certificate body from `keys_dir/cert.pem`. Neither value is logged at startup, so the files and the CLI are the only sources.
4. Exchange fingerprints and cert PEMs between nodes out of band. Each node's `peers:` block needs at least one entry per other node it wants to reach, with that peer's `hostname`, `address`, `cert_pem`, and optionally `fingerprint`.
5. Start each node again. With `peers:` populated, each node builds its SSL contexts, binds the listener, seeds its peers, and starts the heartbeat pulse.

### Getting this node's fingerprint on first start

Identity is loaded (or generated) at `NetworkManager` construction, before anything is served, so even a node with an empty `peers:` list comes up and writes `cert.pem` / `key.pem` into `keys_dir`. That is the data you need to populate `peers:` on the OTHER nodes, so a first start is productive even before this node has any peers of its own. Note that neither the fingerprint nor the cert PEM is logged — read them from `keys_dir/cert.pem` and the networking CLI fingerprint helper.

---

## Operational notes

- Peers connect over a single long-lived bidirectional link per peer. There is no connection pool; the old `pool_size` knob is retired.
- Which side dials is decided by lexicographic hostname election (the lex-lower hostname dials); the lex-higher side is a pure acceptor. A per-edge `dial:` override lets a NAT'd side dial as a fallback while no link exists. A brief double-connect is resolved by a deterministic survivor plus a flap-guard probation, so a reconnect race does not thrash.
- Subscribe / unsubscribe events log at INFO regardless of `verbose_notifier` — useful when debugging cross-node subscription state.
- Legacy fields `secret` / `cert_file` / `key_file` at the top of `networking:` are accepted but ignored. The `node_ips:` field is a hard error.
- A pin failure on inbound mTLS is logged at INFO, not WARNING — a port scanner sweeping the listener would otherwise bury real security events.
- All networking knobs are read once at `NetworkManager` construction. A config change to a timing / discovery / timeout / cap knob alone is adopted on the next rebuild (triggered by a change to `peers` / `port` / `enabled` / `hostname` / `keys_dir`) or on a full restart, not live mid-run.
