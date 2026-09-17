# net_hostile — Type-X hostile-peer harness (scaffold)

Raw TLS + frame client driving the §D adversarial cells (TP-70..81) + the Type-X
gap-hunt cells (TG-05b/09/17/18/20) against a rewrite node. NOT a cooperative
Plexus node: it exists to violate SPEC §5.

Status: SCAFFOLD. Cannot run yet (the §5 wire is rewrite-only; subagents cannot
run python). The parent wires it into the wave-2 socket suite once a branch lands.

## Files
- `wire.py` — SPEC §5 codec: kind table, 4B-BE length, cid high-bit=dial-role,
  msgpack control fields / opaque CHUNK data. `encode_frame` / `decode_frame` /
  `encode_raw` / `encode_cid`.
- `hostile_client.py` — DIALER mode. `HostileClient` (connect with an arbitrary
  cert, send/recv primitives, crafted-frame helpers), `make_client_ssl_context`,
  `pickle_args`, `StallListener` (victim listener counting connect attempts).
- `hostile_server.py` — ACCEPTOR / PONG-server mode. `HostilePongServer` (accept
  the node's dial, present a chosen cert, answer PING with a crafted PONG +
  optional crafted DirectorySnapshot), `make_server_ssl_context`,
  `make_snapshot_bytes`.

## Which mode a cell uses
- **Hostile DIALS node** (`HostileClient`): TP-70-inbound, TP-71/72/73/75/76/79/80/81,
  TG-05b/09/20. Give the hostile a LEX-LOWER hostname so it dials; the node pins it.
- **Node DIALS hostile** (`HostilePongServer`): TP-74, TP-77/78, TG-17,
  TP-70-outbound/vouched. Give the hostile a LEX-HIGHER hostname so the node dials;
  the node pins it (except TP-70-outbound-unpinned, which asserts SPKI rejection).

## Public API (summary)

`HostileClient(host, port, cert_file=, key_file=, server_cert_pem=, verify_server=)`
- `connect(reuse_session=None)` — TCP + TLS handshake. Raises `HostileConnError`
  when the node rejects the cert (the expected TP-70 outcome). `reuse_session` /
  the captured `.tls_session` attempts a TLS-1.3 resumed handshake.
- `close()`, context-manager (`with HostileClient(...) as cli:`)
- `next_cid()` — allocate a dialer cid (high bit set)
- `send_ping(have_hash=)`, `send_call(selector=, mode=, caller=, handler_timeout=)`,
  `send_chunk(cid, data, last=)`, `send_call_with_args(...)`, `send_cancel(cid)`,
  `send_end(cid)`, `send_error(cid, kind, exc=)`
- `send_raw(payload, declared_length=)` — malformed / lying-length frame (TP-79)
- `recv_frame(timeout=)` -> `wire.Frame(kind, cid, fields, data, last, raw_body)`
- `link_is_up(...)` — send a valid PING, require a PONG (TP-73/74/80 link-stays-up
  vs TP-79 link-torn)

`StallListener(host, port=0)` — `.start()`, `.stop()`, `.connect_count`,
`.connect_times` (the connection-attempt observable §A lacks; TP-50 / TG-19).

`pickle_args(obj)` — pickle bytes for a CALL's args (the node runs `safe_loads`
on the reassembled CHUNK payload).

## How a Type-X cell is structured (for the full-authoring round)

A hostile cell asserts on THREE surfaces:
1. The raw frame the node returns / omits (`recv_frame` + `wire`).
2. Link stays up vs torn (`link_is_up`).
3. §A `_core/*` events + `snapshot()` the NODE emits — captured by a cooperative
   OBSERVER plugin (`NetObsProbe`, a separate wave-2 fixture) co-located on the
   node subprocess, written to a result file the cell reads. The hostile client
   never sees §A directly.

The node subprocess is booted (extend `networking_pair/pair_node.py`) with the
hostile identity PINNED as a peer so the handshake completes and frames reach the
reader — except TP-70, which presents an UNPINNED cert and asserts rejection.

## WIRE-LAYOUT ASSUMPTION (must confirm before Type-X cells go green)

SPEC §5 pins the kind table, the 4B-BE length convention, cid-high-bit=dial-role,
and the codec split (control=msgpack / CHUNK.data=opaque). It does NOT pin, to the
byte, the internal layout of `[cid + fields]` (cid WIDTH + int encoding; where the
msgpack map starts; how CHUNK's `last` flag + opaque data sit vs the cid). This
scaffold assumes:
- control kinds: `[8B cid, BE uint64, high bit=role] + msgpack(fields_dict)`
- CHUNK: `[8B cid] + [1B last: 0/1] + [opaque data...]`

Change only `wire.py`'s constants + the two encode/decode branches if the landed
branch differs. This is BOTH a Type-X blocker AND a combine-compatibility pin (all
3 branches must encode identically or one harness can't drive all three). Top open
item in `WAVE2_TEST_MAP.md`.
