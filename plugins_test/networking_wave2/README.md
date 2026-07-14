# networking_wave2 — wave-2 COOPERATIVE socket cells (batch 1)

Real multi-node acceptance net for the networking rewrite. Boots real rewrite
nodes (driver + 1-2 peers) and drives the cooperative wave-2 cells through
`Wave2Driver`, asserting the §A public surface. Validates against the winning
rewrite POST-combine (no rewrite is deployed yet; cannot run on current code —
uses `snapshot()` / `_core/*` / rewrite config keys). Gated behind
`PLEXUS_PAIR_TEST`.

```
PLEXUS_PAIR_TEST=1 python -m pytest plugins_test/networking_wave2/
```

## Pieces
- `wave2_node.py` — generic N-peer node runner (injects port/keys/peers/knobs;
  exports env for the fixture plugins).
- `config.{driver,peer,peer2,peer_changed}.yml` — role configs (hostnames
  w2a-driver < w2b-peer < w2c-peer2 so dial election is deterministic).
- `Wave2Driver/` — the in-node cell driver (CaseRecorder; group/cell via env;
  drives the four primitives + NetFixTarget/NetObsProbe/NetCtl; writes a result
  file). Fixtures live at `plugins_test/{NetFixTarget,NetObsProbe,NetCtl}`.
- `_wave2_harness.py` — spawn/keypair/topology helpers for the pytest.
- `test_wave2_cooperative.py` — spawns each topology, asserts the driver result
  (fails the pytest on any failed/errored cell), plus the lifecycle + P-cell tests.

## Groups → topology → cells
- **pair** (2 mesh): TP-55, TG-05, TP-56, TG-08, TP-05b, TP-17b, TP-04, TP-34,
  TP-32/TG-07, TG-24, TG-12, TG-15, TG-01b, TG-22(inbound half), TG-06.
- **trio_mesh** (3 mesh): TG-03, TG-01, TG-23, TG-02(rate half; capability half
  skip-noted), TP-53.
- **star** (driver pins only the hub): TP-35.
- **discovery** (discoverable + hub vouches peer2): TP-43, TG-21, TP-44,
  TP-50 / TP-47 (skip-noted unless the boot wires an orphan victim / vouch cap).
- **lifecycle** (phase-coordinated kill/respawn/reload, one cell per boot):
  TP-08, TP-09, TP-11, TP-30, TP-31, TP-14, TP-39, TG-14 (+ TP-36 handler ready,
  needs an add_peer spec).
- **P-cells** (boot behavior): TP-15 (own-keypair mismatch → LOUD abort),
  TP-58 (config-key migration → clean boot).

## Batch 2 — Type-X hostile + races (`test_wave2_hostile.py`, `test_wave2_races.py`)
- **`test_wave2_hostile.py`** (Type-X, via `net_hostile` HostileClient +
  HostilePongServer against a real target node whose NetObsProbe self-dumps to a
  file): TP-70 (unpinned SPKI + resumed), TP-71 (system-caller spoof), TP-72
  (anti-spoof), TP-73 (reassembly bound keeps link), TP-75 (slow-drip absolute
  deadline, `@slow`), TP-76 (PING-flood floor), TP-79 (malformed frame tears link),
  TP-80 (straggler discarded), TP-81 (reserved topic), TG-05b (per-cid ProtocolError
  keeps link, A10), TG-20 (SafeUnpickler RCE guard), TG-09 (guaranteed-minimum). //
  ACCEPTOR mode (node dials hostile): TP-74 (PONG-snapshot over-bound), TP-77/78
  (malformed / SPKI-mismatch vouched cert), TG-17 (over-count vouched_peers).
- **`test_wave2_races.py`** (fault-injected, driver lifecycle cells): TP-38
  (revoke-during-await via `pong_delay`), TP-46 (remove-mid-dial via StallListener),
  TP-51 (pulse survives poison), TP-37 (revoke stays gone), TP-41 (operator re-add),
  TG-04 (LinkRefused fast-path via a dead port).
- **`test_wave2_deadline_unit.py`** — TP-33/TG-18 injected-`now` unit test (skips
  until the branch exposes an injectable-clock deadline hook).
- **`WAVE2_BATCH2_FCASES.md`** — §F white-box items with no injectable §A observable:
  TP-33/TG-18 (monotonic anchor), TP-48 (removed-voucher in-flight), TP-49 (flap-guard
  no-tear half = §F#22).

**Type-X WIRE LAYOUT (A1) is DEFERRED:** the parent RE-POINTS `net_hostile/wire.py`
(the single site) to the WINNING branch's exact `[cid+fields]` byte layout at
combine/swap BEFORE running the Type-X cells.

Discovery follow-ups still skip-guarded unless the boot wires them: TP-40 (vouched
durability), TP-45 (fp-conflict), TP-47/TP-50 (vouch cap / orphan victim), TG-16
(voucher churn) — driver logic present; the extra per-cell topology is the wiring.

## Ambiguity dispositions applied
A4 dial-rate via `StallListener.connect_count`; A6/A8 event asserts presence-only;
A7 out_q drop = receiver all-or-nothing; A10 per-cid ProtocolError errors the cid +
KEEPS the link (TG-05b asserts link stays up).
