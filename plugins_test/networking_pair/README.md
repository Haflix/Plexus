# networking_pair — 2-node connection failure-angle harness

Real-socket integration tests that boot **two real Plexus nodes** as a
same-machine, mutual-mTLS-pinned, concurrently-booted pair (the actual
deployment topology, mirroring `plugins/Tools/PlexusTUI/smoke/tui_smoke_pair.py`).
This is the topology the in-process suites do **not** cover: `TestRemoteSuite`
brings the parent up first and connects a subnode, which dodges the boot-race
class of bugs.

## Run it (opt-in)

These tests are **gated behind `PLEXUS_PAIR_TEST`** so a blanket
`pytest plugins_test/` does not spawn real nodes (which would worsen the Windows
socket starvation the boot-heavy suite already hits). Run explicitly:

```bash
PLEXUS_PAIR_TEST=1 python -m pytest plugins_test/networking_pair/ -v
```

They are **not** collected by `test_application.py` (the custom in-process
runner does not run pytest files). Wire them into CI as a separate step.

## What's here

- `test_pair_advert.py` — the orchestrator. Regression guard for **B-082**
  (FIXED 2026-07-09, plexus 0.69.13): cross-node subscription adverts used to
  never propagate in this concurrent-boot topology. Now asserts, in both
  directions (asker = lower/initiator and asker = higher/reciprocator, since
  B-082 was initiator-vs-reciprocator asymmetric), that the peer's `pair/probe`
  advert propagates and a cross-node `request_event(hosts="any")` is answered.
  Includes `test_broken_cert_control`, which pins a wrong cert and asserts the
  harness reports *no connection* — proving its `peer_connected` gate
  distinguishes a real advert-path failure from an unrelated mTLS/connection
  failure.
- `pair_node.py` — headless node runner (one half of the pair; role via CLI).
- `PairProbe/` — the fixture plugin: role=sub subscribes; role=ask polls its
  own network for the peer connection + advert and reports a result file.
- `config.pair_a.yml` / `config.pair_b.yml` — the two node configs (hostnames
  `pair-a` < `pair-b` drive the tiebreak).

- `test_S4_drop_and_reconnect_recovers` — the drop+reconnect cell. Boots the
  pair, establishes the advert, KILLS the subscriber (asker strikes it dead,
  advert vanishes), then RESPAWNS it on the same identity/port (new session_id)
  and requires the advert to re-propagate + a cross-node request to be answered.
  Currently **xfail**: it reproduces **B-088** (a strike-dead peer that restarts
  is not recovered — the asker never re-probes a peer it marked dead, and the
  respawn does not re-enable it). Flips to xpass when B-088 is fixed. `resync_
  interval` is pinned longer than the recovery budget so a pass proves the real
  reconnect healed it, not the periodic sweep.

## Running / Windows socket budget

Each test boots 2-3 real nodes; the whole file is ~9-11 boots. On Windows these
accumulate TIME_WAIT sockets and can starve Winsock (WinError 10055), surfacing
as a spurious advert failure in a LATER test. An autouse cooldown between tests
mitigates it, but on a constrained box run in smaller batches (e.g. the B-082
cases, then S4 separately). **Each test passes cleanly in isolation** — a full-
file failure that disappears when the failing test is run alone is starvation,
not a regression.

## Extending (B-085 matrix)

`_run_pair(asker_is_lower, break_cert)` / `_run_drop_reconnect()` + the
`@parametrize` are the seam. The `--recover` / `--phase-file` / timer CLI args on
`pair_node.py` and the `role=ask` recovery probe in PairProbe are the fault-
injection plumbing (kill+respawn via the parent; per-run timer knobs live-set on
the NM). New angles (env-scheduled runtime subscribe/unsubscribe for the M3
delta guard, asker-local revoke for HUNT-014/182) are added the same way. See
bug **B-085** (the reconciled Phase-1 plan) and **B-086** (the advert-layer
rework this matrix is the acceptance net for).
