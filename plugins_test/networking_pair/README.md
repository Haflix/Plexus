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

- `test_pair_advert.py` — the orchestrator. Currently guards **B-082**
  (cross-node subscription adverts never propagate in this topology), xfail in
  both directions (asker = lower/initiator and asker = higher/reciprocator,
  since B-082 is initiator-vs-reciprocator asymmetric). Includes
  `test_broken_cert_control`, which pins a wrong cert and asserts the harness
  reports *no connection* — proving its `peer_connected` gate distinguishes a
  real advert deadlock from an unrelated mTLS/connection failure.
- `pair_node.py` — headless node runner (one half of the pair; role via CLI).
- `PairProbe/` — the fixture plugin: role=sub subscribes; role=ask polls its
  own network for the peer connection + advert and reports a result file.
- `config.pair_a.yml` / `config.pair_b.yml` — the two node configs (hostnames
  `pair-a` < `pair-b` drive the tiebreak).

## Extending (B-085 matrix)

`_run_pair(asker_is_lower, break_cert)` + the `@parametrize` are the seam. New
angles (boot order, discovery-only vs configured-peer topology, fault injection
— peer silent / restart mid-exchange / revoke, >2 nodes) are added as new params
/ `_run_pair` flags. See bug **B-085** (test-suite gap analysis).
