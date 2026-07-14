# Batch-2 §F / white-box review items (no injectable §A observable)

These wave-2 cells have NO black-box §A observable that a shared runnable cell can
assert on. They are per-branch CODE-READ rubric items (confirmed by reading the
winning branch), with a targeted unit test where a clock can be injected. Cite the
black-box twin where one exists.

## TP-33 / TG-18 — backward-clock does not extend a slow-drip (MONOTONIC anchor)
- **Disposition (A5):** do NOT step the OS clock under a subprocess (not portable/
  safe on Windows). → §F code-read + `test_wave2_deadline_unit.py` (an injected-`now`
  unit test of the absolute-reassembly-deadline check).
- **§F assertion:** the absolute per-reassembly deadline (SPEC §4.4/§11, 60s) is
  anchored on `time.monotonic()`, NEVER `time.time()`/wall-clock; the directory
  APPLY path likewise uses monotonic/epoch, never wall-clock (so a backward NTP step
  cannot extend a slow-drip DoS or wedge apply). Read the reassembly accumulate/
  timeout code + the `Directory.replace` apply decision.
- **Unit hook required (design ask):** the deadline check should accept an injectable
  `now` in test mode (a `now: float | None = None` param defaulting to
  `time.monotonic()`), so the unit test can drive it deterministically. If the branch
  does not expose it, the unit test SKIPS and this stays a pure code-read.
- Black-box relative: TP-75 (the socket cell) proves the deadline FIRES; TG-18 is
  only the "backward-clock cannot extend it" delta, which is the monotonic-anchor —
  a code property, not a wire-observable.

## TP-48 — removed-voucher's in-flight snapshot → ingest no-ops
- **Disposition:** the window (the voucher's snapshot in-flight AT the instant of its
  removal) is not deterministically reachable black-box. → primarily §F#1.
- **§F assertion:** `ingest_vouched(voucher, ...)` re-checks `voucher in roster` /
  not-tombstoned at APPLY time (inside the one await-free critical section), so a
  removed voucher's already-decoded snapshot seeds NOTHING. No `await` between the
  source-voucher gate and the per-entry adds.
- Black-box best-effort twin: remove the voucher, then confirm its vouched entries are
  not present (a weaker check; the driver `discovery` group can add it, but it does
  not exercise the true in-flight race). §F is authoritative.

## TP-49 — flap-guard: healthy override link is NOT torn (no-tear half)
- **Disposition:** the "does not tear a healthy override link" half needs a link-level
  observable §A lacks → §F#22 (white-box ONLY). The CONVERGE half (a cross-node call
  keeps succeeding through a flapping election edge) IS black-box, but reproducing a
  controllable flapping election-dialer link cooperatively needs a link that connects
  then drops on a timer — deferred with the injector work; the converge property is
  covered indirectly by the pulse-survives/self-heal cells.
- **§F assertion (§F#22):** during a collision the OVERRIDE link stays AUTHORITATIVE
  for dispatch while the PROBATIONARY election link carries the pulses; promotion only
  after the probationary link's pulses succeed for one `idle_read_deadline`; a healthy
  override link is not torn by a flapping election edge; the read-decide-swap on
  `links[hostname]` is one await-free CAS (§7).

## Notes
- TP-40 (vouched-revoke durability across restart) and TP-45 (vouched fp-conflict) are
  cooperative-expressible but need a discovery topology with a restart / a mismatched
  fingerprint vouch; the driver `discovery` group has the assertion logic (TP-43/45),
  and the durability variant follows the TP-39 reload/restart pattern. Wired as the
  discovery-topology follow-up, not §F.
- TG-16 (voucher-churn budget) is a cooperative 3-node SEQUENCE (not a timing race);
  authored in the driver `discovery`/churn path — no injector needed.
