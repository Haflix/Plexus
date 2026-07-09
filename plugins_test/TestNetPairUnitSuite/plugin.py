"""TestNetPairUnitSuite — in-process minimal-NM regression guards for the
networking advert/liveness layer (the B-085 "P-cell" family).

These are the fast, deterministic, no-socket half of the B-085 networking
failure-angle matrix (B-085 in the bug tracker). They construct a
``NetworkManager`` skeleton via ``object.__new__`` carrying ONLY the attributes
the REAL method under test reads (the same minimal-NM idiom the other
``*UnitSuite`` plugins use), drive the real method, and assert the FIXED /
correct behavior with ``expected_status="pass"`` so a regression turns the gate
RED. The real-socket half (concurrent-boot convergence, drop+reconnect, revoke)
lives separately in ``plugins_test/networking_pair/`` behind ``PLEXUS_PAIR_TEST``.

SCOPE NOTE: only behaviors that are CORRECT today belong here (pass-polarity).
Repros for still-OPEN advert-layer bugs (HUNT-013/052/093/094) stay as xfail
guards in the gitignored ``plugins_test/hunt_2026_06/`` dir and get promoted
here (flipped to pass-polarity) once they are fixed.

MACHINERY-SPECIFIC TAG: several of these cases poke methods B-086 (the planned
advert-layer rework: delete the tiebreak / ack-retry / delta / restart-detect
machinery for a level-triggered reconcile model) will delete or restructure.
They are deliberately tagged so their removal/rewrite ALONGSIDE B-086 is not read
as a regression — they guard today's implementation, not the eventual one. The
durable, rework-surviving guards are the OUTCOME-level socket cells in
``networking_pair/`` (see B-085 / B-086 in the tracker).
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.networking import NetworkManager  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.1.0"


# --- minimal stand-ins -----------------------------------------------------
class _StubNode:
    """Minimal Node stand-in for the liveness helpers. Only ``.enabled`` and
    ``.hostname`` are read by ``_record_heartbeat_miss`` / ``_mark_node_dead``."""

    def __init__(self, hostname: str, enabled: bool = True) -> None:
        self.hostname = hostname
        self.enabled = enabled


def _base_nm() -> NetworkManager:
    """NetworkManager skeleton with just a logger; callers add the attributes
    their method-under-test reads."""
    nm = object.__new__(NetworkManager)
    nm._logger = logging.getLogger("test.NetPairUnit")
    return nm


class TestNetPairUnitSuite(Plugin):
    """In-process minimal-NM guards for the networking advert/liveness layer."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestNetPairUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestNetPairUnitSuite disabled")

    @async_log_errors
    async def run(
        self,
        category: Optional[str] = None,
        host: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        bug_ids: Optional[List[str]] = None,
        skip_slow: bool = False,
        allow_destructive: bool = True,
    ) -> Dict[str, Any]:
        rec = CaseRecorder("TestNetPairUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        await self._b082_advertise_reports_skip(rec, kw)
        await self._b082_initial_exchange_releases_slot_on_skip(rec, kw)
        await self._p4_heartbeat_strikes_then_mark_dead(rec, kw)

        return rec.to_dict()

    # ----- B-082: advertise/initial-exchange invariant (fixed this sprint) -----

    async def _b082_advertise_reports_skip(self, rec, kw):
        # B-082 fix (plexus 0.69.13): advertise_subs_remote returns a bool so a
        # caller that pairs a _snapshot_sent slot-claim with the send can tell a
        # genuine send apart from a SKIP. When is_ready is False (pre-ready
        # discovery / mid-shutdown) it must return False WITHOUT sending and
        # WITHOUT raising. Before the fix it returned None (bare return), which
        # the caller could not distinguish from a completed send.
        async def body(c):
            nm = _base_nm()
            nm.is_ready = False
            sent = await nm.advertise_subs_remote("10.0.0.9", "peer-B")
            # Must be an explicit False (the skip signal), not None/truthy.
            assert sent is False, (
                "advertise_subs_remote must return False when is_ready is False "
                f"(no send, no raise); got {sent!r}. B-082 regression: the "
                "caller can no longer tell a skipped send from a real one, so "
                "_perform_initial_exchange will poison the _snapshot_sent slot."
            )

        await rec.run_case(
            "networking.advertise_subs_remote_reports_skip_when_not_ready",
            body,
            tags=("networking", "advert"),
            bug_ids=("B-082",),
            category="networking",
            **kw,
        )

    async def _b082_initial_exchange_releases_slot_on_skip(self, rec, kw):
        # B-082 root fix: _perform_initial_exchange claims _snapshot_sent[host]
        # BEFORE calling advertise_subs_remote, and (post-fix) RELEASES it when
        # advertise reports it did not send. In the pre-ready window advertise
        # skips (returns False) without raising, so the slot must be popped —
        # otherwise it is poisoned as "sent" with nothing on the wire and every
        # later exchange short-circuits (the B-082 deadlock). Drives the REAL
        # _perform_initial_exchange + REAL advertise_subs_remote (is_ready=False
        # path), asserting the slot is NOT left claimed.
        async def body(c):
            nm = _base_nm()
            nm.is_ready = False
            nm._snapshot_sent = {}
            nm._peer_session_ids = {}
            nm._adverts_struct_lock = asyncio.Lock()

            await nm._perform_initial_exchange("10.0.0.9", "peer-B")

            assert "peer-B" not in nm._snapshot_sent, (
                "B-082 regression: _perform_initial_exchange left "
                "_snapshot_sent['peer-B'] claimed after advertise_subs_remote "
                "skipped the send (is_ready=False). The slot is poisoned as "
                "'sent' with nothing transmitted; later discovery/reciprocal "
                "triggers will short-circuit on it forever (the deadlock B-082 "
                "fixed). The slot must be released when the send was skipped."
            )

        await rec.run_case(
            "networking.perform_initial_exchange_releases_slot_on_skipped_send",
            body,
            tags=("networking", "advert"),
            bug_ids=("B-082",),
            category="networking",
            **kw,
        )

    # ----- P4 (HUNT-092 death half): strike-then-die mechanics (correct today) -----

    async def _p4_heartbeat_strikes_then_mark_dead(self, rec, kw):
        # The N-strikes liveness DEATH path (C-044). This is the CORRECT half of
        # HUNT-092 / B-088 (the BUG is that a struck-dead peer is never
        # re-probed; that recovery gap is guarded by the socket cells, not
        # here). Here we pin the death mechanics: _record_heartbeat_miss
        # tolerates misses below heartbeat_strikes and signals dead at the
        # threshold (clearing the counter), and _mark_node_dead disables the
        # node, drops its advert state, clears its miss counter, and is
        # idempotent. Drives the REAL helpers; _drop_peer_advert_state is stubbed
        # to a recorder (its own state-drop is guarded elsewhere).
        async def body(c):
            nm = _base_nm()
            nm.heartbeat_strikes = 2
            nm._heartbeat_misses = {}
            drop_calls: List[str] = []

            async def _stub_drop(host):
                drop_calls.append(host)

            nm._drop_peer_advert_state = _stub_drop  # type: ignore[assignment]

            class _Plexus:
                requests: Dict[str, Any] = {}

            nm.plexus = _Plexus()
            node = _StubNode("peer-B", enabled=True)

            # Miss 1/2: tolerated (below threshold), counter increments.
            r1 = await nm._record_heartbeat_miss(node)
            c.expect(r1, False)
            c.expect(nm._heartbeat_misses.get("peer-B"), 1)

            # Miss 2/2: threshold reached -> signal dead, counter cleared.
            r2 = await nm._record_heartbeat_miss(node)
            c.expect(r2, True)
            c.expect("peer-B" in nm._heartbeat_misses, False)

            # Mark dead: disable + drop advert state + (already-clear) counter.
            await nm._mark_node_dead(node)
            c.expect(node.enabled, False)
            c.expect(drop_calls, ["peer-B"])
            c.expect("peer-B" in nm._heartbeat_misses, False)

            # Idempotent: a second mark is a no-op (node already disabled),
            # so _drop_peer_advert_state is NOT called again.
            await nm._mark_node_dead(node)
            c.expect(node.enabled, False)
            c.expect(drop_calls, ["peer-B"])

        await rec.run_case(
            "networking.heartbeat_strikes_then_mark_node_dead",
            body,
            tags=("networking", "liveness"),
            bug_ids=("HUNT-092", "B-088"),
            category="networking",
            **kw,
        )
