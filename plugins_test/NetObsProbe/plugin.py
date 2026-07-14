"""NetObsProbe — wave-2 observability recorder for the networking rewrite.

Runs on the asker / puller node. Records every §A observability event and polls
``plexus.network.snapshot()`` VERBATIM (whatever shape the NM returns — the
routing-table sub-structure is pinned by the maintainer at phase 4, and recording
verbatim means the cells adapt to the pinned shape with no fixture rework). It is
how a socket cell reads the §A event + snapshot surface from inside the node
subprocess: a driver calls the ``obs_*`` endpoints (or NetObsProbe self-dumps to a
result file the parent test reads).

Events captured via ``internal_observe`` (sync, <1ms, auto-cleaned on disable):
  _core/peer/{up,down,hostname_mismatch,restarted,vouched,vouch_conflict,
              vouch_rejected}
  _core/directory/replaced
  _core/net/{inbound,reject}
  _core/ratelimit/rejected
  + the current-code events _core/peer/{connected,disconnected} (harmless if the
    rewrite does not emit them — registration never fails, the callback just never
    fires), so the same fixture also works on the wave-1 floor.

Defensive: if ``plexus.network`` / ``snapshot()`` is absent (e.g. current code),
recording degrades to an error marker instead of crashing enable.
"""

import json
import os
import time
from collections import deque
from typing import Any

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors


# Every _core/* topic the rewrite emits on §A (+ the two current-code peer events).
_OBSERVED_TOPICS = (
    "_core/peer/up",
    "_core/peer/down",
    "_core/peer/hostname_mismatch",
    "_core/peer/restarted",
    "_core/peer/vouched",
    "_core/peer/vouch_conflict",
    "_core/peer/vouch_rejected",
    "_core/directory/replaced",
    "_core/net/inbound",
    "_core/net/reject",
    "_core/ratelimit/rejected",
    # wave-1-floor / current-code events (no-op on the rewrite if not emitted):
    "_core/peer/connected",
    "_core/peer/disconnected",
)

_SNAP_POLL_INTERVAL_S = 0.5
_SNAP_HISTORY = 400  # bounded ring of (ts, snapshot) so transitions are assertable


class NetObsProbe(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._events: list = []
        self._snap_history: deque = deque(maxlen=_SNAP_HISTORY)
        self._observers: list = []   # (topic, callback) for symmetric cleanup
        self._poll_task = None

    @async_log_errors
    async def on_enable(self):
        import asyncio
        for topic in _OBSERVED_TOPICS:
            cb = self._make_observer(topic)
            try:
                self.internal_observe(topic, cb)
                self._observers.append((topic, cb))
            except Exception:
                # A topic the framework refuses to register is skipped, not fatal.
                self._logger.exception("NetObsProbe: observe(%s) failed", topic)
        self._poll_task = asyncio.create_task(self._poll_snapshots())

    @async_log_errors
    async def on_disable(self):
        if self._poll_task is not None and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except Exception:
                pass
        self._poll_task = None
        for topic, cb in list(self._observers):
            try:
                self.internal_unobserve(topic, cb)
            except Exception:
                pass
        self._observers = []

    def _make_observer(self, topic: str):
        # Bind the topic so a bare-2-arg internal_observe callback records it even
        # if the bus does not pass the topic through. Sync + trivially fast.
        def _obs(cb_topic=topic, payload=None, *_a, **_k):
            try:
                rec = dict(payload) if isinstance(payload, dict) else {"raw": payload}
            except Exception:  # noqa: BLE001 - never let recording break the bus
                rec = {"raw": repr(payload)}
            self._events.append({"topic": cb_topic, "payload": rec, "ts": time.time()})
        return _obs

    async def _poll_snapshots(self):
        import asyncio
        net = getattr(self._plexus, "network", None)
        # Type-X mode: if a result file is set, self-dump each cycle so a hostile
        # pytest (which cannot call this node's plugins) can read the node's
        # _core/* events + snapshot from the file after acting.
        self_dump = os.environ.get("NETOBS_RESULT_FILE", "")
        while True:
            snap = self._read_snapshot(net)
            self._snap_history.append({"ts": time.time(), "snapshot": snap})
            if self_dump:
                self._dump_to(self_dump, snap)
            await asyncio.sleep(_SNAP_POLL_INTERVAL_S)

    def _dump_to(self, path, snap):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"events": list(self._events), "snapshot": snap,
                           "snapshot_history": list(self._snap_history)}, f, default=repr)
        except OSError:
            pass

    def _read_snapshot(self, net) -> Any:
        """Return snapshot() VERBATIM, or an error marker if unavailable."""
        if net is None:
            return {"_obs_error": "no network"}
        fn = getattr(net, "snapshot", None)
        if not callable(fn):
            return {"_obs_error": "no snapshot()"}
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            return {"_obs_error": f"{type(e).__name__}: {e}"}

    # ── Readback endpoints (a driver / cell calls these) ────────────────
    @async_log_errors
    async def obs_events(self, topic: str = None, clear: bool = False) -> list:
        """Recorded events (optionally filtered to ``topic``). ``clear`` resets the
        buffer AFTER reading so a cell can scope a window."""
        out = [e for e in self._events if topic is None or e["topic"] == topic]
        if clear:
            self._events = []
        return out

    @async_log_errors
    async def obs_snapshot(self) -> Any:
        """The CURRENT snapshot() verbatim."""
        return self._read_snapshot(getattr(self._plexus, "network", None))

    @async_log_errors
    async def obs_snapshot_history(self) -> list:
        """The bounded ring of (ts, snapshot) — for transition asserts
        (e.g. reachable true→false)."""
        return list(self._snap_history)

    @async_log_errors
    async def obs_clear(self) -> bool:
        self._events = []
        self._snap_history.clear()
        return True

    @async_log_errors
    async def obs_dump(self, result_file: str = "") -> bool:
        """Write {events, snapshot, snapshot_history} to a result file the parent
        test reads. Falls back to the NETOBS_RESULT_FILE env (subprocess mode)."""
        path = result_file or os.environ.get("NETOBS_RESULT_FILE", "")
        if not path:
            return False
        payload = {
            "events": list(self._events),
            "snapshot": self._read_snapshot(getattr(self._plexus, "network", None)),
            "snapshot_history": list(self._snap_history),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, default=repr)
            return True
        except OSError:
            self._logger.exception("NetObsProbe: dump to %s failed", path)
            return False
