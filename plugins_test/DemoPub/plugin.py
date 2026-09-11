"""Demo publisher: drives the event system's outbound paths.

Three things it exercises:

  1. `fire_events` publishes a burst on `demo.greeted` / `demo.ticked`.
     Both topics are subscribed by DemoSub and DemoOrch, so one call
     fans out 1:N to several handlers.
  2. `beat2_ask` fires a single `request_event` on `demo.ask`, a 1:1
     ask that returns the answering subscriber's value. When no local
     subscriber matches, the request falls through to a peer node.
  3. `beat3_flood` fires twenty asks back to back so the burst lands
     inside one token-bucket refill window, tripping whatever
     `endpoint_in` limit the host configured on the handler, and
     counts the resulting rejects.

Also carries tagged endpoints (`demo`, `fire`, `ping`) so tag-based
endpoint discovery has something to find.
"""

import asyncio

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors
from plexus.exceptions import RequestException


class DemoPub(Plugin):
    @log_errors
    def on_load(self, autoplay: bool = True, *args, **kwargs):
        self.description = (
            "Demo publisher: fires demo events on demand."
        )
        # Auto-play: when true, on_enable starts a loop that replays the
        # three demo beats, so the demo produces traffic without anyone
        # calling an endpoint. Set autoplay=false to disable.
        self._autoplay = bool(autoplay)
        self._autoplay_task = None

    @async_log_errors
    async def on_enable(self):
        if self._autoplay:
            self._autoplay_task = asyncio.create_task(self._autoplay_loop())

    @async_log_errors
    async def on_disable(self):
        t = self._autoplay_task
        self._autoplay_task = None
        if t is not None and not t.done():
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    async def _autoplay_loop(self):
        """Replay the three demo beats on a loop so the demo produces
        traffic unattended. Beat 1 (publish 1:N) -> Beat 2 (1:1 ask) ->
        Beat 3 (flood -> rejects), then idle and repeat, so the reject
        tally keeps climbing across cycles."""
        try:
            await asyncio.sleep(6.0)  # let the host settle after startup
            while True:
                try:
                    await self.fire_events()
                    await asyncio.sleep(3.0)
                    await self.beat2_ask()
                    await asyncio.sleep(2.0)
                    await self.beat3_flood()
                except Exception:
                    pass  # never let one cycle kill the loop
                await asyncio.sleep(18.0)
        except asyncio.CancelledError:
            return

    @async_log_errors
    async def fire_events(self):
        """Publish 5 events: 3 greeted + 2 ticked. Each fires a
        `_core/event/published` bus emit, plus `_core/event/requested`
        for any matching subscriber dispatch."""
        for i in range(3):
            await self.publish_event("greeted", payload={"i": i, "kind": "greet"})
        for i in range(2):
            await self.publish_event("ticked", payload={"i": i, "kind": "tick"})
        return {"fired": 5, "topics": ["demo.greeted", "demo.ticked"]}

    @async_log_errors
    async def beat2_ask(self):
        """Beat 2: a 1:1 request_event that comes back with an answer.

        Fires `request_event` on topic `demo.ask`. Whichever subscriber
        matches (DemoOrch.handle_ask) answers, and the return value comes
        back here. The ask is config-routed: the caller addresses a topic,
        not a named plugin, so in a two-node setup where nothing
        subscribes demo.ask locally the request falls through to the peer.

        Logged at WARNING so it shows through a console_log_level of
        WARNING.
        """
        answer = await self.request_event(
            "ask", payload={"q": "ping"}, timeout=3.0
        )
        self._logger.warning(">>> BEAT 2: asked peer -> got %r", answer)
        return {"beat": 2, "answer": answer}

    @async_log_errors
    async def beat3_flood(self, n: int = 20):
        """Beat 3: flood the 1:1 ask endpoint to trip its endpoint_in
        rate limit.

        Fires `n` request_events back to back with no sleep, so the whole
        burst lands inside one token-bucket refill window. The endpoint_in
        limit on handle_ask (set in the node config) lets the first few
        through and rejects the rest IN-side; for a 1:1 request_event that
        reject is passed back to this caller as a RequestException, which
        we count.

        The reject also fires the `_core/ratelimit/rejected` observability
        event, so a host can observe the rejects as they happen.
        """
        ok = 0
        rejected = 0
        for _ in range(int(n)):
            try:
                await self.request_event(
                    "ask", payload={"q": "flood"}, timeout=3.0
                )
                ok += 1
            except RequestException:
                rejected += 1
        self._logger.warning(
            ">>> BEAT 3: flood %d -> %d ok, %d rejected", int(n), ok, rejected
        )
        return {"beat": 3, "fired": int(n), "ok": ok, "rejected": rejected}

    @async_log_errors
    async def ping(self):
        """Tagged with `demo, ping` — try filtering by tag in the
        Plugins tab."""
        return "pong"

    @async_log_errors
    async def echo(self, message: str = "hello"):
        return {"echo": message}
