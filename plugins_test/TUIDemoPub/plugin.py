"""TUI smoke demo publisher.

Two purposes:

  1. Fires a burst of demo events from `fire_events` so the Events ▸
     Live stream panel populates. The events match topics that
     `TUIDemoSub` subscribes to, so subscriber dispatch metrics show
     up too.
  2. Carries a few tagged endpoints (`demo`, `fire`, `ping`) so the
     Plugins-tab tag-search input has something to filter against.
"""

import asyncio

from plexus.utils import Plugin
from plexus.decorators import async_log_errors, log_errors
from plexus.exceptions import RequestException


class TUIDemoPub(Plugin):
    @log_errors
    def on_load(self, autoplay: bool = True, *args, **kwargs):
        self.description = (
            "TUI smoke demo publisher — fires demo events on demand."
        )
        # Presentation auto-play: when true, on_enable starts a loop that
        # replays the 3 demo beats so the demo runs without clicking the
        # TUI Call button. Set autoplay=false to disable.
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
        """Replay the 3 presentation beats on a loop so the demo works
        without the TUI Call button. Beat 1 (publish 1:N) -> Beat 2 (1:1
        ask) -> Beat 3 (flood -> rejects), then idle and repeat. The
        Rate-Limits tab reject counter keeps climbing across cycles."""
        try:
            await asyncio.sleep(6.0)  # let the TUI settle after startup
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
        `_core/event/published` bus emit (and `_core/event/requested`
        for any matching subscriber dispatch), populating the Events
        tab's Live-stream panel."""
        for i in range(3):
            await self.publish_event("greeted", payload={"i": i, "kind": "greet"})
        for i in range(2):
            await self.publish_event("ticked", payload={"i": i, "kind": "tick"})
        return {"fired": 5, "topics": ["demo.greeted", "demo.ticked"]}

    @async_log_errors
    async def beat2_ask(self):
        """Presentation Beat 2 — 1:1 request_event answered by a local subscriber.

        Fires `request_event` on topic `demo.ask`. A local subscriber
        (TUIDemoOrch.handle_ask) answers, and the return value comes back
        here. Shows a 1:1 ask that is config-routed: the caller addresses
        a topic, not a named plugin.

        Banner is logged at WARNING so it shows through the harness's
        console_log_level: WARNING.
        """
        answer = await self.request_event(
            "ask", payload={"q": "ping"}, timeout=3.0
        )
        self._logger.warning(">>> BEAT 2: asked peer -> got %r", answer)
        return {"beat": 2, "answer": answer}

    @async_log_errors
    async def beat3_flood(self, n: int = 20):
        """Presentation Beat 3 — flood the 1:1 ask endpoint to trip its
        endpoint_in rate limit.

        Fires `n` request_events back to back with no sleep, so the whole
        burst lands inside one token-bucket refill window. The endpoint_in
        limit on handle_ask (set in the node config) lets the first few
        through and rejects the rest IN-side; for a 1:1 request_event that
        reject is passed back to this caller as a RequestException, which
        we count.

        The reject also fires the `_core/ratelimit/rejected` observability
        event, so the Rate-Limits tab shows the rejects climb.
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
