"""Capability-gate wiring fixture.

A plugin that makes ASSERTING execute calls on demand, so the suite can drive
the capability gate end-to-end through a real ``execute()`` dispatch. Loaded
twice (Actor + Actor2) to give two distinct identities + an ancestry chain.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Dict, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.exceptions import CapabilityException  # noqa: E402


class TestCapabilityActor(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        pass

    @async_log_errors
    async def on_disable(self):
        pass

    @async_log_errors
    async def echo(self, value: Any = None) -> str:
        # Victim sink: just proves the asserting call actually dispatched.
        return "echo"

    @async_log_errors
    async def do_assert(
        self, target: str, method: str, author: str, author_id: str
    ) -> dict:
        # The asserting call. Runs as THIS actor's stamped frame; claims
        # `author`/`author_id`. The gate at plexus.execute raises
        # CapabilityException synchronously to THIS (immediate) caller, so we
        # catch it here and report a marker -- a plugin attempting an assertion
        # handles its own denial. (Across a further handler boundary the type
        # would be re-wrapped to RequestException; catching it at the assertion
        # site is both realistic and gives the suite the precise type.)
        try:
            r = await self.execute(
                target, method, author=author, author_id=author_id
            )
            return {"outcome": "ok", "result": r}
        except CapabilityException as e:
            return {"outcome": "denied", "reason": str(e)}

    @async_log_errors
    async def try_reassert(self, value: Any = None) -> dict:
        # Reached as the TARGET of an ALLOWED impersonation, so
        # _asserted_identity is active up the real call chain. Attempt a
        # DIFFERENT assertion (system) -> the no-chaining rule must DENY it even
        # though this actor may hold system_caller. This only denies if
        # _asserted_identity genuinely propagated through the dispatch -> it is
        # the integration proof that asserted_identity_scope works.
        try:
            r = await self.execute(
                self.plugin_name, "echo", author="system", author_id="system"
            )
            return {"outcome": "ok", "result": r}
        except CapabilityException as e:
            return {"outcome": "denied", "reason": str(e)}

    @async_log_errors
    async def relay(self, spec: Dict[str, Any]) -> Any:
        # Reached as a stamped frame so the inner target sees THIS actor as its
        # ancestor. Forwards to spec["plugin"].spec["method"](spec["args"]).
        return await self.execute(
            spec["plugin"], spec["method"], args=spec.get("args")
        )

    @log_errors
    def do_assert_sync(
        self, target: str, method: str, author: str, author_id: str
    ) -> dict:
        # SYNC-path assertion. A sync endpoint runs on a worker thread, so
        # self.execute_sync bridges the dispatch onto the loop where the
        # (now-unified) _dispatch_request gates the RAW author claim. This is the
        # integration proof that the dispatch-unify cleanup extended the
        # capability gate to execute_sync: the CapabilityException raised
        # loop-side crosses the bridge via future.result() and is caught here.
        try:
            r = self.execute_sync(
                target, method, author=author, author_id=author_id
            )
            return {"outcome": "ok", "result": r}
        except CapabilityException as e:
            return {"outcome": "denied", "reason": str(e)}

    @async_log_errors
    async def do_assert_stream(
        self, target: str, method: str, author: str, author_id: str
    ) -> dict:
        # ASYNC-stream assertion. execute_stream is a lazy async generator; the
        # gate fires on the first iteration (inside _create_gen_request_gated).
        # Iterate fully and report the gate result.
        try:
            async for _ in self.execute_stream(
                target, method, author=author, author_id=author_id
            ):
                pass
            return {"outcome": "ok"}
        except CapabilityException as e:
            return {"outcome": "denied", "reason": str(e)}

    @log_errors
    def do_assert_stream_sync(
        self, target: str, method: str, author: str, author_id: str
    ) -> dict:
        # SYNC-stream assertion. execute_stream_sync bridges construction
        # loop-side where _create_gen_request_gated gates; the
        # CapabilityException crosses the bridge on the first next() and surfaces
        # here. Proves the dispatch-unify gate reached execute_stream_sync.
        try:
            for _ in self.execute_stream_sync(
                target, method, author=author, author_id=author_id
            ):
                pass
            return {"outcome": "ok"}
        except CapabilityException as e:
            return {"outcome": "denied", "reason": str(e)}

    @async_log_errors
    async def do_assert_stream_lazy(
        self, target: str, method: str, author: str, author_id: str
    ) -> dict:
        # Prove the async generator is LAZY: merely creating it must NOT gate (no
        # body runs until iteration), so `created` is reached; only iterating
        # triggers the denial. If execute_stream ever became eager, the gen
        # creation below would raise and this handler would error instead of
        # returning the marker.
        gen = self.execute_stream(
            target, method, author=author, author_id=author_id
        )
        created = True
        try:
            async for _ in gen:
                pass
            return {"created": created, "denied_on_iter": False}
        except CapabilityException:
            return {"created": created, "denied_on_iter": True}
