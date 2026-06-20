"""Runnable two-plugin demo for the copypasta templates.

Boots Plexus with copypasta/demo_config.yml (SensorPlugin + AveragePlugin), then
drives a short scripted scenario that exercises every feature the two plugins
demonstrate, printing what happens at each step. Run from the REPO ROOT:

    python copypasta/run_demo.py

It is self-contained: networking is off, the "sensor" is fake and deterministic,
and it shuts down cleanly at the end. Read it top-to-bottom as a worked example
of driving Plexus from outside a plugin (via the Plexus-level execute API).
"""
import asyncio

from plexus.core import Plexus
from plexus.exceptions import RequestException, RateLimitException


def banner(title: str) -> None:
    print(f"\n=== {title} ===")


async def main() -> None:
    plx = Plexus("copypasta/demo_config.yml")
    await plx.wait_until_ready()
    try:
        print("Loaded plugins:", ", ".join(sorted(plx.plugins)))

        # 1) Endpoint discovery by tag (no hardcoded names).
        banner("find_endpoints_by_tag")
        sensors = await plx.execute("AveragePlugin", "discover_sensors")
        print("endpoints tagged 'demo-sensor':", sensors)

        # 2) Event publish/subscribe: SensorPlugin emits readings onto the
        #    'sensor/reading' topic; AveragePlugin is subscribed and accumulates.
        banner("publish_event -> subscriber (running average)")
        for v in (21.0, 22.5, 20.0, 23.5):
            n = await plx.execute(
                "SensorPlugin", "emit_reading", args={"value": v}
            )
            print(f"emit_reading({v}) scheduled to {n} subscriber(s)")
        await asyncio.sleep(0.1)  # let the fan-out deliver
        print("running average:", await plx.execute("AveragePlugin", "average"))

        # 3) A sync generator endpoint streamed over the wire.
        banner("sync generator endpoint (recorded_values)")
        recorded = [c async for c in plx.execute_stream("AveragePlugin", "recorded_values")]
        print("recorded values:", recorded)

        # 4) Inter-plugin execute(): pull a reading on demand.
        banner("execute() to a named plugin (pull_reading)")
        print("pull_reading ->", await plx.execute("AveragePlugin", "pull_reading"))

        # 5) Capabilities: AveragePlugin is granted impersonation_allowed:
        #    [SensorPlugin], so it may act AS SensorPlugin but nothing else.
        banner("capabilities (assert an identity)")
        sensor_uuid = plx.plugins["SensorPlugin"].plugin_uuid
        ok = await plx.execute(
            "AveragePlugin", "try_act_as",
            args={"author": "SensorPlugin", "author_id": sensor_uuid},
        )
        print("act as SensorPlugin (granted):", ok)
        denied = await plx.execute(
            "AveragePlugin", "try_act_as",
            args={"author": "Eve", "author_id": "eve"},
        )
        print("act as Eve (not granted):     ", denied)

        # 6) Rate limiting: main config caps endpoint_in(SensorPlugin, read) at
        #    5/sec (overriding the plugin's own 50/sec). Hammer it and watch the
        #    limiter reject. (An IN-side reject surfaces as RequestException whose
        #    message names the binding dimension.) NOTE: the steps above already
        #    spent a few `read` tokens from this same 1-second bucket, so fewer
        #    than 5 are admitted here -- the bucket is shared across all callers.
        banner("rate limiting (endpoint_in cap = 5/sec, shared window)")
        admitted = 0
        for i in range(8):
            try:
                await plx.execute("SensorPlugin", "read")
                admitted += 1
            except (RateLimitException, RequestException) as e:
                print(f"call #{i + 1} rejected: {e}")
                break
        print(f"admitted {admitted} read(s) before the limiter kicked in")
    finally:
        banner("shutdown")
        await plx.graceful_shutdown()
        print("demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
