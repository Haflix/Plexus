import asyncio
import signal
import sys
from plexus.core import Plexus


def _install_fast_loop():
    """Install a faster event-loop policy when available: winloop on
    Windows, uvloop on POSIX. Must run before asyncio.run() creates the
    loop. Optional — `pip install plexus-core[fastloop]` activates it; a
    bare checkout falls back to the stock asyncio loop (no-op). Returns the
    installed module name, or None.
    """
    try:
        if sys.platform == "win32":
            import winloop as _fast
        else:
            import uvloop as _fast
    except ImportError:
        return None
    _fast.install()
    return _fast.__name__


async def main():
    pc = Plexus("config.yml")
    await pc.wait_until_ready()

    # Plugins (e.g., DiscordBot /shutdown) set this event to trigger exit.
    pc._shutdown_event = asyncio.Event()

    # Handle Ctrl+C gracefully — set the shutdown event instead of killing the loop.
    # This lets graceful_shutdown() run (disabling plugins, closing connections).
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, pc._shutdown_event.set)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler for SIGINT in all contexts.
            # Fall back to signal.signal for Ctrl+C.
            signal.signal(sig, lambda s, f: pc._shutdown_event.set())

    await pc._shutdown_event.wait()
    print("Shutting down...")
    await pc.graceful_shutdown()


if __name__ == "__main__":
    _loop_impl = _install_fast_loop()
    if _loop_impl:
        print(f"Using fast event loop: {_loop_impl}")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        print("Successfully shutdown the service.")
