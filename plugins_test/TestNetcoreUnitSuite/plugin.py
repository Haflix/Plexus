"""TestNetcoreUnitSuite — in-suite white-box unit cells for the netcore rewrite.

Wraps the per-module netcore self-tests (``plexus/netcore/_*_selftest.py``) as
CaseRecorder cells so the mechanism-level coverage (wire framing + reassembly
accounting, content_hash total-order, export/route filtering, ERROR-kind
mapping, mTLS/SPKI link-up, stream cancel/teardown, the reassembly-bound guard)
runs on EVERY boot instead of only when a dev invokes the self-tests by hand.

The self-test functions ARE the source of truth — this plugin only ADAPTS each
top-level ``test_*`` into a case (the self-test raises on failure -> the recorder
marks the case failed). No test logic is duplicated here.

Socket policy: cells that stand up real loopback TLS pairs/nodes are gated behind
``PLEXUS_NETCORE_SOCKET`` and SKIP in the default boot — same rationale as
``networking_pair`` / ``PLEXUS_PAIR_TEST`` (avoid Windows socket starvation from a
socket-heavy suite). The pure/in-process cells always run.
"""

from __future__ import annotations

import inspect
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Any, Callable, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402

from plexus.netcore import (  # noqa: E402
    _wire_selftest,
    _transport_selftest,
    _membership_selftest,
    _directory_selftest,
    _dispatch_selftest,
)

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.2.0"

# (module-short, module-object) in a stable order.
_MODULES = [
    ("wire", _wire_selftest),
    ("transport", _transport_selftest),
    ("membership", _membership_selftest),
    ("directory", _directory_selftest),
    ("dispatch", _dispatch_selftest),
]

# Cells that stand up real loopback sockets/TLS -> gated behind PLEXUS_NETCORE_SOCKET.
# The transport module is socket by DEFAULT (most of its cells drive a real loopback
# pair), with the genuinely in-process ones carved out in _PURE_CELLS below.
_SOCKET_MODULES = frozenset({"transport"})
_SOCKET_CELLS = frozenset(
    {
        ("membership", "test_socket_linkup_and_revoke"),
        ("membership", "test_acceptor_context_refresh"),
        ("dispatch", "test_end_to_end"),
    }
)
# In-process cells that live in a socket-DEFAULT module (duck-typed stand-ins, no
# socket/loop) -> they ALWAYS run in the default boot despite the module default.
_PURE_CELLS = frozenset(
    {
        ("transport", "test_node_wide_reservation_guaranteed_minimum"),
        ("transport", "test_dial_refused_pruned_on_stop_link"),
    }
)


def _is_socket(mod_short: str, name: str) -> bool:
    if (mod_short, name) in _PURE_CELLS:
        return False
    return mod_short in _SOCKET_MODULES or (mod_short, name) in _SOCKET_CELLS


def _discover(mod_obj) -> List:
    """The module's OWN top-level ``test_*`` functions, in alphabetical order."""
    out = []
    for name, fn in sorted(inspect.getmembers(mod_obj, inspect.isfunction)):
        if name.startswith("test_") and fn.__module__ == mod_obj.__name__:
            out.append((name, fn))
    return out


class TestNetcoreUnitSuite(Plugin):
    """White-box netcore mechanism cells, wrapping the per-module self-tests."""

    @log_errors
    def on_load(self, *args, **kwargs):
        pass

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestNetcoreUnitSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestNetcoreUnitSuite disabled")

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
        rec = CaseRecorder("TestNetcoreUnitSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )
        sockets_on = bool(os.environ.get("PLEXUS_NETCORE_SOCKET"))
        for mod_short, mod_obj in _MODULES:
            for name, fn in _discover(mod_obj):
                socket_cell = _is_socket(mod_short, name)
                await rec.run_case(
                    f"netcore.{mod_short}.{name[len('test_'):]}",
                    self._make_body(fn, socket_cell, sockets_on),
                    tags=("netcore", mod_short) + (("socket",) if socket_cell else ()),
                    category="netcore",
                    slow=socket_cell,
                    **kw,
                )
        return rec.to_dict()

    def _make_body(self, fn: Callable, socket_cell: bool, sockets_on: bool) -> Callable:
        is_async = inspect.iscoroutinefunction(fn)

        async def body(c):
            if socket_cell and not sockets_on:
                c.skip(
                    "real-socket netcore cell; set PLEXUS_NETCORE_SOCKET=1 to run "
                    "(kept out of the default boot to avoid Winsock starvation — "
                    "same policy as networking_pair/PLEXUS_PAIR_TEST)"
                )
            if is_async:
                await fn()
            else:
                fn()

        return body
