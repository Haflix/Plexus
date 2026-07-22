"""TestNetcoreUnitSuite — in-suite white-box unit cells for the netcore rewrite.

Wraps the per-module netcore self-tests (``plexus/netcore/_*_selftest.py``) as
CaseRecorder cells so the mechanism-level coverage (wire framing + reassembly
accounting, content_hash total-order, export/route filtering, ERROR-kind
mapping, mTLS/SPKI link-up, stream cancel/teardown, the reassembly-bound guard)
runs on EVERY boot instead of only when a dev invokes the self-tests by hand.

The self-test functions ARE the source of truth — this plugin only ADAPTS each
top-level ``test_*`` into a case (the self-test raises on failure -> the recorder
marks the case failed). No test logic is duplicated here.

Socket policy: none. Every cell runs on every boot, including the ones that stand
up real loopback TLS pairs. These were previously gated behind
``PLEXUS_NETCORE_SOCKET`` on the theory that they caused Windows socket
starvation. Two facts checkable from this tree retired that gate: the env var was
set NOWHERE in the repo, so the 11 gated cells had never executed while the boot
reported green; and the starvation rationale traced back to a different runner (a
suite doing ~660 full Plexus boots) plus orphaned processes, neither of which
applies here, because this gate boots Plexus once. The gated set's runtime cost
is visible in the suite's own duration in test_report.json (~6s for all 36
cells). A one-off ad-hoc measurement on 2026-07-22 put its TIME_WAIT cost at ~11
entries, below idle-machine churn; that number is NOT produced by anything in
this repo, so treat it as an unreproduced note rather than a checkable fact.

The socket cells are also no longer marked ``slow``, so a ``skip_slow=True``
invocation no longer drops them. That is deliberate: the ``skip_slow`` filter
returns WITHOUT recording a case, so those cells used to vanish from the
totals entirely rather than report as skips.
"""

from __future__ import annotations

import inspect
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


SUITE_VERSION = "0.3.0"

# (module-short, module-object) in a stable order.
_MODULES = [
    ("wire", _wire_selftest),
    ("transport", _transport_selftest),
    ("membership", _membership_selftest),
    ("directory", _directory_selftest),
    ("dispatch", _dispatch_selftest),
]


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
        for mod_short, mod_obj in _MODULES:
            for name, fn in _discover(mod_obj):
                await rec.run_case(
                    f"netcore.{mod_short}.{name[len('test_'):]}",
                    self._make_body(fn),
                    tags=("netcore", mod_short),
                    category="netcore",
                    **kw,
                )
        return rec.to_dict()

    def _make_body(self, fn: Callable) -> Callable:
        is_async = inspect.iscoroutinefunction(fn)

        async def body(c):
            if is_async:
                await fn()
            else:
                fn()

        return body
