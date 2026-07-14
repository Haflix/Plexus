"""plexus.networking — RETIRED (compat shim).

The ~7,600-line ``NetworkManager`` god-class is replaced by the ``plexus.netcore``
package (the SPEC networking rewrite). This shim re-exports the new ``NetworkManager``
under the old import path and preserves the few legacy constants / dataclasses that
core + some tests still import, so the seam swap does not require touching every
importer in a single pass. The old advert / liveness / wire machinery (``MSG_*``,
``AdvertSub`` ack tracking, the connection pool, resync, etc.) is GONE by design.

Follow-up (cosmetic): rewire importers to ``plexus.netcore`` and drop this shim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from .netcore import NetworkManager  # the rewritten networking root
from .netcore.types import PeerSpec   # compatible dataclass (adds dial/source/vouched_by)
from .networking_classes import Node, RemotePlugin
from .serialization import safe_loads, generate_keypair, FINGERPRINT_CLI_CMD

__all__ = [
    "NetworkManager", "PeerSpec", "AdvertSub", "Node", "RemotePlugin",
    "safe_loads", "generate_keypair", "FINGERPRINT_CLI_CMD",
    "DEFAULT_HEARTBEAT_INTERVAL", "DEFAULT_RESYNC_INTERVAL", "DEFAULT_LOOKUP_INTERVAL",
    "DEFAULT_LIVENESS_TIMEOUT", "DEFAULT_PROBE_TIMEOUT", "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_INBOUND_IDLE_TIMEOUT", "DEFAULT_REQUEST_TIMEOUT",
    "DEFAULT_MAX_OUTBOUND_CONNECTIONS",
]

# --- legacy default knobs. Only HEARTBEAT + LIVENESS are read anywhere (by
# utils.apply_configvalues); the other seven are vestigial exports kept for
# import-compat with the retired push layer and have no live reader. ---
DEFAULT_HEARTBEAT_INTERVAL: float = 10.0
DEFAULT_RESYNC_INTERVAL: float = 300.0
DEFAULT_LOOKUP_INTERVAL: float = 60.0
DEFAULT_LIVENESS_TIMEOUT: float = 30.0
DEFAULT_PROBE_TIMEOUT: Optional[float] = None
DEFAULT_CONNECT_TIMEOUT: float = 10.0
DEFAULT_INBOUND_IDLE_TIMEOUT: float = 120.0
DEFAULT_REQUEST_TIMEOUT: float = 30.0
DEFAULT_MAX_OUTBOUND_CONNECTIONS: int = 20


@dataclass
class AdvertSub:
    """Legacy advert record — the advert machinery is retired; this remains only so a
    few importers/tests do not ImportError during the swap. Ack fields kept as no-op
    defaults."""

    sub_uuid: str = ""
    topic_pattern: str = ""
    hosts: Union[str, list, None] = None
    blocked_hosts: Union[str, list, None] = None
    authors: Union[str, list, None] = None
    blocked_authors: Union[str, list, None] = None
    sent_at: Optional[float] = None
    acked_at: Optional[float] = None
    state: str = "pending"
    retry_count: int = 0
