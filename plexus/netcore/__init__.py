"""plexus.netcore — the SPEC v4.4.2 networking rewrite (built ALONGSIDE the
untouched ``plexus/networking.py``; the seam swap is phase 6).

Four cohesive modules plus a thin root (SPEC §3):
  transport   — §4.4 per-peer bidirectional PeerLink, mTLS+SPKI, chunking
  membership  — §4.2/§4.6/§4.7 roster+pin+tombstone, pulse, discovery
  directory   — §4.3 content_hash, route_* seam, build_pong
  dispatch    — §4.5 *_remote senders, inbound re-match, rate/identity seam
  manager     — §3 NetworkManager root (composes the four; the seam core sees)

Public export: ``NetworkManager``.
"""

from .manager import NetworkManager

__all__ = ["NetworkManager"]
