"""HostilePongServer — the ACCEPTOR / PONG-server half of the Type-X harness.

For the §D cells where the NODE dials the hostile and pulls a crafted PONG +
directory snapshot: TP-74 (PONG/snapshot trips a bound), TP-77/78 (malformed /
SPKI-mismatched vouched cert in the served snapshot), TG-17 (over-count
``vouched_peers``), and TP-70's outbound + vouched-context variants.

It binds a listener, accepts the node's dial, presents a CHOSEN cert (mTLS server
side), and answers the node's PING with a crafted ``PONG`` header — optionally
followed by a crafted DirectorySnapshot as CHUNK frames + an END, all on the
PING's cid (the responder replies on the PINGER's cid; the hostile is the ACCEPTOR
so it never allocates its own cid for a PONG).

Direction control (which side dials): pairwise ``lex(self, peer)`` election means
the LOWER hostname dials. To make the NODE dial the hostile, give the hostile a
LEX-HIGHER hostname than the node, and pin the hostile identity in the node config
(for TP-70's outbound-unpinned variant, do NOT pin it and assert the node's SPKI
post-check rejects the handshake).

Same WIRE-LAYOUT ASSUMPTION as ``wire.py`` (A1). The DirectorySnapshot BODY msgpack
field layout is rewrite-defined (same family as A1); ``make_snapshot_bytes`` is the
single point that encodes it — re-point it to the landed branch's snapshot shape.
"""
from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable, Optional

from . import wire

# Snapshot body chunking unit (SPEC §4.4: CHUNK_SIZE 64 KB).
CHUNK_SIZE = 64 * 1024


def make_server_ssl_context(
    cert_file: str,
    key_file: str,
    *,
    node_cert_pem: Optional[str] = None,
    verify_node: bool = False,
) -> ssl.SSLContext:
    """Server context presenting ``cert_file``/``key_file`` to the dialing node.

    ``verify_node=False`` (default) accepts whatever client cert the node presents
    (a hostile server does not verify the node), so the handshake outcome is
    governed purely by whether the NODE accepts the hostile's server cert (its SPKI
    pin) — which is the TP-70-outbound assertion. Set ``verify_node=True`` +
    ``node_cert_pem`` to also require the node's cert.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    if verify_node and node_cert_pem:
        ctx.load_verify_locations(cadata=node_cert_pem)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_snapshot_bytes(
    *,
    epoch: str = "hostile-epoch",
    content_hash: str = "hostile-hash",
    endpoints=None,
    tagged=None,
    subs=None,
    vouched_peers=None,
) -> bytes:
    """Encode a DirectorySnapshot body (SPEC §4.3 fields) as msgpack — the value
    the node reassembles from the PONG's CHUNKs and decodes. Cells craft the
    fields: an over-count ``vouched_peers`` (TG-17), a malformed ``cert_pem``
    (TP-77), an SPKI≠fingerprint entry (TP-78), or an oversized body (TP-74).

    NOTE: the exact snapshot msgpack layout is rewrite-defined (A1 family); this
    is the single point to re-point at the landed branch.
    """
    if not wire.HAVE_MSGPACK:
        raise RuntimeError("msgpack required to encode a snapshot body")
    import msgpack
    body = {
        "epoch": epoch,
        "content_hash": content_hash,
        "endpoints": endpoints or [],
        "tagged": tagged or {},
        "subs": subs or [],
        "vouched_peers": vouched_peers or [],
    }
    return msgpack.packb(body, use_bin_type=True)


# A PONG builder: given the decoded PING fields, return
# (pong_fields_dict, snapshot_bytes_or_None). Default = a minimal header-only PONG.
PongBuilder = Callable[[dict], "tuple[dict, Optional[bytes]]"]


def _default_pong_builder(ping_fields: dict):
    return ({"epoch": "hostile-epoch", "content_hash": "hostile-hash",
             "snapshot_follows": False}, None)


class HostilePongServer:
    """Accept the node's dial, present a chosen cert, answer PING with a crafted
    PONG (+ optional crafted snapshot).

    Usage in a cell::

        srv = HostilePongServer("127.0.0.1", port, cert_file=c, key_file=k,
                                pong_builder=my_builder)
        srv.start()
        # ... boot a node that pins this hostile identity + dials it ...
        # assert on the node's snapshot()/events via NetObsProbe
        srv.stop()
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        cert_file: str,
        key_file: str,
        node_cert_pem: Optional[str] = None,
        verify_node: bool = False,
        pong_builder: Optional[PongBuilder] = None,
        read_timeout: float = 5.0,
        stall_pong: bool = False,
        poison: bool = False,
        pong_delay: float = 0.0,
    ) -> None:
        self.host = host
        self._ctx = make_server_ssl_context(
            cert_file, key_file, node_cert_pem=node_cert_pem, verify_node=verify_node,
        )
        self._pong_builder = pong_builder or _default_pong_builder
        # stall_pong: accept + handshake but NEVER answer a PING (the pulse-await
        # stays open — TP-38 revoke-during-await). poison: answer a PING with a
        # MALFORMED frame every time (TP-51 poison peer — the node's pulse to this
        # peer errors each time, isolated from other peers).
        self._stall_pong = stall_pong
        self._poison = poison
        # pong_delay: answer a PING only after this many seconds (TP-38: the node's
        # pulse-await stays open long enough for a revoke to land mid-await; the
        # delayed PONG's resume-stamp must be roster-gated, not resurrect the peer).
        self._pong_delay = pong_delay
        self._read_timeout = read_timeout
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self.port = self._srv.getsockname()[1]
        self._srv.listen(16)
        self.accept_count = 0
        self.handshake_failures = 0
        self.pings_seen = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._srv.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # --- accept + serve ---------------------------------------------------
    def _accept_loop(self) -> None:
        self._srv.settimeout(0.5)
        while self._running:
            try:
                raw, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accept_count += 1
            try:
                tls = self._ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                self.handshake_failures += 1
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            # Serve this connection on its own thread so a slow node does not
            # block new accepts.
            threading.Thread(
                target=self._serve_conn, args=(tls,), daemon=True
            ).start()

    def _serve_conn(self, tls: ssl.SSLSocket) -> None:
        tls.settimeout(self._read_timeout)
        buf = bytearray()
        try:
            while self._running:
                frame = self._read_one_frame(tls, buf)
                if frame is None:
                    return
                if frame.kind == wire.KIND_PING:
                    self.pings_seen += 1
                    self._answer_ping(tls, frame)
                # Other inbound kinds (CALL/CHUNK/etc.) are ignored by the
                # PONG-server; a cell that needs to answer a CALL uses a custom
                # builder / subclass.
        except (OSError, wire.WireError):
            return
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _answer_ping(self, tls: ssl.SSLSocket, ping: wire.Frame) -> None:
        if self._stall_pong:
            return  # accept the PING, never answer (the pulse-await stays open)
        if self._poison:
            # a malformed frame on the ping cid (garbage kind + a lying length)
            tls.sendall(wire.encode_raw(bytes([0x7f]) + b"\xde\xad\xbe\xef",
                                        declared_length=99999))
            return
        if self._pong_delay > 0:
            import time as _t
            _t.sleep(self._pong_delay)
        pong_fields, snap_bytes = self._pong_builder(ping.fields or {})
        # PONG header on the SAME cid the node opened.
        tls.sendall(wire.encode_frame(wire.KIND_PONG, ping.cid, fields=pong_fields))
        if snap_bytes is None:
            return
        # Snapshot body: one logical value → CHUNK frames (last on final) + END.
        if not snap_bytes:
            tls.sendall(wire.encode_frame(wire.KIND_CHUNK, ping.cid, data=b"", last=True))
        else:
            off = 0
            n = len(snap_bytes)
            while off < n:
                piece = snap_bytes[off:off + CHUNK_SIZE]
                off += CHUNK_SIZE
                tls.sendall(wire.encode_frame(
                    wire.KIND_CHUNK, ping.cid, data=piece, last=(off >= n),
                ))
        tls.sendall(wire.encode_frame(wire.KIND_END, ping.cid, fields={}))

    def _read_one_frame(self, tls: ssl.SSLSocket, buf: bytearray) -> Optional[wire.Frame]:
        import struct
        while len(buf) < 4:
            if not self._fill(tls, buf):
                return None
        declared = struct.unpack(">I", buf[:4])[0]
        need = 4 + declared
        while len(buf) < need:
            if not self._fill(tls, buf):
                return None
        raw = bytes(buf[:need])
        del buf[:need]
        return wire.decode_frame(raw)

    def _fill(self, tls: ssl.SSLSocket, buf: bytearray) -> bool:
        try:
            chunk = tls.recv(65536)
        except socket.timeout:
            return False
        if not chunk:
            return False
        buf.extend(chunk)
        return True
