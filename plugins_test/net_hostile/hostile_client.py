"""HostileClient — a raw TLS + frame client for the Type-X adversarial cells.

Opens a real mTLS connection to a rewrite node's listener PRESENTING AN ARBITRARY
CERT (pinned or unpinned, per the cell), then sends hand-crafted frames and reads
the node's replies at the raw-frame level. NOT a cooperative Plexus node: it never
runs the pulse/directory/dispatch machinery — it exists to violate the protocol.

Driven SYNChronously from the test process (blocking sockets + timeouts), matching
``networking_pair/test_pair_advert.py`` (sync test, subprocess nodes). The node
under test is a real rewrite node booted as a subprocess that has the hostile
identity PINNED as a peer (so the mTLS handshake completes and frames reach the
reader) — except for TP-70, which presents an UNPINNED cert and asserts the
handshake / SPKI post-check REJECTS it.

WHAT A TYPE-X CELL ASSERTS ON (the harness's observable surface — §A is the
black-box surface; Type-X adds these because an adversarial cell drives the raw
protocol, which a cooperative black-box cell cannot):
  1. The raw FRAME the node returns / omits (e.g. an ERROR{kind} vs an END vs a
     header-only PONG vs silence) — parsed via ``wire.decode_frame``.
  2. Whether the LINK STAYS UP vs is TORN — probe by sending a follow-up valid
     frame and checking it is still answered (TP-73/74/80 = up; TP-79 = torn).
  3. §A ``_core/*`` events the NODE emits + its ``snapshot()`` — captured by a
     cooperative OBSERVER plugin co-located ON the node subprocess (the wave-2
     ``NetObsProbe`` fixture, a separate deliverable) that records events +
     snapshot to a result file the cell reads. The hostile client itself never
     sees §A; it sees only the wire.

Scaffold scope (this round): CONNECTION + FRAME-CODEC glue + send/recv primitives
+ representative crafted-frame helpers (send_call / send_chunk / send_ping /
send_raw / recv_frame). NOT the TP-70..81 cells (the parent commissions those
after reviewing WAVE2_TEST_MAP.md).
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
from typing import Optional

from . import wire


class HostileConnError(Exception):
    """The hostile client could not establish / hold its TLS connection."""


def make_client_ssl_context(
    cert_file: str,
    key_file: str,
    *,
    server_cert_pem: Optional[str] = None,
    verify_server: bool = False,
) -> ssl.SSLContext:
    """Build the client-side TLS context that PRESENTS ``cert_file``/``key_file``.

    The node under test runs mutual TLS (CERT_REQUIRED with each pinned peer cert
    as its own CA) + a post-handshake SPKI pin. For the hostile client to reach
    the node's reader, the node must have THIS cert pinned as a peer (the test
    seeds it via config). For TP-70 (unpinned SPKI) the cell passes a cert the
    node did NOT pin and asserts rejection.

    ``verify_server=False`` (default) makes the client accept whatever server cert
    is presented (a hostile client does not care about server identity), so the
    handshake outcome is governed purely by whether the NODE accepts the client
    cert. Set ``verify_server=True`` + ``server_cert_pem`` to also pin the server.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if verify_server and server_cert_pem:
        ctx.load_verify_locations(cadata=server_cert_pem)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


class HostileClient:
    """A raw-frame TLS client to a rewrite node's listener.

    Typical use in a Type-X cell::

        cli = HostileClient("127.0.0.1", port, cert_file=c, key_file=k)
        cli.connect()                       # TP-70: expect HostileConnError
        cid = cli.send_ping(have_hash=b"")  # -> a header-only PONG frame
        pong = cli.recv_frame()
        assert pong.kind == wire.KIND_PONG
        cli.close()
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        cert_file: str,
        key_file: str,
        server_cert_pem: Optional[str] = None,
        verify_server: bool = False,
        connect_timeout: float = 10.0,
        read_timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self._ctx = make_client_ssl_context(
            cert_file, key_file,
            server_cert_pem=server_cert_pem, verify_server=verify_server,
        )
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._sock: Optional[ssl.SSLSocket] = None
        self._recv_buf = bytearray()
        self._cid_counter = 0
        # Captured after a successful handshake so a second connect can attempt
        # a TLS-1.3 RESUMED handshake (TP-70 resumed-session variant).
        self.tls_session: Optional[ssl.SSLSession] = None

    # --- connection -------------------------------------------------------
    def connect(self, *, reuse_session: Optional[ssl.SSLSession] = None) -> None:
        """Open TCP + do the TLS handshake. Raises HostileConnError if the node
        rejects the cert (the EXPECTED outcome for TP-70). ``reuse_session`` (or a
        prior ``self.tls_session``) attempts a resumed handshake."""
        raw = socket.create_connection((self.host, self.port), self._connect_timeout)
        try:
            session = reuse_session or self.tls_session
            tls = self._ctx.wrap_socket(
                raw, server_hostname=self.host, session=session,
            )
        except (ssl.SSLError, OSError) as e:
            try:
                raw.close()
            finally:
                pass
            raise HostileConnError(f"TLS handshake rejected: {e}") from e
        tls.settimeout(self._read_timeout)
        self._sock = tls
        try:
            self.tls_session = tls.session
        except Exception:  # noqa: BLE001 - session capture is best-effort
            self.tls_session = None

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "HostileClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- cid allocation ---------------------------------------------------
    def next_cid(self) -> int:
        """Allocate the next dialer cid (high bit set, per SPEC §5)."""
        self._cid_counter += 1
        return wire.encode_cid(self._cid_counter, dialer=True)

    # --- low-level send/recv ---------------------------------------------
    def send_bytes(self, data: bytes) -> None:
        if self._sock is None:
            raise HostileConnError("not connected")
        self._sock.sendall(data)

    def send_frame(
        self, kind: int, cid: int, *, fields=None, data=None, last=None
    ) -> None:
        self.send_bytes(wire.encode_frame(kind, cid, fields=fields, data=data, last=last))

    def send_raw(self, payload: bytes, *, declared_length: Optional[int] = None) -> None:
        """Send a frame with an arbitrary / lying length prefix (TP-79 malformed
        frame, mid-frame corruption)."""
        self.send_bytes(wire.encode_raw(payload, declared_length=declared_length))

    def recv_frame(self, *, timeout: Optional[float] = None) -> wire.Frame:
        """Read + decode exactly one frame. Raises socket.timeout if none arrives,
        HostileConnError if the link closed (a torn link -> empty read)."""
        return wire.decode_frame(self._recv_raw_frame(timeout=timeout))

    def _recv_raw_frame(self, *, timeout: Optional[float] = None) -> bytes:
        deadline = time.time() + (self._read_timeout if timeout is None else timeout)
        # length prefix
        while len(self._recv_buf) < 4:
            self._fill(deadline)
        declared = struct.unpack(">I", self._recv_buf[:4])[0]
        need = 4 + declared
        while len(self._recv_buf) < need:
            self._fill(deadline)
        raw = bytes(self._recv_buf[:need])
        del self._recv_buf[:need]
        return raw

    def _fill(self, deadline: float) -> None:
        if self._sock is None:
            raise HostileConnError("not connected")
        remaining = deadline - time.time()
        if remaining <= 0:
            raise socket.timeout("recv_frame deadline exceeded")
        self._sock.settimeout(remaining)
        chunk = self._sock.recv(65536)
        if not chunk:
            raise HostileConnError("link closed by peer (empty read)")
        self._recv_buf.extend(chunk)

    def link_is_up(self, *, probe_have_hash: bytes = b"", timeout: float = 4.0) -> bool:
        """Probe whether the link survived a prior hostile frame: send a valid PING
        and require a PONG on OUR ping cid. Tolerates interleaved node-originated
        PING frames (both ends pulse) by reading until our PONG or the timeout.
        TP-73/74/80 = up; TP-79 = torn. Any read failure / closed link -> False."""
        try:
            cid = self.send_ping(have_hash=probe_have_hash)
            deadline = time.time() + timeout
            while time.time() < deadline:
                f = self.recv_frame(timeout=max(0.1, deadline - time.time()))
                if f.kind == wire.KIND_PONG and f.cid == cid:
                    return True
                # ignore a node-originated PING / other frame and keep waiting
            return False
        except (HostileConnError, socket.timeout, wire.WireError, OSError):
            return False

    # --- crafted-frame helpers (representative; cells add more) -----------
    def send_ping(self, *, have_hash: bytes = b"", cid: Optional[int] = None) -> int:
        """PING{cid, have_hash} on the priority slot. Returns the cid used."""
        cid = self.next_cid() if cid is None else cid
        self.send_frame(wire.KIND_PING, cid, fields={"have_hash": have_hash})
        return cid

    def send_call(
        self,
        *,
        selector: dict,
        mode: int,
        caller: dict,
        handler_timeout: Optional[float] = None,
        cid: Optional[int] = None,
    ) -> int:
        """CALL{cid, selector, mode, caller, handler_timeout} — opens an inbound
        cid at the node. ``selector`` = {"plugin","endpoint","plugin_uuid"?} for
        execute / {"topic"} for events. ``caller`` = {author, author_id,
        author_host, request_uuid} (NO system_caller — the wire never carries it;
        TP-71 crafts one anyway to prove it is ignored). ``handler_timeout`` is a
        RELATIVE duration (absent on FANOUT). Returns the cid (args follow as
        CHUNKs on the same cid)."""
        cid = self.next_cid() if cid is None else cid
        fields = {"selector": selector, "mode": mode, "caller": caller}
        if handler_timeout is not None:
            fields["handler_timeout"] = handler_timeout
        self.send_frame(wire.KIND_CALL, cid, fields=fields)
        return cid

    def send_chunk(self, cid: int, data: bytes, *, last: bool) -> None:
        """CHUNK{cid, data, last}. ``data`` is OPAQUE bytes the node feeds to
        ``safe_loads`` after full reassembly — pass ``pickle_args(...)`` for a CALL's
        args (allowlisted value = TG-20 control; a disallowed reduce = the RCE
        probe)."""
        self.send_frame(wire.KIND_CHUNK, cid, data=data, last=last)

    def send_call_with_args(
        self, *, selector, mode, caller, args_bytes: bytes,
        handler_timeout=None, cid: Optional[int] = None,
    ) -> int:
        """Convenience: CALL header + a single terminal args CHUNK. For oversize /
        slow-drip variants call ``send_call`` + ``send_chunk`` manually."""
        cid = self.send_call(
            selector=selector, mode=mode, caller=caller,
            handler_timeout=handler_timeout, cid=cid,
        )
        self.send_chunk(cid, args_bytes, last=True)
        return cid

    def recv_result(self, cid: int, *, timeout: Optional[float] = None):
        """Read frames until the cid settles. Returns:
          ("value", obj)   on END (obj = pickle.loads of the reassembled CHUNKs)
          ("error", kind)  on ERROR{cid, kind}
          ("empty", None)  on END with no CHUNK
        Frames for other cids are ignored. Raises socket.timeout / HostileConnError
        on a stalled/closed link (a cell asserts on that separately)."""
        import pickle
        buf = bytearray()
        got_chunk = False
        while True:
            f = self.recv_frame(timeout=timeout)
            if f.cid != cid:
                continue
            if f.kind == wire.KIND_CHUNK:
                buf.extend(f.data or b"")
                got_chunk = True
            elif f.kind == wire.KIND_END:
                if not got_chunk:
                    return ("empty", None)
                try:
                    return ("value", pickle.loads(bytes(buf)))
                except Exception:  # noqa: BLE001 - opaque bytes may not be pickle
                    return ("value_raw", bytes(buf))
            elif f.kind == wire.KIND_ERROR:
                return ("error", (f.fields or {}).get("kind"))

    def call_unary(self, *, selector: dict, caller: dict, args_obj,
                   mode: int = wire.MODE_FIRST, handler_timeout=None,
                   timeout: Optional[float] = None):
        """Send a CALL + a single terminal args CHUNK, then read the settled
        result/ERROR. ``args_obj`` is pickled (the node's safe_loads decodes it;
        pass a DISALLOWED reduce for the TG-20 RCE probe)."""
        cid = self.send_call_with_args(
            selector=selector, mode=mode, caller=caller,
            args_bytes=pickle_args(args_obj), handler_timeout=handler_timeout)
        return self.recv_result(cid, timeout=timeout)

    def send_cancel(self, cid: int) -> None:
        self.send_frame(wire.KIND_CANCEL, cid, fields={})

    def send_end(self, cid: int) -> None:
        self.send_frame(wire.KIND_END, cid, fields={})

    def send_error(self, cid: int, kind: int, exc: bytes = b"") -> None:
        self.send_frame(wire.KIND_ERROR, cid, fields={"kind": kind, "exc": exc})


def pickle_args(obj) -> bytes:
    """Serialize a CALL's args the way the node will DESERIALIZE them: the node
    runs ``safe_loads`` (restricted unpickler) on the reassembled CHUNK bytes, so
    args on the wire are a pickle byte-string. For TG-20 the RCE probe pickles a
    DISALLOWED reduce (e.g. os.system) and asserts safe_loads rejects it; the
    control pickles an allowlisted value."""
    import pickle
    return pickle.dumps(obj)


class StallListener:
    """A passive victim listener for the redial-rate / reflected-connect-storm
    cells (TP-50 redial-cap half, TG-19 out-of-CIDR "never dials it").

    It binds a port, ACCEPTS inbound TCP connects, and COUNTS them (optionally
    stalling before/without completing TLS), so a cell can assert the node's dial
    attempts to a never-successfully-handshaked vouched address are bounded to the
    §4.7 fixed low rate (e.g. once per 30s) rather than a storm. This is the
    connection-ATTEMPT observable that §A lacks (flagged in WAVE2_TEST_MAP.md):
    dial frequency is not on snapshot() / any _core event, so counting SYNs at the
    victim is how the security property is measured.

    Runs its accept loop on a background thread; ``connect_count`` /
    ``connect_times`` are the assertions' input.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self.port = self._srv.getsockname()[1]
        self._srv.listen(16)
        self.connect_times: list[float] = []
        self._running = False
        self._thread = None

    @property
    def connect_count(self) -> int:
        return len(self.connect_times)

    def start(self) -> None:
        import threading
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        self._srv.settimeout(0.5)
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connect_times.append(time.time())
            # Stall: never complete TLS, so the node keeps treating the address
            # as never-handshaked (the redial-cap path under test). Close after a
            # beat so file descriptors do not accumulate.
            try:
                conn.settimeout(0.2)
                conn.recv(1)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._running = False
        try:
            self._srv.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
