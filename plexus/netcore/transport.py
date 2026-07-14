"""netcore.transport — §4.4 Transport: one bidirectional link per pair.

Per SPEC §4.4 (Decision 2 = B): ONE multiplexed bidirectional ``PeerLink`` per
pair; pairwise ``lex(self.hostname, peer.hostname)`` dial election (lower dials);
a supervisor per peer dials + reconnects forever with capped backoff; the
acceptor serves inbound connects. mTLS with each peer cert as its own CA
(the SSL contexts come from Membership's context-provider seam) PLUS the
AUTHORITATIVE post-handshake SPKI-pin check on BOTH server + client contexts
(§4.1, fail closed on absent/unpinned SPKI). Universal chunking; cid ownership
by DIAL ROLE (dialer=1, acceptor=0); reassembly bounds with a guaranteed
per-peer MINIMUM + a pop-once decrement; deterministic survivor + flap-guard
probation (§4.4/§7).

Collaborator seams (the three stub modules are INJECTED so this module builds +
self-tests standalone):
  * Membership (context provider) — Transport calls:
      ``server_ssl_context() -> ssl.SSLContext``
      ``client_ssl_context() -> ssl.SSLContext``
      ``resolve_pin(spki_fingerprint: str) -> Optional[str]``  (hostname | None,
        dereferences the LIVE pin set at check time; None => fail closed)
      ``in_roster(hostname: str) -> bool``                      (roster gate)
      ``identity_for(hostname: str) -> PeerIdentity``           (auth identity)
      ``on_link_up(hostname: str) -> None``                     (routable SLA)
      attr ``self_hostname: str``                               (lex election)
  * Directory — ``serve_ping(hostname, have_hash) -> Optional[Pong]`` (inbound
    PING; returns None to DROP under the per-peer PING-floor, else if
    ``snapshot_follows`` the returned ``Pong.snapshot`` holds the
    ``DirectorySnapshot`` OBJECT to serialize as the trailing snapshot body).
  * Dispatch — the inbound handler seam (SPEC §4.5/§8.1/§8.2):
      ``authorize_inbound(identity, frame) -> None``  SYNC header authz+rate
        BEFORE any arg CHUNK is buffered; raise ``InboundReject`` to reject.
      ``dispatch_inbound(identity, frame, args)`` ASYNC — returns the value
        (UNARY/FIRST), an async-iterator (STREAM), or None (FANOUT); raise
        ``InboundReject`` (mapped ERROR) or any exception (HANDLER_RAISED).
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import logging
from typing import Any, Deque, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .types import (
    ErrorKind,
    Kind,
    LinkDown,
    LinkRefused,
    Mode,
    PeerIdentity,
    PeerSpec,
    Pending,
    Pong,
    ProtocolError,
    Timeout,
)
from .wire import (
    CHUNK_SIZE,
    PER_CID_REASSEMBLY_CAP,
    Frame,
    FrameReader,
    ReassemblyBoundExceeded,
    Reassembler,
    chunk_value,
    decode_snapshot,
    deserialize_value,
    encode_call,
    encode_cancel,
    encode_chunk,
    encode_end,
    encode_error,
    encode_ping,
    encode_pong,
    encode_snapshot,
    serialize_value,
)

_logger = logging.getLogger("plexus.netcore.transport")


# --- SPEC §11 defaults (tunable; overridable via Transport kwargs) ----------
STREAM_QUEUE_MAXSIZE = 32
CONNECT_TIMEOUT = 10.0
BACKOFF_INITIAL = 0.5
BACKOFF_CAP = 25.0
IDLE_READ_DEADLINE = 25.0        # ~2-2.5x heartbeat (10s)
STREAM_IDLE_DEADLINE = 30.0      # per-chunk stream idle = request_timeout
REASSEMBLY_ABS_DEADLINE = 60.0   # absolute per-reassembly deadline, MONOTONIC (§4.4 / TG-18)
DRAIN_TIMEOUT = 30.0             # bounded writer.drain()
PER_PEER_REASSEMBLY_CAP = 16 * 1024 * 1024
PER_PEER_REASSEMBLY_MIN = 2 * 1024 * 1024
NODE_WIDE_REASSEMBLY_CAP = 128 * 1024 * 1024
PER_PEER_CID_CAP = 64

# The cid high bit encodes DIAL ROLE (dialer=1, acceptor=0), §4.4/§5.
_HIGH_BIT = 1 << 63
_CID_MASK = (1 << 63) - 1

# Pump batch bound: keep a PING preemptable within probe_timeout on a congested
# link (SPEC §4.4 write-pump).
BATCH_MAX_BYTES = 256 * 1024


def _spki_fingerprint(der_cert: bytes) -> str:
    """Compute ``sha256:<hex>`` of the cert's SubjectPublicKeyInfo DER (SPEC
    §4.1) — mirrors ``serialization.generate_keypair``'s fingerprint format."""
    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


class InboundReject(Exception):
    """A Dispatch-seam rejection carrying the ERROR.kind the callee replies with
    (SPEC §4.5). ``authorize_inbound`` / ``dispatch_inbound`` raise this for the
    NO_MATCH / NO_ENDPOINT / RATE_LIMIT / CAPABILITY / NETWORK dispositions; a
    plain handler exception is mapped to HANDLER_RAISED instead."""

    def __init__(self, error_kind: ErrorKind, exc: Any = None):
        super().__init__(f"inbound reject: {error_kind!r}")
        self.error_kind = error_kind
        self.exc = exc


class _OutValue:
    """A whole logical VALUE queued for the write-pump: its pre-built frame
    byte-strings emitted CONTIGUOUSLY (SPEC §4.4). ``fanout`` marks it as the
    all-or-nothing drop unit on out_q overflow; ``started`` guards drop-oldest
    (never drop a value with any chunk already on the wire)."""

    __slots__ = ("frames", "fanout", "started")

    def __init__(self, frames: List[bytes], fanout: bool = False):
        self.frames = frames
        self.fanout = fanout
        self.started = False


class _InboundCid:
    """Callee-side state for one peer-opened cid (a CALL). Owns its own arg
    reassembly + handler task (SPEC §4.4)."""

    __slots__ = (
        "cid",
        "frame",
        "reasm",
        "reassembly_bytes",
        "args_future",
        "args_bytes",
        "task",
        "_abs_timer",
        "_idle_timer",
    )

    def __init__(self, cid: int, frame: Frame, per_cid_cap: int):
        self.cid = cid
        self.frame = frame
        self.reasm = Reassembler(per_cid_cap)
        self.reassembly_bytes = 0
        self.args_future: Optional[asyncio.Future] = None
        self.args_bytes: bytes = b""
        self.task: Optional[asyncio.Task] = None
        self._abs_timer = None
        self._idle_timer = None


class StreamQueue:
    """A bounded async queue backing a cross-node STREAM (SPEC §3/§4.4). One
    item per ``CHUNK{last=true}``; closes on ``END``; a slow/abandoned consumer
    (queue full on ``offer``) makes the reader FAIL the stream + CANCEL (SPEC §10
    slow-consumer row)."""

    _CLOSE = object()

    def __init__(self, cid: int, maxsize: int = STREAM_QUEUE_MAXSIZE):
        self._cid = cid
        self._q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._error: Optional[BaseException] = None
        self._closed = False

    @property
    def cid(self) -> int:
        """The link cid this stream reassembles on (SPEC §3)."""
        return self._cid

    def offer(self, item: Any) -> bool:
        """Reader-side non-blocking put; False if the consumer is too slow
        (queue full) so the reader can fail the stream (never block the loop)."""
        try:
            self._q.put_nowait(item)
            return True
        except asyncio.QueueFull:
            return False

    def close(self) -> None:
        """Signal a clean END (SPEC §4.4)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._q.put_nowait(self._CLOSE)
        except asyncio.QueueFull:
            pass

    def fail(self, exc: BaseException) -> None:
        """Signal a terminal error to the consumer (peer-down / bound-exceed /
        mapped ERROR)."""
        if self._error is None:
            self._error = exc
        try:
            self._q.put_nowait(self._CLOSE)
        except asyncio.QueueFull:
            pass

    def __aiter__(self) -> "StreamQueue":
        return self

    async def __anext__(self) -> Any:
        item = await self._q.get()
        if item is self._CLOSE:
            if self._error is not None:
                raise self._error
            raise StopAsyncIteration
        return item


class PeerLink:
    """One multiplexed bidirectional mTLS link to a single peer (SPEC §4.4).

    Each INSTANCE owns its OWN ``_pending`` (my-outbound cids), inbound-task set,
    and per-cid reassembly buffers; a replacement swaps the whole object so a
    dying instance's terminal fail-pending touches only its own maps (§4.4/§7).
    The cid high bit is assigned by DIAL ROLE (dialer=1, acceptor=0)."""

    def __init__(
        self,
        transport: "Transport",
        hostname: str,
        *,
        is_dialer: bool,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self._transport = transport
        self._hostname = hostname
        self._is_dialer = is_dialer
        self._reader = reader
        self._writer = writer
        self._framereader = FrameReader(reader)
        self._loop = asyncio.get_event_loop()

        # cid role bit (§4.4): dialer=1, acceptor=0.
        self._role_bit = 1 if is_dialer else 0
        self._counter = 0

        # Election vs override role (§4.4 survivor/flap). The DIALER of this link
        # is lex-lower iff this is the election link.
        dialer = transport.self_hostname if is_dialer else hostname
        other = hostname if is_dialer else transport.self_hostname
        self.is_election = dialer < other
        self.is_override = not self.is_election

        self._per_cid_cap = transport.per_cid_cap

        # Outbound correlation (my-allocated cids).
        self._pending: Dict[int, Pending] = {}
        # Inbound cids (peer-opened CALLs).
        self._inbound: Dict[int, _InboundCid] = {}
        self._inbound_tasks: set = set()

        # Reassembly bytes currently charged to THIS peer (node-wide lives on
        # Transport). §4.4/§7.
        self._reasm_bytes = 0

        # Write-pump structures.
        self._priority: Deque[bytes] = collections.deque()   # control preempts
        self._value_q: Deque[_OutValue] = collections.deque()
        self._current: Optional[_OutValue] = None
        self._cur_idx = 0
        self._pump_wake = asyncio.Event()

        self._closed = False
        self._closed_event = asyncio.Event()
        self._reader_task: Optional[asyncio.Task] = None
        self._pump_task: Optional[asyncio.Task] = None

    # --- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Start the reader + write-pump tasks (SPEC §4.4)."""
        self._reader_task = self._loop.create_task(self.run_reader())
        self._pump_task = self._loop.create_task(self.run_write_pump())

    @property
    def closed(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        """Block until the link is torn down (supervisor reconnect trigger)."""
        await self._closed_event.wait()

    async def close(self, reason: str = "closed") -> None:
        """Tear the link + cancel/await ALL inbound tasks (SPEC §4.4)."""
        self._terminal_teardown(reason)
        tasks = [t for t in (self._reader_task, self._pump_task) if t]
        tasks += list(self._inbound_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            # gather(return_exceptions=True) captures the tasks' OWN
            # CancelledErrors as results (swallowed) while a CancelledError
            # targeting close() ITSELF still propagates out of the gather.
            await asyncio.gather(*tasks, return_exceptions=True)

    def _tear(self, reason: str) -> None:
        """Trigger the reader-terminal act from a non-reader path (drain fail)."""
        self._terminal_teardown(reason)

    # --- cid allocation (§4.4) --------------------------------------------
    def _alloc_cid(self) -> int:
        while True:
            self._counter = (self._counter + 1) & _CID_MASK
            if self._counter == 0:
                continue
            cid = self._counter | (self._role_bit << 63)
            if cid not in self._pending:
                return cid

    # --- enqueue (write-pump inputs) --------------------------------------
    def enqueue_control(self, frame_bytes: bytes) -> None:
        """Enqueue a control frame on the PRIORITY lane (PING/PONG/CANCEL);
        preempts BETWEEN a value's chunks (SPEC §4.4)."""
        self._priority.append(frame_bytes)
        self._pump_wake.set()

    def enqueue_value(self, value: _OutValue) -> None:
        """Enqueue a whole logical VALUE (SPEC §4.4). On out_q overflow,
        drop-oldest drops a whole NOT-YET-STARTED FANOUT value (never partial,
        never a non-fanout value)."""
        if len(self._value_q) >= self._transport.out_q_max:
            if value.fanout:
                for i, existing in enumerate(self._value_q):
                    if existing.fanout and not existing.started:
                        del self._value_q[i]
                        break
                else:
                    # nothing droppable -> drop the incoming fanout (sends nothing)
                    return
            # non-fanout: never dropped; allow overflow (backpressure via drain +
            # the request deadline).
        self._value_q.append(value)
        self._pump_wake.set()

    # --- write-pump (SPEC §4.4) -------------------------------------------
    async def run_write_pump(self) -> None:
        try:
            while not self._closed:
                await self._pump_wake.wait()
                self._pump_wake.clear()
                batch = self._collect_batch()
                if not batch:
                    continue
                try:
                    self._writer.write(b"".join(batch))
                    await asyncio.wait_for(
                        self._writer.drain(), self._transport._drain_timeout
                    )
                except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
                    self._tear(f"drain failed: {exc!r}")
                    return
        except asyncio.CancelledError:
            raise

    def _collect_batch(self) -> List[bytes]:
        """Assemble one wake's write batch (sync, await-free). Control preempts;
        each value's chunks emitted CONTIGUOUSLY; cids switch only BETWEEN
        values; bounded so a huge value can't HoL a PING (SPEC §4.4)."""
        out: List[bytes] = []
        size = 0
        # control first
        while self._priority:
            b = self._priority.popleft()
            out.append(b)
            size += len(b)
        while size < BATCH_MAX_BYTES:
            if self._priority:
                while self._priority:
                    b = self._priority.popleft()
                    out.append(b)
                    size += len(b)
            if self._current is None:
                if not self._value_q:
                    break
                self._current = self._value_q.popleft()
                self._current.started = True
                self._cur_idx = 0
            v = self._current
            if self._cur_idx >= len(v.frames):
                self._current = None
                continue
            fb = v.frames[self._cur_idx]
            self._cur_idx += 1
            out.append(fb)
            size += len(fb)
        if self._priority or self._current is not None or self._value_q:
            self._pump_wake.set()
        return out

    # --- reader (SPEC §4.4) -----------------------------------------------
    async def run_reader(self) -> None:
        try:
            while True:
                frame = await asyncio.wait_for(
                    self._framereader.read_frame(),
                    self._transport._idle_read_deadline,
                )
                self._route_frame(frame)
        except asyncio.CancelledError:
            self._terminal_teardown("cancelled")
            raise
        except asyncio.TimeoutError:
            self._terminal_teardown("idle read deadline")
        except (LinkDown, ProtocolError, ConnectionError, OSError) as exc:
            self._terminal_teardown(f"reader: {exc!r}")
        except Exception as exc:  # noqa: BLE001 - defensive: never leak
            _logger.exception("reader crashed for %s", self._hostname)
            self._terminal_teardown(f"reader crash: {exc!r}")

    def _route_frame(self, frame: Frame) -> None:
        """Route ONE frame (sync, await-free). PING -> Directory; CALL opens an
        inbound cid; CANCEL inline; CHUNK/END/ERROR/PONG by cid ownership
        (SPEC §4.4)."""
        kind = frame.kind
        if kind == Kind.PING:
            self._handle_inbound_ping(frame)
            return
        if kind == Kind.CANCEL:
            self._handle_cancel(frame.cid)
            return
        if kind == Kind.CALL:
            self._open_inbound(frame)
            return
        # PONG / CHUNK / END / ERROR — route by cid ownership high bit.
        allocator_bit = (frame.cid >> 63) & 1
        if allocator_bit == self._role_bit:
            self._route_pending(frame)   # my outbound (reply to me / ping snapshot)
        else:
            self._route_inbound(frame)   # peer inbound (its CALL args)

    # --- inbound PING -> Directory.serve_ping (§3/§4.4) -------------------
    def _handle_inbound_ping(self, frame: Frame) -> None:
        directory = self._transport.directory
        try:
            # PING-floor suppress seam (§8.2, phase-2b flag #7): the peer-keyed
            # ``serve_ping`` applies the per-peer floor + returns None to DROP a
            # below-floor PING (at-most-one PONG per window).
            pong = directory.serve_ping(self._hostname, frame.have_hash)
        except Exception as exc:  # noqa: BLE001 - never crash the reader on a serve
            _logger.warning("serve_ping failed for %s: %r", self._hostname, exc)
            return
        if pong is None:
            return  # PING-floor suppressed: at-most-one PONG per window (§8.2)
        # PONG header on the priority lane.
        self.enqueue_control(
            encode_pong(
                frame.cid, pong.epoch, pong.content_hash, pong.snapshot_follows
            )
        )
        if pong.snapshot_follows and pong.snapshot is not None:
            # MSGPACK-encode the snapshot (§4.4 LOCKED: DirectorySnapshot=msgpack,
            # NOT pickle) + chunk it on the ping cid, then END.
            frames: List[bytes] = []
            raw = encode_snapshot(pong.snapshot)
            for frag, last in chunk_value(raw):
                frames.append(encode_chunk(frame.cid, frag, last))
            frames.append(encode_end(frame.cid))
            self.enqueue_value(_OutValue(frames))

    # --- inbound CALL (§4.4/§4.5) -----------------------------------------
    def _open_inbound(self, frame: Frame) -> None:
        cid = frame.cid
        if cid in self._inbound:
            return  # duplicate CALL for an open cid -> ignore
        if len(self._inbound) >= self._transport.per_peer_cid_cap:
            self.enqueue_value(_OutValue([encode_error(cid, ErrorKind.NETWORK)]))
            return
        identity = self._transport.membership.identity_for(self._hostname)
        # HEADER authz+rate BEFORE opening the cid / buffering args (§4.4/§8.2).
        try:
            self._transport.dispatch.authorize_inbound(identity, frame)
        except InboundReject as r:
            self.enqueue_value(
                _OutValue([encode_error(cid, r.error_kind, r.exc)])
            )
            return
        except Exception as exc:  # noqa: BLE001
            _logger.warning("authorize_inbound crashed: %r", exc)
            self.enqueue_value(_OutValue([encode_error(cid, ErrorKind.NETWORK)]))
            return
        inb = _InboundCid(cid, frame, self._per_cid_cap)
        inb.args_future = self._loop.create_future()
        self._inbound[cid] = inb
        # G1-mirror: arm the ABSOLUTE reassembly deadline at the CALL HEADER, not
        # only at the first arg CHUNK. A peer that opens the cid then withholds every
        # arg CHUNK on an otherwise-busy link would otherwise park _run_inbound on
        # args_future forever (the first-chunk arm in _touch_reassembly_timers never
        # runs). Idempotent with that arm (it sets _abs_timer only when None). On
        # expiry _reassembly_deadline_fired -> _reassembly_exceed_inbound frees the
        # cid + cancels the task, KEEPS the link.
        if inb._abs_timer is None:
            inb._abs_timer = self._loop.call_later(
                self._transport._reassembly_abs_deadline,
                self._reassembly_deadline_fired,
                inb,
                True,
            )
        inb.task = self._loop.create_task(self._run_inbound(inb))
        self._inbound_tasks.add(inb.task)
        inb.task.add_done_callback(self._inbound_tasks.discard)

    async def _run_inbound(self, inb: _InboundCid) -> None:
        cid = inb.cid
        try:
            try:
                await inb.args_future  # reader completes reassembly / fails on down
            except asyncio.CancelledError:
                return
            try:
                args = deserialize_value(inb.args_bytes)
            except Exception:  # safe_loads reject / bad payload -> NETWORK
                self.enqueue_value(_OutValue([encode_error(cid, ErrorKind.NETWORK)]))
                return
            identity = self._transport.membership.identity_for(self._hostname)
            mode = inb.frame.mode
            try:
                if mode in (Mode.UNARY, Mode.FIRST):
                    result = await self._transport.dispatch.dispatch_inbound(
                        identity, inb.frame, args
                    )
                    self._send_value_reply(cid, result)
                elif mode == Mode.STREAM:
                    await self._run_stream_handler(inb, identity, args)
                elif mode == Mode.FANOUT:
                    await self._transport.dispatch.dispatch_inbound(
                        identity, inb.frame, args
                    )  # no reply
            except InboundReject as r:
                if mode != Mode.FANOUT:
                    self.enqueue_value(
                        _OutValue([encode_error(cid, r.error_kind, r.exc)])
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - handler raised
                if mode != Mode.FANOUT:
                    self.enqueue_value(
                        _OutValue(
                            [encode_error(cid, ErrorKind.HANDLER_RAISED, exc)]
                        )
                    )
        finally:
            self._inbound.pop(cid, None)

    def _send_value_reply(self, cid: int, value: Any) -> None:
        frames: List[bytes] = []
        raw = serialize_value(value)
        for frag, last in chunk_value(raw):
            frames.append(encode_chunk(cid, frag, last))
        frames.append(encode_end(cid))
        self.enqueue_value(_OutValue(frames))

    async def _run_stream_handler(
        self, inb: _InboundCid, identity: PeerIdentity, args: Any
    ) -> None:
        cid = inb.cid
        agen = self._transport.dispatch.dispatch_inbound(identity, inb.frame, args)
        try:
            if agen is not None:
                async for item in agen:
                    frames = [
                        encode_chunk(cid, frag, last)
                        for frag, last in chunk_value(serialize_value(item))
                    ]
                    # each stream ITEM is one whole value (cids switch only
                    # between items, never mid-item — B-019 order).
                    self.enqueue_value(_OutValue(frames))
            self.enqueue_value(_OutValue([encode_end(cid)]))
        finally:
            # generator close on cancel / completion (SPEC §4.4).
            aclose = getattr(agen, "aclose", None)
            if aclose is not None:
                try:
                    await aclose()
                except Exception:  # noqa: BLE001
                    pass

    # --- inbound CHUNK routing (peer's CALL args) -------------------------
    def _route_inbound(self, frame: Frame) -> None:
        inb = self._inbound.get(frame.cid)
        if inb is None:
            return  # unknown/closed inbound cid -> silently discard (§4.4)
        if frame.kind != Kind.CHUNK:
            return  # only CHUNK is expected inbound (args); stray END/ERROR -> drop
        if inb.args_future is None or inb.args_future.done():
            return  # extra chunk after args complete -> discard
        delta = len(frame.data or b"")
        if not self._charge(inb.reasm, delta):
            self._reassembly_exceed_inbound(inb)
            return
        try:
            complete, _d = inb.reasm.accept(frame.data or b"", bool(frame.last))
        except ReassemblyBoundExceeded:
            self._reassembly_exceed_inbound(inb)
            return
        self._transport.commit_charge(self, delta)
        inb.reassembly_bytes += delta
        if complete:
            self._cancel_reassembly_timers(inb)  # reassembly done
            inb.args_bytes = inb.reasm.take()
            # reassembly budget freed AT DISPATCH (SPEC §4.4).
            self._release_charge_inbound(inb)
            if not inb.args_future.done():
                inb.args_future.set_result(None)
        else:
            # arm the absolute deadline (first chunk) + reset the idle deadline.
            self._touch_reassembly_timers(inb, inbound=True)

    def _reassembly_exceed_inbound(self, inb: _InboundCid) -> None:
        """Per §4.4: FAIL CLOSED — drop cid + CANCEL + reject, KEEP THE LINK."""
        self._cancel_reassembly_timers(inb)
        self._release_charge_inbound(inb)
        self.enqueue_control(encode_cancel(inb.cid))
        self._transport.observe_reject("reassembly_bound", self._hostname)
        self._inbound.pop(inb.cid, None)
        if inb.task and not inb.task.done():
            inb.task.cancel()

    # --- outbound reply routing (my pending) ------------------------------
    def _route_pending(self, frame: Frame) -> None:
        entry = self._pending.get(frame.cid)
        if entry is None:
            return  # unknown/closed -> straggler, discard
        if frame.kind == Kind.PONG:
            self._settle_pong(entry, frame)
        elif frame.kind == Kind.CHUNK:
            self._accumulate_pending(entry, frame)
        elif frame.kind == Kind.END:
            self._settle_end(entry)
        elif frame.kind == Kind.ERROR:
            self._settle_error(entry, frame)

    def _accumulate_pending(self, entry: Pending, frame: Frame) -> None:
        delta = len(frame.data or b"")
        if not self._charge(entry.reassembly_buf, delta):
            self._reassembly_exceed_pending(entry)
            return
        try:
            complete, _d = entry.reassembly_buf.accept(
                frame.data or b"", bool(frame.last)
            )
        except ReassemblyBoundExceeded:
            self._reassembly_exceed_pending(entry)
            return
        self._transport.commit_charge(self, delta)
        entry.reassembly_bytes += delta
        # arm absolute (first chunk of THIS reassembly) + reset idle (every chunk).
        self._touch_reassembly_timers(entry, inbound=False)

        if entry.mode == Mode.STREAM:
            if complete:
                # per-ITEM absolute deadline: cancel it so the next item re-arms
                # fresh (a stream may run indefinitely); keep the idle deadline
                # running to bound the gap to the next item.
                self._cancel_abs_timer(entry)
                raw = entry.reassembly_buf.take()
                # free this item's bytes; reset for the next item.
                self._release_charge_pending(entry)
                entry.reassembly_buf = Reassembler(self._per_cid_cap)
                q: StreamQueue = entry.fut_or_queue
                try:
                    item = deserialize_value(raw)
                except Exception as exc:  # noqa: BLE001
                    self._fail_stream(entry, exc)
                    return
                if not q.offer(item):
                    # slow/abandoned consumer -> fail stream + CANCEL (§10).
                    self.enqueue_control(encode_cancel(entry.cid))
                    self._fail_stream(
                        entry, LinkDown("stream consumer backpressure")
                    )

    def _settle_pong(self, entry: Pending, frame: Frame) -> None:
        pong = Pong(
            epoch=frame.epoch,
            content_hash=frame.content_hash,
            snapshot_follows=bool(frame.snapshot_follows),
        )
        if not frame.snapshot_follows:
            # header-terminal: settle + close the cid (SPEC §4.4).
            self._pending.pop(entry.cid, None)
            self._cancel_timer(entry)
            self._cancel_reassembly_timers(entry)
            self._release_charge_pending(entry)
            if not entry.fut_or_queue.done():
                entry.fut_or_queue.set_result(pong)
            return
        # snapshot follows: settle the header now, reassemble the body on this
        # cid, settle .snapshot on END. The header stamp keeps the peer reachable
        # even if the snapshot later trips a bound (§4.4 carve-out).
        snap_future = self._loop.create_future()
        pong.snapshot = snap_future
        entry.snapshot_follows = True
        entry._snapshot_future = snap_future
        # G1 (panel concurrency #1 landmine): arm the ABSOLUTE reassembly deadline at the
        # PONG HEADER, not only at the first snapshot CHUNK. A peer that promises
        # snapshot_follows=true then withholds every CHUNK on an otherwise-busy link would
        # otherwise park this pending entry forever (no timer ever armed). Idempotent with
        # the first-chunk arm in _touch_reassembly_timers (which arms _abs_timer only when
        # it is None). On expiry _reassembly_deadline_fired -> _reassembly_exceed_pending
        # frees the cid and resolves the snapshot to None (G7), peer stays reachable.
        if entry._abs_timer is None:
            entry._abs_timer = self._loop.call_later(
                self._transport._reassembly_abs_deadline,
                self._reassembly_deadline_fired,
                entry,
                False,
            )
        self._cancel_timer(entry)  # header answered; body bounded by reassembly
        if not entry.fut_or_queue.done():
            entry.fut_or_queue.set_result(pong)

    def _settle_end(self, entry: Pending) -> None:
        self._pending.pop(entry.cid, None)
        self._cancel_timer(entry)
        self._cancel_reassembly_timers(entry)
        raw = entry.reassembly_buf.take()
        self._release_charge_pending(entry)

        if entry.mode == Mode.PING:
            snap_future = getattr(entry, "_snapshot_future", None)
            if snap_future is not None and not snap_future.done():
                try:
                    # MSGPACK-decode the snapshot body (§4.4 LOCKED) — NOT the
                    # app-value safe_loads path; count-bounds raise ProtocolError,
                    # which the pinger drops (peer stays reachable via the header).
                    snap = decode_snapshot(raw) if raw else None
                    snap_future.set_result(snap)
                except Exception:  # noqa: BLE001
                    # G7 (panel robustness/correctness): a malformed/over-count snapshot
                    # body on a STILL-LIVE peer resolves to None (peer stays reachable,
                    # pulse applies no snapshot), NOT set_exception — an unguarded pulse
                    # await must never down a live peer over a bad snapshot.
                    snap_future.set_result(None)
            return
        if entry.mode == Mode.STREAM:
            entry.fut_or_queue.close()
            return
        # UNARY / FIRST: settle the single reassembled value on END.
        fut = entry.fut_or_queue
        if fut.done():
            return
        if not raw:
            # END with no value (SPEC §4.4 unary anomaly) -> fail this request,
            # KEEP the link (a per-request anomaly is not a frame malformation).
            fut.set_exception(ProtocolError("UNARY END with no CHUNK value"))
            return
        try:
            fut.set_result(deserialize_value(raw))
        except Exception as exc:  # noqa: BLE001
            fut.set_exception(exc)

    def _settle_error(self, entry: Pending, frame: Frame) -> None:
        # §3: Transport.request RETURNS a raw ERROR frame so Dispatch maps it.
        self._pending.pop(entry.cid, None)
        self._cancel_timer(entry)
        self._cancel_reassembly_timers(entry)
        self._release_charge_pending(entry)
        if entry.mode == Mode.STREAM:
            self._fail_stream(entry, _error_frame_holder(frame))
            return
        fut = entry.fut_or_queue
        if not fut.done():
            fut.set_result(frame)  # raw ERROR frame

    # --- CANCEL (inline, bidirectional lookup) ----------------------------
    def _handle_cancel(self, cid: int) -> None:
        """Handle CANCEL inline (SPEC §4.4): it may reference MY outbound (peer
        dropped my request) or an inbound cid (peer cancels its request). No-op
        on an unknown/completed cid."""
        entry = self._pending.pop(cid, None)
        if entry is not None:
            self._cancel_timer(entry)
            self._cancel_reassembly_timers(entry)
            self._release_charge_pending(entry)
            self._fail_entry(entry, LinkDown("cancelled by peer"))
            return
        inb = self._inbound.pop(cid, None)
        if inb is not None:
            self._cancel_reassembly_timers(inb)
            self._release_charge_inbound(inb)
            if inb.task and not inb.task.done():
                inb.task.cancel()

    # --- reassembly budget helpers (§4.4/§7) ------------------------------
    def _charge(self, reasm: Reassembler, delta: int) -> bool:
        """Peek ALL bounds (per-cid + per-peer/node-wide with the guaranteed
        MINIMUM) WITHOUT mutating; True iff the delta fits."""
        if reasm.byte_count + delta > reasm.per_cid_cap:
            return False
        return self._transport.can_charge(self, delta)

    def _release_charge_pending(self, entry: Pending) -> None:
        amt = entry.reassembly_bytes
        if amt:
            self._transport.release_charge(self, amt)
            entry.reassembly_bytes = 0

    def _release_charge_inbound(self, inb: _InboundCid) -> None:
        amt = inb.reassembly_bytes
        if amt:
            self._transport.release_charge(self, amt)
            inb.reassembly_bytes = 0

    def _reassembly_exceed_pending(self, entry: Pending) -> None:
        self._pending.pop(entry.cid, None)
        self._cancel_timer(entry)
        self._cancel_reassembly_timers(entry)
        self._release_charge_pending(entry)
        self.enqueue_control(encode_cancel(entry.cid))
        self._transport.observe_reject("reassembly_bound", self._hostname)
        # PING-snapshot carve-out: header already settled -> DROP the snapshot; the
        # peer STAYS reachable (Membership stamped last_seen on the header).
        # G7 (panel robustness/correctness, MODERATE): resolve the snapshot to None
        # rather than set_exception(LinkDown) — this is a STILL-LIVE peer, and an
        # unguarded `await pong.snapshot` on the pulse path must NOT down it. The pulse
        # sees None and simply applies no snapshot. The genuine link-DOWN path
        # (_fail_entry) still set_exceptions the snapshot.
        snap_future = getattr(entry, "_snapshot_future", None)
        if entry.mode == Mode.PING and snap_future is not None:
            if not snap_future.done():
                snap_future.set_result(None)
            return
        self._fail_entry(entry, LinkDown("reassembly bound exceeded"))

    # --- timers -----------------------------------------------------------
    def _cancel_timer(self, entry: Pending) -> None:
        timer = getattr(entry, "_timer", None)
        if timer is not None:
            timer.cancel()

    # --- per-reassembly deadlines (SPEC §4.4 / TG-18 / TP-75) --------------
    # An ABSOLUTE 60s deadline (armed once at the FIRST chunk of a reassembly)
    # PLUS a per-chunk IDLE deadline (reset every chunk). Both are anchored on
    # the event loop's MONOTONIC clock (``call_later``/``call_at`` use
    # ``loop.time()``), so a backward WALL-clock (NTP) step can NOT extend a
    # slow-drip. On fire -> FAIL CLOSED exactly like a bound-exceed (drop cid +
    # CANCEL + free budget + KEEP the link).
    def _touch_reassembly_timers(self, entry: Any, *, inbound: bool) -> None:
        """Arm the absolute deadline once (first chunk) + reset the per-chunk
        idle deadline (every chunk)."""
        loop = self._loop
        if getattr(entry, "_abs_timer", None) is None:
            entry._abs_timer = loop.call_later(
                self._transport._reassembly_abs_deadline,
                self._reassembly_deadline_fired,
                entry,
                inbound,
            )
        old = getattr(entry, "_idle_timer", None)
        if old is not None:
            old.cancel()
        entry._idle_timer = loop.call_later(
            self._transport._stream_idle,
            self._reassembly_deadline_fired,
            entry,
            inbound,
        )

    def _arm_stream_idle(self, entry: Pending) -> None:
        """Arm the per-chunk idle deadline at STREAM OPEN so a stream that never
        produces its first item is still bounded (SPEC §4.4)."""
        old = getattr(entry, "_idle_timer", None)
        if old is not None:
            old.cancel()
        entry._idle_timer = self._loop.call_later(
            self._transport._stream_idle,
            self._reassembly_deadline_fired,
            entry,
            False,
        )

    def _cancel_abs_timer(self, entry: Any) -> None:
        t = getattr(entry, "_abs_timer", None)
        if t is not None:
            t.cancel()
            entry._abs_timer = None

    def _cancel_reassembly_timers(self, entry: Any) -> None:
        for name in ("_abs_timer", "_idle_timer"):
            t = getattr(entry, name, None)
            if t is not None:
                t.cancel()
                setattr(entry, name, None)

    def _reassembly_deadline_fired(self, entry: Any, inbound: bool) -> None:
        """A per-reassembly deadline (absolute or idle) elapsed: FAIL CLOSED,
        KEEP the link (SPEC §4.4)."""
        if inbound:
            if self._inbound.get(entry.cid) is not entry:
                return  # already settled/dropped
            self._reassembly_exceed_inbound(entry)
        else:
            if self._pending.get(entry.cid) is not entry:
                return
            self._reassembly_exceed_pending(entry)

    def _fail_timeout(self, cid: int) -> None:
        entry = self._pending.pop(cid, None)
        if entry is None:
            return
        self._cancel_reassembly_timers(entry)
        self._release_charge_pending(entry)
        self.enqueue_control(encode_cancel(cid))  # tell the callee to stop
        self._fail_entry(entry, Timeout(f"request {cid} deadline"))

    def _fail_stream(self, entry: Pending, exc: BaseException) -> None:
        self._pending.pop(entry.cid, None)
        self._cancel_timer(entry)
        self._cancel_reassembly_timers(entry)
        self._release_charge_pending(entry)
        entry.fut_or_queue.fail(exc)

    def _fail_entry(self, entry: Pending, exc: BaseException) -> None:
        target = entry.fut_or_queue
        if isinstance(target, StreamQueue):
            target.fail(exc)
            return
        snap_future = getattr(entry, "_snapshot_future", None)
        if not target.done():
            target.set_exception(exc)
        elif snap_future is not None and not snap_future.done():
            snap_future.set_exception(exc)

    # --- link-down terminal act (reader, await-free) ----------------------
    def _terminal_teardown(self, reason: str) -> None:
        if self._closed:
            return
        self._closed = True
        # fail all pending + release budgets.
        for cid in list(self._pending.keys()):
            entry = self._pending.pop(cid, None)
            if entry is None:
                continue
            self._cancel_timer(entry)
            self._cancel_reassembly_timers(entry)
            self._release_charge_pending(entry)
            self._fail_entry(entry, LinkDown(reason))
        # discard inbound reassembly + cancel inbound tasks (awaited in close()).
        for cid in list(self._inbound.keys()):
            inb = self._inbound.pop(cid, None)
            if inb is None:
                continue
            self._cancel_reassembly_timers(inb)
            self._release_charge_inbound(inb)
            if inb.task and not inb.task.done():
                inb.task.cancel()
        try:
            self._writer.close()
        except Exception:  # noqa: BLE001
            pass
        self._pump_wake.set()  # wake the pump so it observes _closed and exits
        self._closed_event.set()
        self._transport._on_link_closed(self._hostname, self)

    # --- outbound request/ping/stream/fanout ------------------------------
    async def request(
        self, call_frame: Frame, args: Any, deadline: float
    ) -> Any:
        """Send a UNARY/FIRST CALL; await the reply. Returns the value on END OR
        a raw ERROR frame on ERROR; raises LinkDown/Timeout (SPEC §3)."""
        cid = self._alloc_cid()
        fut = self._loop.create_future()
        entry = Pending(
            cid=cid,
            deadline=deadline,
            mode=call_frame.mode,
            fut_or_queue=fut,
            reassembly_buf=Reassembler(self._per_cid_cap),
            reassembly_bytes=0,
        )
        self._pending[cid] = entry
        # `deadline` is a RELATIVE duration from the caller (events.py passes
        # `deadline=timeout_duration`), or None for UNBOUNDED (learning 11: a None
        # deadline must arm NO timer, never `max(0.0, None)`).
        if deadline is not None:
            entry._timer = self._loop.call_later(max(0.0, deadline), self._fail_timeout, cid)
        self._enqueue_call(cid, call_frame, args, fanout=False)
        return await fut

    async def open_stream(self, call_frame: Frame, args: Any) -> StreamQueue:
        """Send a STREAM CALL; return a StreamQueue exposing the cid (SPEC §3)."""
        cid = self._alloc_cid()
        q = StreamQueue(cid, self._transport.stream_queue_maxsize)
        entry = Pending(
            cid=cid,
            deadline=0.0,
            mode=Mode.STREAM,
            fut_or_queue=q,
            reassembly_buf=Reassembler(self._per_cid_cap),
            reassembly_bytes=0,
        )
        self._pending[cid] = entry
        # bound a stream that never produces its first item (SPEC §4.4).
        self._arm_stream_idle(entry)
        self._enqueue_call(cid, call_frame, args, fanout=False)
        return q

    def send(self, call_frame: Frame, args: Any) -> None:
        """FANOUT: enqueue the CALL + arg CHUNKs as ONE whole value (all-or-
        nothing under out_q drop), NO terminator, NO reply (SPEC §3/§4.4)."""
        cid = self._alloc_cid()
        self._enqueue_call(cid, call_frame, args, fanout=True)

    async def ping(self, have_hash: str, deadline: float) -> Pong:
        """Send PING on a fresh cid; return on the PONG HEADER (SPEC §3/§4.4)."""
        cid = self._alloc_cid()
        fut = self._loop.create_future()
        entry = Pending(
            cid=cid,
            deadline=deadline,
            mode=Mode.PING,
            fut_or_queue=fut,
            reassembly_buf=Reassembler(self._per_cid_cap),
            reassembly_bytes=0,
        )
        self._pending[cid] = entry
        # `deadline` is a RELATIVE duration from the caller (events.py passes
        # `deadline=timeout_duration`), or None for UNBOUNDED (learning 11: a None
        # deadline must arm NO timer, never `max(0.0, None)`).
        if deadline is not None:
            entry._timer = self._loop.call_later(max(0.0, deadline), self._fail_timeout, cid)
        self.enqueue_control(encode_ping(cid, have_hash))
        return await fut

    def cancel(self, cid: int) -> None:
        """Send CANCEL for an in-flight outbound cid + clean up locally (SPEC
        §3/§4.4 consumer-abandon path). Also FAIL the future/queue so any
        coroutine still awaiting this request unblocks (never hangs)."""
        self.enqueue_control(encode_cancel(cid))
        entry = self._pending.pop(cid, None)
        if entry is not None:
            self._cancel_timer(entry)
            self._cancel_reassembly_timers(entry)
            self._release_charge_pending(entry)
            self._fail_entry(entry, LinkDown("request cancelled by consumer"))

    def _enqueue_call(
        self, cid: int, call_frame: Frame, args: Any, *, fanout: bool
    ) -> None:
        frames: List[bytes] = [
            encode_call(
                cid,
                call_frame.selector,
                call_frame.mode,
                call_frame.caller,
                call_frame.handler_timeout,
            )
        ]
        for frag, last in chunk_value(serialize_value(args)):
            frames.append(encode_chunk(cid, frag, last))
        self.enqueue_value(_OutValue(frames, fanout=fanout))


def _error_frame_holder(frame: Frame) -> Exception:
    """Wrap a raw stream ERROR frame so a StreamQueue consumer RAISES it (the
    stream path can't return a value; Dispatch maps the kind at the sender)."""
    exc = LinkDown(f"stream ERROR kind={frame.error_kind!r}")
    exc.error_frame = frame  # type: ignore[attr-defined]
    return exc


class Transport:
    """Per-peer link registry + framing/SPKI/dial-election/supervisor (SPEC
    §4.4). Owns the ``_links[hostname]`` registry + per-peer flap-probation
    state; the survivor/flap read-decide-swap is ONE await-free CAS (§7). Holds
    the NODE-WIDE reassembly counter (§4.4/§7)."""

    def __init__(
        self,
        membership: Any,
        directory: Any,
        dispatch: Any,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int = 2510,
        manager: Any = None,
        per_cid_cap: int = PER_CID_REASSEMBLY_CAP,
        per_peer_cap: int = PER_PEER_REASSEMBLY_CAP,
        per_peer_min: int = PER_PEER_REASSEMBLY_MIN,
        node_cap: int = NODE_WIDE_REASSEMBLY_CAP,
        per_peer_cid_cap: int = PER_PEER_CID_CAP,
        out_q_max: int = 256,
        stream_queue_maxsize: int = STREAM_QUEUE_MAXSIZE,
        connect_timeout: float = CONNECT_TIMEOUT,
        backoff_cap: float = BACKOFF_CAP,
        liveness_timeout: float = 30.0,
        idle_read_deadline: float = IDLE_READ_DEADLINE,
        drain_timeout: float = DRAIN_TIMEOUT,
        stream_idle: float = STREAM_IDLE_DEADLINE,
        reassembly_abs_deadline: float = REASSEMBLY_ABS_DEADLINE,
    ):
        self.membership = membership
        self.directory = directory
        self.dispatch = dispatch
        self.manager = manager
        self.self_hostname = getattr(membership, "self_hostname", None)

        self._listen_host = listen_host
        self._listen_port = listen_port

        self.per_cid_cap = per_cid_cap
        self.per_peer_cap = per_peer_cap
        self.per_peer_min = per_peer_min
        self.node_cap = node_cap
        self.per_peer_cid_cap = per_peer_cid_cap
        self.out_q_max = out_q_max
        self.stream_queue_maxsize = stream_queue_maxsize
        self._connect_timeout = connect_timeout
        self._idle_read_deadline = idle_read_deadline
        self._drain_timeout = drain_timeout
        self._stream_idle = stream_idle
        self._reassembly_abs_deadline = reassembly_abs_deadline
        # Backoff cap STRICTLY < liveness_timeout (SPEC §4.4).
        self._backoff_cap = min(backoff_cap, liveness_timeout * 0.9)

        # The loop is captured lazily on-loop (get_running_loop() at each spawn
        # site), NOT at construction — NetworkManager builds Transport in a sync
        # __init__ that may run off-loop (attach_transport late-bind), exactly the
        # reason Membership refuses to capture here too (F#4e; membership.py:124).

        # §7 concurrency data: link registry + probation + generations.
        self._links: Dict[str, PeerLink] = {}
        self._probation: Dict[str, PeerLink] = {}
        self._generations: Dict[str, int] = {}
        self._supervisors: Dict[str, asyncio.Task] = {}
        self._last_dial_refused: Dict[str, bool] = {}

        # F3 (panel concurrency): strong-refs for the fire-and-forget tasks spawned
        # by the link-registry CAS / stop_link (probation promote + link closes). A
        # bare create_task is only weakly held by the loop, so a GC mid-`await
        # sleep(idle_read_deadline)` in _probation_promote would permanently wedge
        # probation for that peer. Mirrors membership/PeerLink _spawn discipline.
        self._bg_tasks: set = set()

        # NODE-WIDE reassembly counter (shared across links; await-free, pop-once
        # decrement) — §4.4/§7.
        self._node_reasm = 0

        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False

    def _spawn(self, coro) -> "asyncio.Task":
        """Create + STASH a background task so the loop's weak-ref GC cannot drop a
        fire-and-forget task mid-flight (F3)."""
        task = asyncio.get_running_loop().create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    # --- node-wide reassembly budget (§4.4/§7) ----------------------------
    def can_charge(self, link: PeerLink, delta: int) -> bool:
        """Per-peer CAP + node-wide with the guaranteed per-peer MINIMUM: a peer
        whose usage stays within its MINIMUM is ALWAYS admitted (so a newcomer
        can always start SOME reassembly, TG-09); above the minimum it must fit
        the node-wide cap (SPEC §4.4/§F#19)."""
        new_peer = link._reasm_bytes + delta
        if new_peer > self.per_peer_cap:
            return False
        if new_peer > self.per_peer_min and self._node_reasm + delta > self.node_cap:
            return False
        return True

    def commit_charge(self, link: PeerLink, delta: int) -> None:
        link._reasm_bytes += delta
        self._node_reasm += delta

    def release_charge(self, link: PeerLink, amt: int) -> None:
        """Pop-once decrement (SPEC §4.4/§7): called by the pop-winner exactly
        once per exit path with the entry's recorded bytes."""
        link._reasm_bytes -= amt
        self._node_reasm -= amt

    def observe_reject(self, reason: str, hostname: Optional[str] = None) -> None:
        """Emit ``_core/net/reject`` with ``reason`` (SPEC §8.3). Routes through the
        manager's `_observe` seam (same as the dispatch-side reject reasons); the
        manager exposes `_observe`, NOT `observe_reject`."""
        if self.manager is not None:
            observe = getattr(self.manager, "_observe", None)
            if observe is not None:
                observe("_core/net/reject", {"reason": reason, "hostname": hostname})

    # --- lifecycle --------------------------------------------------------
    async def start(self) -> None:
        """Bind the listener + start the acceptor (SPEC §3)."""
        self._running = True
        self._server = await asyncio.start_server(
            self._on_accept,
            self._listen_host,
            self._listen_port,
            ssl=self.membership.server_ssl_context(),
        )

    async def stop(self) -> None:
        """Stop the acceptor FIRST, then all supervisors + close all links + drain
        background tasks (SPEC §4.4)."""
        self._running = False
        # Stop accepting FIRST (cycle-2 teardown-window finding): close the listener now
        # (sync, no stall) and the _on_accept head also gates on _running — together no
        # inbound can _install_link/_spawn a promote task past this point and escape the
        # _bg_tasks drain below. wait_closed() is deferred to the very end (after links
        # close) to avoid the >=3.12 "wait for in-flight handlers" stall.
        if self._server is not None:
            self._server.close()
        for task in list(self._supervisors.values()):
            task.cancel()
        for hostname, link in list(self._links.items()):
            await link.close("transport stop")
        for hostname, link in list(self._probation.items()):
            await link.close("transport stop")
        # F-A2 (white-box review): drain the _spawn'd background tasks (probation-promote,
        # link closes) the same way Membership.stop drains its own (F1) — else a
        # _probation_promote sleeping on idle_read_deadline survives stop() and pins the
        # old transport/PeerLink refs (relevant on hot-reload NM re-init).
        bg = list(self._bg_tasks)
        for t in bg:
            t.cancel()
        if bg:
            await asyncio.gather(*bg, return_exceptions=True)
        if self._server is not None:
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # --- SPKI authentication (§4.1) ---------------------------------------
    def _authenticate(self, ssl_object: Any) -> str:
        """The AUTHORITATIVE post-handshake trust gate (SPEC §4.1): extract the
        peer SPKI, require it in the LIVE pin set, map to the expected hostname.
        FAIL CLOSED on absent/unextractable/unpinned SPKI."""
        if ssl_object is None:
            raise LinkDown("no ssl object — fail closed")
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            raise LinkDown("absent peer cert — fail closed")
        fingerprint = _spki_fingerprint(der)
        hostname = self.membership.resolve_pin(fingerprint)
        if hostname is None:
            raise LinkDown("unpinned SPKI — fail closed")
        return hostname

    # --- link registry: survivor + flap-guard CAS (§4.4/§7) ---------------
    def _install_link(self, hostname: str, new_link: PeerLink) -> bool:
        """ONE await-free read-decide-swap on ``_links[hostname]`` (§7 CAS).
        Returns True if ``new_link`` was installed/probationary (its reader
        should start), False if it lost the collision and must be closed."""
        cur = self._links.get(hostname)
        if cur is None or cur.closed:
            self._links[hostname] = new_link
            return True
        # collision — deterministic survivor = the ELECTION link, with flap guard.
        if new_link.is_election and cur.is_override:
            # flap guard: election link enters PROBATION; override stays
            # authoritative for dispatch, pulses go over the probationary link.
            if self._probation.get(hostname) is not None:
                return False
            self._probation[hostname] = new_link
            self._spawn(self._probation_promote(hostname, new_link))  # F3: strong-ref
            return True
        if new_link.is_election and not cur.is_election:
            # (unreachable given the branch above; kept explicit)
            self._links[hostname] = new_link
            self._spawn(cur.close("superseded by election link"))  # F3: strong-ref
            return True
        # new is override, or a redundant election link -> a link exists: close new.
        return False

    async def _probation_promote(self, hostname: str, prob: PeerLink) -> None:
        """Promote the probationary election link iff its pulses survive one
        idle_read_deadline; else discard it + keep the override (SPEC §4.4)."""
        await asyncio.sleep(self._idle_read_deadline)
        if self._probation.get(hostname) is not prob:
            return
        self._probation.pop(hostname, None)
        if prob.closed:
            return  # its own idle/pulse failed -> discard, keep override
        old = self._links.get(hostname)
        self._links[hostname] = prob
        if old is not None and old is not prob:
            await old.close("promoted election link")

    def _on_link_closed(self, hostname: str, link: PeerLink) -> None:
        """Reader terminal-act callback (sync): drop the link from the registry
        if it is still the installed one (Directory NOT dropped, §4.4)."""
        if self._links.get(hostname) is link:
            self._links.pop(hostname, None)
        if self._probation.get(hostname) is link:
            self._probation.pop(hostname, None)

    # --- acceptor ---------------------------------------------------------
    async def _on_accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if not self._running:  # refuse inbound during/after stop(): a late accept must not
            writer.close()      # _install_link + _spawn a promote task past the stop() drain
            return
        ssl_object = writer.get_extra_info("ssl_object")
        try:
            hostname = self._authenticate(ssl_object)
        except Exception as exc:  # noqa: BLE001 - fail closed
            _logger.info("inbound SPKI check failed: %r", exc)
            writer.close()
            return
        # registration roster-gate (close the ghost link on revoke) — §4.4.
        if not self.membership.in_roster(hostname):
            writer.close()
            return
        link = PeerLink(
            self, hostname, is_dialer=False, reader=reader, writer=writer
        )
        if not self._install_link(hostname, link):
            writer.close()
            return
        link.start()
        self.membership.on_link_up(hostname)

    # --- link start/stop (Membership -> Transport, §3/§4.6) ---------------
    def start_link(self, spec: PeerSpec) -> None:
        """Start (or no-op if running) a generation-tagged supervisor for a peer
        (SPEC §3/§4.6)."""
        hostname = spec.hostname
        gen = self._generations.get(hostname, 0) + 1
        self._generations[hostname] = gen
        old = self._supervisors.get(hostname)
        if old is not None and not old.done():
            old.cancel()
        self._supervisors[hostname] = asyncio.get_running_loop().create_task(
            self._supervise(spec, gen)
        )

    def stop_link(self, hostname: str) -> None:
        """Stop the supervisor + tear the link (idempotent, hostname-keyed,
        generation-tagged) (SPEC §3/§4.6)."""
        self._generations[hostname] = self._generations.get(hostname, 0) + 1
        sup = self._supervisors.pop(hostname, None)
        if sup is not None and not sup.done():
            sup.cancel()
        link = self._links.pop(hostname, None)
        if link is not None:
            self._spawn(link.close("stop_link"))  # F3: strong-ref
        prob = self._probation.pop(hostname, None)
        if prob is not None:
            self._spawn(prob.close("stop_link"))  # F3: strong-ref
        # A7: prune the stale dial-refused reason so a revoke+re-add (or any link
        # teardown) does not leave a frozen `connection_refused` in the snapshot's
        # unreachable_reason. remove_peer routes through stop_link, so this covers
        # the revoke path too.
        self._last_dial_refused.pop(hostname, None)

    async def _supervise(self, spec: PeerSpec, generation: int) -> None:
        """Dial + reconnect with capped backoff (SPEC §4.4). Only the election
        dialer (lex-lower) dials; a per-edge ``dial`` override dials ONLY while
        no link exists (NAT edge fallback). Event-driven: when a link already
        exists (dialed OR accepted) the supervisor AWAITS its ``wait_closed``
        instead of polling; a pure-acceptor side (lex-higher, no override) has
        nothing to dial and returns (the acceptor installs its link)."""
        hostname = spec.hostname
        is_election_dialer = self.self_hostname < hostname
        has_override = spec.dial is not None
        if not is_election_dialer and not has_override:
            # pure acceptor side — never dials; the acceptor + _on_link_closed
            # own the link lifecycle. Nothing to do (no busy poll).
            return
        backoff = BACKOFF_INITIAL
        try:
            while self._running and self._generations.get(hostname) == generation:
                if not self.membership.in_roster(hostname):
                    return
                cur = self._links.get(hostname)
                if cur is not None and not cur.closed:
                    # a link exists (dialed or accepted) -> wait for it to close,
                    # then re-evaluate (event-driven, no poll).
                    await cur.wait_closed()
                    backoff = BACKOFF_INITIAL
                    continue
                # no link -> dial (election dialer always; override only when no
                # link exists, which is the case here).
                try:
                    link = await self._dial(spec)
                except LinkRefused:
                    self._last_dial_refused[hostname] = True
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self._backoff_cap)
                    continue
                except (LinkDown, Timeout, asyncio.TimeoutError, OSError) as exc:
                    self._last_dial_refused[hostname] = False
                    _logger.debug("dial %s failed: %r", hostname, exc)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self._backoff_cap)
                    continue
                self._last_dial_refused[hostname] = False
                if not self._install_link(hostname, link):
                    # lost the collision -> the winning link exists now; the loop
                    # re-checks and awaits ITS wait_closed (no poll).
                    await link.close("lost dial collision")
                    continue
                link.start()
                self.membership.on_link_up(hostname)
                backoff = BACKOFF_INITIAL
                await link.wait_closed()
        except asyncio.CancelledError:
            raise

    async def _dial(self, spec: PeerSpec) -> PeerLink:
        ctx = self.membership.client_ssl_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    spec.ip, spec.port, ssl=ctx, server_hostname=spec.hostname
                ),
                self._connect_timeout,
            )
        except ConnectionRefusedError as exc:
            raise LinkRefused(str(exc)) from exc
        except (asyncio.TimeoutError, OSError) as exc:
            raise LinkDown(str(exc)) from exc
        ssl_object = writer.get_extra_info("ssl_object")
        hostname = self._authenticate(ssl_object)  # raises -> supervisor retries
        if hostname != spec.hostname:
            writer.close()
            raise LinkDown(
                f"SPKI hostname {hostname!r} != expected {spec.hostname!r}"
            )
        if not self.membership.in_roster(hostname):
            writer.close()
            raise LinkDown("roster gate (dial)")
        return PeerLink(
            self, hostname, is_dialer=True, reader=reader, writer=writer
        )

    # --- link resolution --------------------------------------------------
    def _get_link(self, hostname: str, *, for_ping: bool = False) -> PeerLink:
        if for_ping:
            prob = self._probation.get(hostname)
            if prob is not None and not prob.closed:
                return prob
        link = self._links.get(hostname)
        if link is None or link.closed:
            if self._last_dial_refused.get(hostname):
                raise LinkRefused(f"no link to {hostname} (refused)")
            raise LinkDown(f"no link to {hostname}")
        return link

    # --- Dispatch -> Transport interface (§3) -----------------------------
    async def ping(self, hostname: str, have_hash: str, deadline: float) -> Pong:
        """Ping a peer; return on the PONG HEADER (SPEC §3). Pulses over the
        PROBATIONARY link during a flap (§4.4)."""
        return await self._get_link(hostname, for_ping=True).ping(have_hash, deadline)

    async def request(
        self, hostname: str, call_frame: Frame, args: Any, deadline: float
    ) -> Any:
        """UNARY/FIRST request; returns a value or a raw ERROR frame; raises
        LinkDown/Timeout (SPEC §3)."""
        return await self._get_link(hostname).request(call_frame, args, deadline)

    async def open_stream(
        self, hostname: str, call_frame: Frame, args: Any
    ) -> StreamQueue:
        """STREAM open; returns a StreamQueue (SPEC §3)."""
        return await self._get_link(hostname).open_stream(call_frame, args)

    def send(self, hostname: str, call_frame: Frame, args: Any) -> None:
        """FANOUT send; no reply. Best-effort: a down peer (no link) is dropped
        silently (fire-and-forget, SPEC §4.5)."""
        try:
            link = self._get_link(hostname)
        except (LinkDown, LinkRefused):
            return
        link.send(call_frame, args)

    def cancel(self, hostname: str, cid: int) -> None:
        """Cancel an in-flight outbound cid (SPEC §3)."""
        try:
            link = self._get_link(hostname)
        except (LinkDown, LinkRefused):
            return
        link.cancel(cid)
