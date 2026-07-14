"""netcore.dispatch — §4.5 the (c) seam: *_remote senders + inbound re-match.

Outbound senders (called by core per candidate) with the UNIFORM signature
PINNED across all 3 branches (SPEC §4.5):
  unary/first : *_remote(hostname, selector, payload, caller, handler_timeout,
                         *, deadline) -> value
  streams     : request_event_stream_remote / execute_remote_stream
                         (hostname, selector, payload, caller,
                         handler_timeout=None, *, deadline) -> AsyncIterator
                (async-generator functions -> calling returns an async ITERATOR,
                 NOT a coroutine)
  fanout      : publish_event_remote(hostname, topic, payload, caller) -> None

They take ``hostname`` (the NM resolved the address; ``Node`` is gone). Each
maps ``ERROR.kind`` -> the exact legacy exception TYPE (SPEC §4.5):
  NO_MATCH        -> NoLocalSubException          (fall through)
  NETWORK / peer-down / timeout / NO_ENDPOINT -> NetworkRequestException (fall through)
  RATE_LIMIT      -> RateLimitException           (propagate)
  CAPABILITY      -> CapabilityException          (propagate)
  HANDLER_RAISED  -> re-raise the deserialized exc, WRAPPING an isinstance
                     Network/NoLocalSub in a NON-Network RequestException
                     (else events.py's fall-through silently re-runs it on the
                     next peer = a side-effect).
  ProtocolError   -> NetworkRequestException      (fall through)
``Transport.request`` RETURNS these as raw ERROR frames; RAISES only on
link-level LinkDown/Timeout.

Inbound = the BLESSED 2-call seam (kept from phase 2b):
  * ``authorize_inbound(identity, frame)`` SYNC header-authz BEFORE arg buffering
    (SPEC §8.1/§8.2): PeerIdentity from the AUTHENTICATED record; ``nodes_in``
    FIRST (attempts, before anti-spoof) -> anti-spoof
    (``caller.author_host == authenticated hostname`` else drop +
    ``_core/peer/hostname_mismatch``) -> live-ROSTER re-check -> callee
    ``framework_in``; reject -> ``InboundReject(ErrorKind)``.
  * ``dispatch_inbound(identity, frame, args)`` (SYNC, returns a coroutine for
    UNARY/FIRST/FANOUT or an async-generator for STREAM): re-match against the
    LIVE registry with the authoritative per-sub/endpoint filters (the registry
    seam owns them + charges the IN-set on the local re-entry), run the handler
    bounded by ``handler_timeout``, emit the typed reply. ``system_caller`` /
    ``author="system"`` is granted SOLELY from the authenticated ``identity``,
    NEVER the wire (§F#7) — passed to the registry as ``identity``.

Injected core seams (core-owned, wired phase 6; faked in the self-test):
  * ``registry`` (the local notifier/registry re-entry, "the untouched core
    notifier"):
      ``async execute(selector, payload, identity, caller) -> value``
        raises NoEndpointError (no match / uuid-mismatch / remote:false / not
        accessible, §F#14), RateLimitException, CapabilityException, or a handler
        exception (-> HANDLER_RAISED).
      ``async request_event(topic, payload, identity, caller) -> value``
        raises NoLocalSubException on no match.
      ``request_event_stream(topic, payload, identity, caller) -> Iterator``
      ``execute_stream(selector, payload, identity, caller) -> Iterator``
        (sync -> raises the re-match error at OPEN; returns a sync-gen OR
         async-iter of items; a mid-stream handler raise -> HANDLER_RAISED.)
      ``async publish_event(topic, payload, identity, caller) -> None``
        (fan-out to matching local subs; a reject stays SILENT.)
  * ``rate`` (the core rate-limiter): ``charge_nodes_in(hostname) -> bool``,
    ``charge_framework_in() -> bool`` (Dispatch charges these two in
    ``authorize_inbound``; the IN-set is charged by the registry re-entry).
  * ``membership`` (DONE): ``identity_for(hostname)`` / ``in_roster(hostname)``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import threading
from typing import Any, AsyncIterator, Optional

from ..exceptions import (
    CapabilityException,
    NetworkRequestException,
    NoLocalSubException,
    RateLimitException,
    RequestException,
)
from .transport import InboundReject
from .types import (
    CallerCtx,
    ErrorKind,
    ExecuteSelector,
    LinkDown,
    LinkRefused,
    Mode,
    PeerIdentity,
    ProtocolError,
    Selector,
    Timeout,
    TopicSelector,
)
from .wire import Frame, Kind, deserialize_value

_logger = logging.getLogger("plexus.netcore.dispatch")


class NoEndpointError(Exception):
    """The callee does not host the requested endpoint / the EXACT ``plugin_uuid``
    (SPEC §4.5 D2 / §F#14). The core registry seam raises this; Dispatch maps it
    to ``ErrorKind.NO_ENDPOINT`` -> ``NetworkRequestException`` (fall through)."""


class Dispatch:
    """Cross-node CALL senders + the inbound identity/rate seam + callee re-match
    (SPEC §4.5). Holds no roster/directory state — it drives Transport
    (send/request/open_stream) and the injected core registry + rate + Membership
    identity seams."""

    def __init__(
        self,
        *,
        transport: Any = None,
        membership: Any = None,
        registry: Any = None,
        rate: Any = None,
        observe: Any = None,
    ):
        self._transport = transport
        self._membership = membership
        self._registry = registry
        self._rate = rate
        self._observe_cb = observe

    def attach_transport(self, transport: Any) -> None:
        """Late-bind Transport (Transport's ctor needs Dispatch first)."""
        self._transport = transport

    # ---------------------------------------------------------------------
    # Outbound senders (SPEC §4.5, PINNED signatures)
    # ---------------------------------------------------------------------
    async def execute_remote(
        self,
        hostname: str,
        selector: Selector,
        payload: Any,
        caller: CallerCtx,
        handler_timeout: Optional[float],
        *,
        deadline: float,
    ) -> Any:
        """Cross-node ``execute`` (UNARY) (SPEC §4.5)."""
        return await self._unary_send(
            hostname, selector, payload, caller, handler_timeout, deadline, Mode.UNARY
        )

    async def request_event_remote(
        self,
        hostname: str,
        selector: Selector,
        payload: Any,
        caller: CallerCtx,
        handler_timeout: Optional[float],
        *,
        deadline: float,
    ) -> Any:
        """Cross-node ``request_event`` (FIRST) (SPEC §4.5)."""
        return await self._unary_send(
            hostname, selector, payload, caller, handler_timeout, deadline, Mode.FIRST
        )

    async def _unary_send(
        self, hostname, selector, payload, caller, handler_timeout, deadline, mode
    ) -> Any:
        call_frame = self._call_frame(selector, mode, caller, handler_timeout)
        try:
            result = await self._transport.request(
                hostname, call_frame, payload, deadline
            )
        except (LinkDown, LinkRefused, Timeout, ProtocolError) as exc:
            # link-level failure / peer-down / timeout -> fall through.
            raise NetworkRequestException(str(exc)) from exc
        # Transport RETURNS a raw ERROR frame for a handler/rate/capability
        # rejection; map it to the exact exception TYPE.
        if isinstance(result, Frame) and result.kind == Kind.ERROR:
            raise self._map_error(result)
        return result

    async def request_event_stream_remote(
        self,
        hostname: str,
        selector: Selector,
        payload: Any,
        caller: CallerCtx,
        handler_timeout: Optional[float] = None,
        *,
        deadline: float,
    ) -> AsyncIterator[Any]:
        """Cross-node ``request_event_stream`` (STREAM, topic selector) (SPEC
        §4.5). An async-generator function -> returns an async ITERATOR."""
        inner = self._stream_send(hostname, selector, payload, caller)
        try:
            async for item in inner:
                yield item
        finally:
            # propagate an early consumer aclose to _stream_send's finally so the
            # remote-cancel fires PROMPTLY (not at GC-finalizer time) — TP-19.
            await inner.aclose()

    async def execute_remote_stream(
        self,
        hostname: str,
        selector: Selector,
        payload: Any,
        caller: CallerCtx,
        handler_timeout: Optional[float] = None,
        *,
        deadline: float,
    ) -> AsyncIterator[Any]:
        """Cross-node ``execute`` STREAM (plugin/endpoint/uuid selector) (SPEC
        §4.5); the callee disambiguates by selector SHAPE."""
        inner = self._stream_send(hostname, selector, payload, caller)
        try:
            async for item in inner:
                yield item
        finally:
            await inner.aclose()  # prompt remote-cancel on early abandon (TP-19)

    async def _stream_send(self, hostname, selector, payload, caller):
        # STREAM: handler_timeout is None/unbounded (a per-chunk idle deadline in
        # Transport bounds a stalled stream); ``deadline`` does not apply to a
        # stream open.
        call_frame = self._call_frame(selector, Mode.STREAM, caller, None)
        try:
            stream = await self._transport.open_stream(hostname, call_frame, payload)
        except (LinkDown, LinkRefused, Timeout, ProtocolError) as exc:
            raise NetworkRequestException(str(exc)) from exc
        settled = False  # True once the stream is terminal (Transport popped pending)
        try:
            async for item in stream:
                yield item
            settled = True  # natural END
        except asyncio.CancelledError:
            # A stream deadline/idle cancel reaching the consumer boundary arrives as a
            # raw asyncio.CancelledError (a BaseException a plain `except Exception` chain
            # misses) — map it to NetworkRequestException (TG-11). Ordered BEFORE the
            # finally, which still CANCELs the remote producer (settled stays False). A
            # clean consumer abandon is GeneratorExit (NOT CancelledError) -> skips here.
            raise NetworkRequestException(f"remote stream {hostname} cancelled/timed out")
        except Exception as exc:  # noqa: BLE001 - map the terminal stream error
            settled = True  # terminal error -> Transport already popped pending
            mapped = self._map_stream_exc(exc)
            if mapped is exc:
                raise
            raise mapped from exc
        finally:
            # Early CONSUMER abandonment (break / aclose -> GeneratorExit, or a
            # task CancelledError) leaves ``settled=False`` -> CANCEL the remote
            # producer + drop the local pending so nothing lingers (TP-19).
            if not settled:
                try:
                    self._transport.cancel(hostname, stream.cid)
                except Exception:  # noqa: BLE001
                    pass

    async def publish_event_remote(
        self, hostname: str, topic: str, payload: Any, caller: CallerCtx
    ) -> None:
        """Cross-node ``publish_event`` (FANOUT) (SPEC §4.5): one FANOUT frame, NO
        deadline/reply; an IN-reject at the callee stays SILENT (no reply
        channel)."""
        call_frame = self._call_frame(TopicSelector(topic), Mode.FANOUT, caller, None)
        # F2 (panel robustness): FANOUT is fire-and-forget with no reply channel, so a
        # down peer OR an unpicklable payload (send raising on serialize/enqueue) must be
        # SWALLOWED, never surfaced — matches A (a/dispatch.py:177-180) / C (c:211-214).
        try:
            self._transport.send(hostname, call_frame, payload)
        except Exception:  # noqa: BLE001 - fire-and-forget: no reply channel
            _logger.debug("fanout send to %s swallowed", hostname, exc_info=True)

    # --- error mapping (SPEC §4.5) ----------------------------------------
    def _map_error(self, frame: Frame) -> Exception:
        """Map a raw ``ERROR`` Frame's ``kind`` -> the exact legacy exception TYPE
        (SPEC §4.5). Returns the exception to raise (the SENDER raises it; core's
        except arms decide fall-through vs propagate by TYPE)."""
        kind = frame.error_kind
        # decode the carried exception (raw pickled bytes -> safe_loads allowlist).
        exc = None
        if frame.exc:
            try:
                exc = deserialize_value(frame.exc)
            except Exception:  # noqa: BLE001 - undecodable -> generic message
                exc = None
        if kind == ErrorKind.NO_MATCH:
            return NoLocalSubException("no remote subscriber matched")
        if kind == ErrorKind.RATE_LIMIT:
            # message MUST contain "rate limit" — the rate cells match on it (and
            # so does the caller-facing surface); prefer the original limiter text.
            return RateLimitException(str(exc) if exc else "remote rate limit")
        if kind == ErrorKind.CAPABILITY:
            return CapabilityException(str(exc) if exc else "remote capability denied")
        if kind == ErrorKind.HANDLER_RAISED:
            # nested-Network wrap: a re-raised Network/NoLocalSub would be SWALLOWED
            # by events.py's fall-through arm (silent side-effecting re-run on the
            # next peer) -> wrap in a NON-Network RequestException.
            if isinstance(exc, (NetworkRequestException, NoLocalSubException)):
                return RequestException(
                    f"remote handler raised {type(exc).__name__}: {exc}"
                )
            # Preserve a RequestException SUBTYPE (RateLimit/Capability/etc.) so the
            # caller can `except` it by type; WRAP any other exception so a raw
            # handler exception (e.g. ValueError) never propagates to the caller as
            # itself (request_event's contract is `Raises: RequestException`).
            if isinstance(exc, RequestException):
                return exc
            if isinstance(exc, BaseException):
                return RequestException(
                    f"remote handler raised {type(exc).__name__}: {exc}"
                )
            return RequestException("remote handler raised")
        # NETWORK / NO_ENDPOINT / anything else -> NETWORK (fall through)
        return NetworkRequestException(
            f"remote error {getattr(kind, 'name', kind)}: {exc if exc else ''}")

    def _map_stream_exc(self, exc: BaseException) -> BaseException:
        """Map a terminal STREAM error to the exception TYPE. A mid/terminal
        ERROR frame is carried on ``exc.error_frame`` (Transport); a link-level
        failure maps to NetworkRequestException."""
        frame = getattr(exc, "error_frame", None)
        if isinstance(frame, Frame) and frame.error_kind is not None:
            return self._map_error(frame)
        if isinstance(exc, (LinkDown, LinkRefused, Timeout, ProtocolError)):
            return NetworkRequestException(str(exc))
        return exc

    def _call_frame(
        self, selector: Selector, mode: Mode, caller: CallerCtx,
        handler_timeout: Optional[float],
    ) -> Frame:
        return Frame(
            kind=Kind.CALL, cid=0, selector=selector, mode=mode,
            caller=caller, handler_timeout=handler_timeout,
        )

    # ---------------------------------------------------------------------
    # Inbound — the 2-call seam (SPEC §4.5/§8.1/§8.2)
    # ---------------------------------------------------------------------
    def authorize_inbound(self, identity: PeerIdentity, frame: Frame) -> None:
        """SYNC header-authz BEFORE arg buffering (SPEC §8.1/§8.2). Order:
        ``nodes_in`` FIRST (attempts) -> anti-spoof -> live-roster re-check ->
        callee ``framework_in``. Raises ``InboundReject`` on any rejection; the
        IN-set is charged later by the registry re-entry (never here, so it is
        NOT charged when re-match fails)."""
        hostname = identity.hostname
        caller = frame.caller
        # 1. nodes_in FIRST (before anti-spoof; = attempts, on the AUTHENTICATED
        #    hostname). Charged once; stands even if a later step rejects.
        if not self._rate.charge_nodes_in(hostname):
            self._reject("nodes_in", hostname)
            raise InboundReject(ErrorKind.RATE_LIMIT)
        # 2. anti-spoof: the wire author_host MUST equal the authenticated
        #    hostname, else DROP + _core/peer/hostname_mismatch (§8.1).
        if caller is None or caller.author_host != hostname:
            self._observe(
                "_core/peer/hostname_mismatch",
                {"authenticated": hostname,
                 "claimed": caller.author_host if caller else None},
            )
            self._reject("hostname_mismatch", hostname)
            raise InboundReject(ErrorKind.NETWORK)
        # 3. live-ROSTER re-check (revoke-window close).
        if not self._membership.in_roster(hostname):
            self._reject("not_in_roster", hostname)
            raise InboundReject(ErrorKind.NETWORK)
        # 4. callee framework_in (on the callee's bucket, §8.2) — ONLY for events /
        #    request_event_stream (TopicSelector). An EXECUTE / execute_stream
        #    (ExecuteSelector) charges framework_in in its own `core.execute[_stream]`
        #    re-entry, so charging it here too would DOUBLE-charge (learning 12).
        if isinstance(frame.selector, TopicSelector):
            if not self._rate.charge_framework_in():
                self._reject("framework_in", hostname)
                raise InboundReject(ErrorKind.RATE_LIMIT)
        self._observe("_core/net/inbound", {"hostname": hostname})

    def dispatch_inbound(self, identity: PeerIdentity, frame: Frame, args: Any):
        """Return the per-mode driver (SYNC): a COROUTINE for UNARY/FIRST/FANOUT
        or an ASYNC GENERATOR for STREAM (Transport awaits / async-fors
        accordingly). The registry re-entry applies the authoritative filters +
        charges the IN-set; ``identity`` (authenticated) carries the SOLE
        ``system_caller`` grant (§F#7)."""
        # G6 (panel security/correctness): in-module anti-escalation backstop. The
        # right to act as author="system" is granted SOLELY from THIS node's
        # authenticated record (identity.system_caller), NEVER the wire (§F#7). Downgrade
        # a spoofed system claim HERE, before the registry re-entry, so no downstream seam
        # can ever observe a wire-asserted system author it didn't grant.
        eff = self._effective_caller(frame.caller, identity)
        if eff is not frame.caller:
            frame = dataclasses.replace(frame, caller=eff)
        mode = frame.mode
        if mode == Mode.STREAM:
            return self._run_stream(identity, frame, args)
        if mode == Mode.FANOUT:
            return self._run_fanout(identity, frame, args)
        return self._run_unary(identity, frame, args)

    def _effective_caller(
        self, caller: Optional[CallerCtx], identity: PeerIdentity
    ) -> Optional[CallerCtx]:
        """Return ``caller`` with a spoofed ``author="system"`` downgraded when THIS
        node's authenticated record does not grant ``system_caller`` (G6, mirrors C's
        c/dispatch.py:330-334). Returns the SAME object when no downgrade is needed so
        the caller can skip the frame copy. ``author_host`` is already anti-spoofed to
        the authenticated hostname by ``authorize_inbound``, so it is left untouched."""
        if caller is None:
            return caller
        if caller.author == "system" and not getattr(identity, "system_caller", False):
            # ignore the client-asserted system claim (no escalation).
            return CallerCtx(
                author=caller.author_id or identity.hostname,
                author_id=caller.author_id,
                author_host=caller.author_host,
                request_uuid=caller.request_uuid,
            )
        return caller

    async def _run_unary(self, identity, frame, args) -> Any:
        # bound the handler by handler_timeout (the callee anchors it on its own
        # monotonic clock at receipt); on expiry cancel the handler + ERROR{NETWORK}.
        ht = frame.handler_timeout
        coro = self._invoke_unary(identity, frame, args)
        if ht is None:
            return await coro  # unbounded (should not happen for UNARY/FIRST)
        if ht <= 0:
            # SPEC §4.4: timeout=0 = immediate -> expire WITHOUT running the
            # handler (never leave a 0 unbounded).
            coro.close()
            raise InboundReject(ErrorKind.NETWORK)
        try:
            return await asyncio.wait_for(coro, ht)
        except asyncio.TimeoutError:
            raise InboundReject(ErrorKind.NETWORK)  # handler_timeout expiry (§4.4)

    async def _invoke_unary(self, identity, frame, args) -> Any:
        selector = frame.selector
        try:
            if isinstance(selector, ExecuteSelector):
                return await self._registry.execute(
                    selector, args, identity, frame.caller
                )
            # TopicSelector -> request_event (FIRST)
            return await self._registry.request_event(
                selector.topic, args, identity, frame.caller
            )
        except NoEndpointError as e:
            raise InboundReject(ErrorKind.NO_ENDPOINT, e)
        except NoLocalSubException as e:
            raise InboundReject(ErrorKind.NO_MATCH, e)
        except RateLimitException as e:
            raise InboundReject(ErrorKind.RATE_LIMIT, e)
        except CapabilityException as e:
            raise InboundReject(ErrorKind.CAPABILITY, e)
        # any other exception is a HANDLER raise -> propagates -> Transport
        # encodes ERROR{HANDLER_RAISED, exc}.

    async def _run_fanout(self, identity, frame, args) -> None:
        selector = frame.selector
        topic = selector.topic if isinstance(selector, TopicSelector) else None
        try:
            await self._registry.publish_event(topic, args, identity, frame.caller)
        except Exception as exc:  # noqa: BLE001
            # a remote publish IN-reject / subscriber error stays SILENT (no reply
            # channel; fire-and-forget) — log, do not reply (§4.5/§8.2).
            _logger.debug("fanout publish swallowed: %r", exc)
        return None

    _REMATCH_ERRORS = (
        NoEndpointError, NoLocalSubException, RateLimitException, CapabilityException,
    )

    def _rematch_reject(self, e) -> "InboundReject":
        if isinstance(e, NoEndpointError):
            return InboundReject(ErrorKind.NO_ENDPOINT, e)
        if isinstance(e, NoLocalSubException):
            return InboundReject(ErrorKind.NO_MATCH, e)
        if isinstance(e, RateLimitException):
            return InboundReject(ErrorKind.RATE_LIMIT, e)
        if isinstance(e, CapabilityException):
            return InboundReject(ErrorKind.CAPABILITY, e)
        return InboundReject(ErrorKind.NETWORK, e)

    async def _run_stream(self, identity, frame, args):
        selector = frame.selector
        # OPEN (re-match). The registry stream methods are async-gen functions, so a
        # re-match failure (no sub / uuid-miss / rate / capability) surfaces either at
        # the sync call OR on the FIRST __anext__ (before any yield). Both map to a
        # mapped ERROR BEFORE any CHUNK (Transport sends it, the caller falls through);
        # only a raise AFTER the first item is a mid-stream HANDLER_RAISED (TG-10).
        try:
            if isinstance(selector, ExecuteSelector):
                handler_iter = self._registry.execute_stream(
                    selector, args, identity, frame.caller
                )
            else:
                handler_iter = self._registry.request_event_stream(
                    selector.topic, args, identity, frame.caller
                )
        except self._REMATCH_ERRORS as e:
            raise self._rematch_reject(e)
        inner = self._normalize_stream(handler_iter)
        started = False
        try:
            async for item in inner:
                started = True
                yield item
        except self._REMATCH_ERRORS as e:
            if started:
                raise  # mid-stream -> HANDLER_RAISED
            raise self._rematch_reject(e)  # before first chunk -> mapped ERROR
        finally:
            # On cancel (link-down / CANCEL / consumer abandon), aclose the inner
            # PROMPTLY so a sync generator's close()/finally: runs at cancel time, not
            # at async-gen FINALIZER time (TG-15). Race-safe via the B-081 lock.
            aclose = getattr(inner, "aclose", None)
            if aclose is not None:
                await aclose()

    def _normalize_stream(self, it: Any):
        """An async-iterator handler is iterated directly; a SYNC generator /
        iterator is driven with the B-081 close/next-serialized bridge (§F#20)."""
        if hasattr(it, "__aiter__"):
            return it
        return self._drive_sync_gen_stream(it)

    async def _drive_sync_gen_stream(self, gen: Any) -> AsyncIterator[Any]:
        """Drive a SYNC generator on a worker thread, SERIALIZING ``next()``
        against ``close()`` with a lock so a cancel (close) never races a live
        ``next()`` (SPEC §F#20 / B-081)."""
        loop = asyncio.get_running_loop()
        lock = threading.Lock()
        closed = {"v": False}
        sentinel = object()

        def _next():
            with lock:
                if closed["v"]:
                    return sentinel
                try:
                    return next(gen)
                except StopIteration:
                    return sentinel

        def _close():
            with lock:
                closed["v"] = True
                close = getattr(gen, "close", None)
                if close is not None:
                    close()

        try:
            while True:
                item = await loop.run_in_executor(None, _next)
                if item is sentinel:
                    return
                yield item
        finally:
            await loop.run_in_executor(None, _close)

    # ---------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------
    def _reject(self, reason: str, hostname: str) -> None:
        self._observe("_core/net/reject", {"reason": reason, "hostname": hostname})

    def _observe(self, event_id: str, payload: dict) -> None:
        if self._observe_cb is not None:
            try:
                self._observe_cb(event_id, payload)
            except Exception:  # noqa: BLE001
                pass
        else:
            _logger.debug("observe %s %r", event_id, payload)
