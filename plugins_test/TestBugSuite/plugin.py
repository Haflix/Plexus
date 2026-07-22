"""TestBugSuite — PR3 Stage F bughunt repro suite + PR4 Stage K B-066 regressions.

One case per open `bugtracker.md` entry plus the surviving PR4 Stage K B-066
regression cases (see B-091 for the coverage gap they represent). Verdicts are recorded by
the parent post-run (annotated on bugtracker.md). NO bug fixes here —
only repros that prove which bugs are real vs fixed-by-construction.

Categories (one method per):
  _b_legacy_removed     — API surface deleted in Stage D — assert .gone
  _b_addressed_in_pr3   — PR3 added behavior that should fix the bug
  _b_active             — still-broken — repro and let recorder mark
  _b_security           — PR4 Stage K B-066 regression guards

See PLAN.md (alongside this file in the worktree) for the per-bug spec
table and pattern recipes.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402
import time  # noqa: E402
import inspect  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import pickle  # noqa: E402
import shutil  # noqa: E402
import ssl  # noqa: E402
import struct  # noqa: E402
import tempfile  # noqa: E402
import uuid  # noqa: E402
from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402
from plexus.exceptions import RequestException  # noqa: E402

from plexus.networking import PeerSpec  # noqa: E402

# The old MSG_* wire constants were DELETED with networking.py's god-class (the SPEC
# networking rewrite replaces the [len][type][payload] protocol with netcore's framed
# CHUNK protocol). The B-066 raw-wire cells below are guarded by `c.skip("networking not
# enabled")` and only reach these when networking is on (i.e. the retired socket harness).
# Kept as module-local constants (NOT re-added to the shim) so the module imports; the
# raw-wire cells are being retired in favour of the netcore Type-X hostile-frame harness.
MSG_EXECUTE = 1
MSG_PING = 4
MSG_RESULT = 10
MSG_STREAM_CHUNK = 11
MSG_ERROR = 12
MSG_END_STREAM = 13
MSG_REQUEST_EVENT = 16
from plexus.serialization import generate_keypair, Serializable  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.6.0"


# ──────────────────────────────────────────────────────────────────────
# PR4 Stage K B-066 — module-level helpers + payload classes.
#
# Pickle resolves classes/callables by (module, qualname). For payloads
# that traverse the wire, the class definition MUST be at module scope
# so the receiver-side find_class can resolve them. Plexus loads
# this file via spec_from_file_location(name="TestBugSuite", ...) so
# __module__ is "TestBugSuite" (not the dotted file path).
# ──────────────────────────────────────────────────────────────────────


def _b066_sentinel_create(sentinel_dir: str) -> None:
    """Module-level callable used as Test 1's __reduce__ target. A
    receiver still vulnerable to pre-/post-auth pickle RCE would invoke
    this. K-1 SafeUnpickler rejects in find_class — defense.
    """
    (Path(sentinel_dir) / "PWNED").write_bytes(b"pwned")


class _B066PrePwnPickle:
    """Test 1 payload. __reduce__ returns module-level callable."""

    def __init__(self, sentinel_dir: str) -> None:
        self.sentinel_dir = sentinel_dir

    def __reduce__(self):
        return (_b066_sentinel_create, (self.sentinel_dir,))


class _B066NotRegistered:
    """Test 2 payload. Plain class NOT inheriting Serializable.
    pickle.dumps succeeds; receiver's safe_loads rejects on find_class.
    """

    def __init__(self, value: str = "test") -> None:
        self.value = value


class _B066RegisteredButPwn(Serializable):
    """Test 2b payload. Inherits Serializable (CLASS lookup passes via
    SERIALIZABLE_REGISTRY) BUT __reduce__ returns a non-allowlisted
    callable — SafeUnpickler rejects on the *callable* lookup.
    """

    def __init__(self, sentinel_dir: str) -> None:
        self.sentinel_dir = sentinel_dir

    def __reduce__(self):
        return (_b066_sentinel_create, (self.sentinel_dir,))


class _B066LogCapture:
    """Inline log handler that buffers records on a logger to a list.
    Use as:
        cap = _B066LogCapture("networking", logging.DEBUG)
        cap.attach()
        try:
            ...
        finally:
            cap.detach()
    """

    def __init__(self, logger_name: str = "networking",
                 min_level: int = logging.DEBUG) -> None:
        self.logger_name = logger_name
        self.min_level = min_level
        self.records: List[logging.LogRecord] = []
        self._handler: Optional[logging.Handler] = None
        self._saved_level: int = logging.NOTSET
        self._attached: bool = False

    def attach(self) -> None:
        h = logging.Handler()
        h.setLevel(self.min_level)
        h.emit = lambda record: self.records.append(record)
        lg = logging.getLogger(self.logger_name)
        self._saved_level = lg.level
        if lg.level == logging.NOTSET or lg.level > self.min_level:
            lg.setLevel(self.min_level)
        lg.addHandler(h)
        self._handler = h
        self._attached = True

    def detach(self) -> None:
        # Only restore logger level if
        # attach() actually ran. A `finally`-block detach() called after
        # an exception during attach setup must not silently reset the
        # logger to NOTSET (which would suppress WARNING messages later
        # security tests rely on).
        if not self._attached:
            return
        lg = logging.getLogger(self.logger_name)
        if self._handler is not None:
            lg.removeHandler(self._handler)
            self._handler = None
        lg.setLevel(self._saved_level)
        self._attached = False

    def has_message(self, substring: str, min_level: int = 0) -> bool:
        for r in self.records:
            if r.levelno < min_level:
                continue
            if substring in r.getMessage():
                return True
        return False


async def _b066_send_msg(writer: asyncio.StreamWriter, msg_type: int,
                         data: Any) -> None:
    """Wire-frame send matching networking._send_message format.
    Sender uses raw pickle.dumps — receiver runs the bytes through
    safe_loads, which is the code under test.
    """
    payload = pickle.dumps(data)
    msg_length = len(payload) + 1
    header = struct.pack(">IB", msg_length, msg_type)
    writer.write(header + payload)
    await writer.drain()


async def _b066_recv_msg(reader: asyncio.StreamReader, *,
                         timeout: float = 5.0):
    """Wire-frame receive. Returns (msg_type, data).

    Raises asyncio.IncompleteReadError if peer closed mid-frame, or
    asyncio.TimeoutError if no full frame arrives within `timeout` (one
    overall bound, not per-segment).
    """
    async def _inner():
        length_bytes = await reader.readexactly(4)
        msg_length = struct.unpack(">I", length_bytes)[0]
        msg_type = (await reader.readexactly(1))[0]
        payload_length = msg_length - 1
        if payload_length > 0:
            payload = await reader.readexactly(payload_length)
            data = pickle.loads(payload)
        else:
            data = None
        return msg_type, data

    return await asyncio.wait_for(_inner(), timeout)

# Plexus loads this file via spec_from_file_location + exec_module
# without auto-registering in sys.modules. pickle.dumps validates that
# obj.__module__ resolves via sys.modules to an importable module
# containing the class — without this registration, pickling our payload
# classes raises PicklingError ("attribute lookup _B066NotRegistered on
# TestBugSuite failed"). Register an empty proxy module here so import-
# system probes find a placeholder; the proxy is populated with the
# final `globals()` snapshot at the BOTTOM of this file (after every
# module-level symbol — including TestBugSuite — is defined). Anything
# pickle resolves needs to be added to the file BEFORE the populate
# call at file bottom; the populate-at-end pattern means new helpers
# defined anywhere above that call are picked up automatically.
import types as _b066_types
_b066_proxy_mod = _b066_types.ModuleType(__name__)
sys.modules[__name__] = _b066_proxy_mod


TARGET = "TestEventTarget"
STREAM_TARGET = "TestStreamTarget"
EXEC_TARGET = "TestExecuteTarget"
BAD_ACTOR = "TestEventBadActor"


class TestBugSuite(Plugin):
    """PR3 Stage F bug-repro suite. See PLAN.md."""

    @log_errors
    def on_load(self, *args, **kwargs):
        # B-047 mailbox: probe handler increments to confirm fan-out
        # actually fires (sanity check for the task_list growth body).
        self.b047_probe_calls = 0
        # B-021 mailboxes: which of the two competing subs answered.
        self.b021_blocked_calls = 0
        self.b021_eligible_calls = 0

    async def handle_b047_probe(self, event):
        self.b047_probe_calls += 1

    async def handle_b021_blocked(self, event):
        # The non-eligible sub (blocks the publisher). request_event must
        # never reach this; if it does, the filter chain was bypassed.
        self.b021_blocked_calls += 1
        return {"who": "blocked"}

    async def handle_b021_eligible(self, event):
        # The eligible fall-through sub. request_event must land here.
        self.b021_eligible_calls += 1
        return {"who": "eligible"}

    @async_log_errors
    async def on_enable(self):
        self._logger.info("TestBugSuite enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.info("TestBugSuite disabled")

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
        rec = CaseRecorder("TestBugSuite", SUITE_VERSION, self._plexus)
        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=False,
        )

        await self._b_legacy_removed(rec, kw)
        await self._b_addressed_in_pr3(rec, kw)
        await self._b_active(rec, kw)
        await self._b_security(rec, kw)
        await self._b_fixed_audit(rec, kw)
        return rec.to_dict()

    async def _b_fixed_audit(self, rec: CaseRecorder, kw: Dict) -> None:
        """Green regression guards for bugs FOUND + FIXED in the 2026-06-21
        core-review audit cycle (promoted from the gitignored audit dir so the
        fix is regression-protected in the committed suite)."""
        category = "fixed_audit"

        # ---- B-081 (audit BUG-028) -----------------------------------
        async def body_b_081_sync_gen_close_worker_thread(c):
            c.skip("old-NM _drive_sync_gen_stream internals retired by netcore; the "
                   "close-vs-next serialization is covered by netcore dispatch §F#20 + selftest")
            # BUG-028 / B-081: the sync-generator branch of
            # _handle_request_event_stream used to close the generator in a
            # finally on the event-loop thread; on a stream timeout that close
            # raced the still-running next() on a worker thread ("generator
            # already executing") and the generator's cleanup was lost. The fix
            # (NetworkManager._drive_sync_gen_stream) closes on the SAME worker
            # thread as next(), serialized by a lock. This guard drives the REAL
            # helper with a generator that blocks inside next() when the timeout
            # fires, and asserts: no close ever raced a live next(), and the
            # generator IS closed on a worker thread. If the fix is reverted,
            # the instrumented generator records race=True and this case fails.
            import threading as _th
            import time as _tm
            from concurrent.futures import ThreadPoolExecutor as _TPE

            grec: Dict[str, Any] = {}

            class _GW:
                def __init__(self, gen):
                    self._gen = gen

                def __iter__(self):
                    return self

                def __next__(self):
                    grec["next_running"] = True
                    try:
                        return self._gen.__next__()
                    finally:
                        grec["next_running"] = False

                def send(self, v):
                    return self._gen.send(v)

                def throw(self, *a):
                    return self._gen.throw(*a)

                def close(self):
                    grec.setdefault("close_calls", []).append(
                        {"thread": _th.current_thread().name,
                         "while_next_running": grec.get("next_running", False)}
                    )
                    try:
                        self._gen.close()
                    except ValueError as e:
                        if "already executing" in str(e):
                            grec["race"] = True
                        raise

            def _mk_gen():
                def g():
                    try:
                        for i in range(4):
                            if i == 1:
                                _tm.sleep(1.0)  # block inside next() so timeout fires mid-next
                            yield i
                    finally:
                        grec["cleanup_ran"] = True
                        grec["cleanup_thread"] = _th.current_thread().name
                return _GW(g())

            nm = self._plexus.network
            if nm is None:
                c.skip("networking not enabled")
                return

            executor = _TPE(max_workers=2)
            sentinel = object()
            received: List[int] = []

            async def on_chunk(item):
                received.append(item)

            gen = _mk_gen()
            timed_out = False
            try:
                await asyncio.wait_for(
                    nm._drive_sync_gen_stream(executor, gen, on_chunk, sentinel),
                    timeout=0.3,
                )
            except asyncio.TimeoutError:
                timed_out = True

            # let the blocked next() return (~1.0s) so the worker-side close runs
            for _ in range(150):
                if grec.get("cleanup_ran") or grec.get("race"):
                    break
                await asyncio.sleep(0.02)
            executor.shutdown(wait=False)

            c.expect(timed_out, True)
            c.expect(received, [0])
            assert not grec.get("race"), (
                f"B-081/BUG-028 regressed: gen.close() raced a live next(); "
                f"close_calls={grec.get('close_calls')}"
            )
            for cc in grec.get("close_calls", []):
                assert not cc["while_next_running"], (
                    f"B-081/BUG-028 regressed: close ran while next() in flight: {cc}"
                )
            assert grec.get("cleanup_ran"), "generator cleanup never ran"
            assert str(grec.get("cleanup_thread", "")).startswith("ThreadPoolExecutor"), (
                f"cleanup ran on {grec.get('cleanup_thread')!r}, expected a worker thread"
            )

        await rec.run_case(
            "bug.B-081.sync_gen_close_worker_thread",
            body_b_081_sync_gen_close_worker_thread,
            category=category,
            tags=("bug_repro", "networking", "sync_gen", "BUG-028"),
            bug_ids=("B-081",),
            **kw,
        )

    # ──────────────────────────────────────────────────────────────────
    # PR4 Stage K B-066 — instance-level test fixtures.
    # ──────────────────────────────────────────────────────────────────
    _b066_peer_seq: int = 0

    async def _b066_make_test_peer(
        self,
        *,
        system_caller: bool = False,
        register_in_maps: bool = True,
        add_to_trust_store: bool = True,
        fake_port: Optional[int] = None,
        hostname: Optional[str] = None,
    ) -> Dict[str, Any]:
        # RETIRED (netcore rewrite): the B-066 raw-wire harness drives the deleted
        # [len][type][payload] MSG_* protocol + old-NM peer maps (`register_in_maps`,
        # trust-store pokes). Those behaviors are covered by the netcore self-tests
        # (mTLS+SPKI, anti-spoof, framing) + the wave-2 hostile-frame harness. Raising
        # the recorder's skip signal here neutralizes every B-066/B-018b wire cell that
        # builds a test peer, without editing each one.
        from _test_helpers import _SkipSignal as _SS
        raise _SS()
        nm = self._plexus.network  # noqa: E501  (unreachable — retained for diff clarity)
        # Every test peer uses a UNIQUE subject CN. If
        # two self-signed CA certs in the trust store share Subject DN,
        # OpenSSL's chain-builder picks the FIRST match by name and
        # validates the presented cert's signature against the WRONG
        # public key — handshake fails for everything but the originally
        # presented cert. Unique hostname == unique Subject DN.
        type(self)._b066_peer_seq += 1
        seq = type(self)._b066_peer_seq
        if hostname is None:
            hostname = f"b066_test_peer_{seq:03d}"
        keys_dir = tempfile.mkdtemp(prefix="b066_test_")
        cert_path, key_path, fp, cert_pem = generate_keypair(keys_dir, hostname)
        spec = None
        if fake_port is None:
            fake_port = 19999 + seq
        if register_in_maps:
            spec = PeerSpec(
                hostname=hostname,
                ip="127.0.0.1",
                port=fake_port,
                cert_pem=cert_pem,
                fingerprint=fp,
                system_caller=system_caller,
            )
            nm.peers.append(spec)
            nm.peers_by_fingerprint[fp] = spec
            nm.peers_by_endpoint[("127.0.0.1", fake_port)] = spec
        if add_to_trust_store:
            nm.ssl_context.load_verify_locations(cadata=cert_pem)
        return {
            "keys_dir": keys_dir,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "fingerprint": fp,
            "cert_pem": cert_pem,
            "spec": spec,
            "fake_port": fake_port,
        }

    def _b066_cleanup_test_peer(self, peer_info: Dict[str, Any]) -> None:
        nm = self._plexus.network
        spec = peer_info.get("spec")
        if spec is not None:
            nm.peers_by_fingerprint.pop(spec.fingerprint, None)
            nm.peers_by_endpoint.pop((spec.ip, spec.port), None)
            nm.peers = [p for p in nm.peers if p.fingerprint != spec.fingerprint]
        shutil.rmtree(peer_info["keys_dir"], ignore_errors=True)

    def _b066_make_client_ssl_context(
        self, peer_info: Dict[str, Any], *, trust_parent: bool = True,
    ) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        ctx.load_cert_chain(peer_info["cert_path"], peer_info["key_path"])
        if trust_parent:
            nm = self._plexus.network
            ctx.load_verify_locations(
                cadata=Path(nm.cert_path).read_text(encoding="utf-8")
            )
        return ctx

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _ensure_loaded(self, name: str) -> bool:
        """Idempotently load+enable a fixture by name from yaml_config."""
        if name in self._plexus.plugins:
            return True
        for entry in self._plexus.yaml_config.get("plugins", []):
            if entry.get("name") == name:
                e = dict(entry)
                e["enabled"] = True
                await self._plexus.load_plugin_with_conf(e)
                if name in self._plexus.plugins:
                    try:
                        await self._plexus.enable_plugin(name)
                    except Exception:
                        pass
                    return True
        return False

    # ==================================================================
    # _b_legacy_removed — Recipe A (API surface gone)
    # ==================================================================
    async def _b_legacy_removed(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "legacy_removed"

        # ---- B-001 ---------------------------------------------------
        async def body_b_001_request_topic_method_gone(c):
            # B-001: code-driven topic handlers bypassed remote: false.
            # The legacy `request_topic` API + `_handle_topic_request`
            # server handler were removed in Stage D, so the entire
            # bypass surface no longer exists.
            c.expect(getattr(self, "request_topic", None), None)
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-011 ---------------------------------------------------
        async def body_b_011_request_topic_stream_remote_gone(c):
            # B-011: legacy stream-error sentinel only existed on the
            # request_topic_stream_remote path. That whole client method
            # was removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "request_topic_stream_remote", None), None)

        # ---- B-012 ---------------------------------------------------
        async def body_b_012_handle_topic_request_stream_gone(c):
            # B-012: server-side stream-chunk error sentinel handler
            # `_handle_topic_request_stream` was removed in Stage D.
            nm = self._plexus.network
            c.expect(
                getattr(nm, "_handle_topic_request_stream", None), None
            )

        # ---- B-014 ---------------------------------------------------
        async def body_b_014_request_topic_stream_sync_gone(c):
            # B-014: `request_topic_stream_sync` method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream_sync", None), None)

        # ---- B-018a --------------------------------------------------
        async def body_b_018a_handle_notify_handler_gone(c):
            # B-018a: wire-side spoof handlers (_handle_notify and
            # _handle_topic_request) were removed in Stage D — the
            # MSG_NOTIFY / MSG_TOPIC_REQUEST surface they hung off no
            # longer exists, so the remote spoof path through them is
            # gone.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_notify", None), None)
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-019 ---------------------------------------------------
        async def body_b_019_notify_method_gone(c):
            # B-019: `notify`'s return-count contract is moot — the
            # method itself was removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # ---- B-020 ---------------------------------------------------
        async def body_b_020_notify_sync_method_gone(c):
            # B-020: `notify_sync` blocking-on-remote-ACK can't repro —
            # method removed in Stage D.
            c.expect(getattr(self, "notify_sync", None), None)

        # ---- B-022 ---------------------------------------------------
        async def body_b_022_subscribe_handler_kwarg_gone(c):
            # B-022: subscribe() no longer accepts `handler=` (silent
            # no-op risk gone). The `target_access_name` parameter
            # replaced it. Verify both: handler not in signature, AND
            # target_access_name IS in signature.
            sig = inspect.signature(self.subscribe)
            params = sig.parameters
            c.expect("handler" in params, False)
            c.expect("target_access_name" in params, True)

        # ---- B-023 ---------------------------------------------------
        async def body_b_023_notify_method_gone(c):
            # B-023: `notify()` raise-on-error contract violation can't
            # repro — method removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # ---- B-024 ---------------------------------------------------
        async def body_b_024_request_topic_stream_gone(c):
            # B-024: oversized chunk corruption on `request_topic_stream`
            # can't repro — method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-025 ---------------------------------------------------
        async def body_b_025_request_topic_stream_gone(c):
            # B-025: re-entry-after-partial-yield bug on
            # `request_topic_stream` can't repro — method removed in
            # Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-027 ---------------------------------------------------
        async def body_b_027_notify_remote_gone(c):
            # B-027: notify_remote return-zero-on-transport-fail can't
            # repro — method removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)

        # ---- B-028 ---------------------------------------------------
        async def body_b_028_remote_notifier_methods_gone(c):
            # B-028: notify_remote, request_topic_remote,
            # request_topic_stream_remote — all client-side notifier
            # methods removed in Stage D, so the no-client-timeout
            # caller-hang surface is gone entirely.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)
            c.expect(getattr(nm, "request_topic_remote", None), None)
            c.expect(getattr(nm, "request_topic_stream_remote", None), None)

        # ---- B-029 ---------------------------------------------------
        async def body_b_029_handle_topic_request_gone(c):
            # B-029: server-side `_handle_topic_request` ignored its
            # `timeout` for code-driven handlers — handler itself gone
            # in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_topic_request", None), None)

        # ---- B-030 ---------------------------------------------------
        async def body_b_030_notify_remote_gone(c):
            # B-030: `notify_remote` swallowing pickle errors can't
            # repro — method removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "notify_remote", None), None)

        # ---- B-032 ---------------------------------------------------
        async def body_b_032_handle_notify_gone(c):
            # B-032: server-side `_handle_notify` head-of-line blocking
            # on slow fan-out can't repro — handler removed in Stage D.
            nm = self._plexus.network
            c.expect(getattr(nm, "_handle_notify", None), None)

        # ---- B-033 ---------------------------------------------------
        async def body_b_033_request_topic_stream_sync_gone(c):
            # B-033: `request_topic_stream_sync` ignoring its `host`
            # parameter can't repro — method removed in Stage D.
            c.expect(getattr(self, "request_topic_stream_sync", None), None)

        # ---- B-035 ---------------------------------------------------
        async def body_b_035_notify_method_gone(c):
            # B-035: `notify`'s asyncio.gather-no-per-sub-timeout
            # symptom can't repro — method removed in Stage D.
            # `publish_event` is the new fire-and-forget primitive but
            # uses asyncio.create_task per-handler (verify in source).
            c.expect(getattr(self, "notify", None), None)
            src = inspect.getsource(self._plexus.publish_event)
            # Sanity: dispatch path uses create_task (per-sub
            # independent) rather than a single gather over all subs.
            c.expect("create_task" in src, True)

        # ---- B-036 ---------------------------------------------------
        async def body_b_036_call_sub_method_gone(c):
            # B-036: `_call_sub` caught Exception not BaseException —
            # function replaced by `_fanout_sub` in PR3. Verify the old
            # name is gone.
            core = self._plexus
            c.expect(getattr(core, "_call_sub", None), None)

        # ---- B-039 ---------------------------------------------------
        async def body_b_039_request_topic_sync_gone(c):
            # B-039: topic-hop-wipes-_sync_call_chain symptom rode on
            # `request_topic_sync` — method removed in Stage D.
            c.expect(getattr(self, "request_topic_sync", None), None)

        # ---- B-042 ---------------------------------------------------
        async def body_b_042_request_topic_stream_gone(c):
            # B-042: code-driven stream bypass (B-001 variant for
            # streams) — `request_topic_stream` method removed in
            # Stage D.
            c.expect(getattr(self, "request_topic_stream", None), None)

        # ---- B-053 ---------------------------------------------------
        async def body_b_053_subscription_handler_field_gone(c):
            # B-053: `Subscription.handler` field removed from the
            # dataclass. Also assert the new field names are present
            # so this case fails informatively if the schema regresses.
            import dataclasses
            from plexus.notifier import Subscription
            fields = {f.name for f in dataclasses.fields(Subscription)}
            c.expect("handler" in fields, False)
            c.expect("endpoint_access_name" in fields, False)
            c.expect("config_driven" in fields, False)
            # Positive assertions: new PR3 fields must be present.
            c.expect("target_access_name" in fields, True)
            c.expect("sub_uuid" in fields, True)
            c.expect("enabled" in fields, True)

        # ---- B-059 ---------------------------------------------------
        async def body_b_059_notify_method_gone(c):
            # B-059: cross-plugin sub routing mismatch on the legacy
            # `notify()` path can't repro — method removed in Stage D.
            c.expect(getattr(self, "notify", None), None)

        # -- run_case calls --------------------------------------------
        await rec.run_case(
            "bug.B-001.request_topic_method_gone",
            body_b_001_request_topic_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-001",), **kw,
        )
        await rec.run_case(
            "bug.B-011.request_topic_stream_remote_gone",
            body_b_011_request_topic_stream_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-011",), **kw,
        )
        await rec.run_case(
            "bug.B-012.handle_topic_request_stream_gone",
            body_b_012_handle_topic_request_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-012",), **kw,
        )
        await rec.run_case(
            "bug.B-014.request_topic_stream_sync_gone",
            body_b_014_request_topic_stream_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-014",), **kw,
        )
        await rec.run_case(
            "bug.B-018a.handle_notify_handler_gone",
            body_b_018a_handle_notify_handler_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-018",), **kw,
        )
        await rec.run_case(
            "bug.B-019.notify_method_gone",
            body_b_019_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-019",), **kw,
        )
        await rec.run_case(
            "bug.B-020.notify_sync_method_gone",
            body_b_020_notify_sync_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-020",), **kw,
        )
        await rec.run_case(
            "bug.B-022.subscribe_handler_kwarg_gone",
            body_b_022_subscribe_handler_kwarg_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-022",), **kw,
        )
        await rec.run_case(
            "bug.B-023.notify_method_gone",
            body_b_023_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-023",), **kw,
        )
        await rec.run_case(
            "bug.B-024.request_topic_stream_gone",
            body_b_024_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-024",), **kw,
        )
        await rec.run_case(
            "bug.B-025.request_topic_stream_gone",
            body_b_025_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-025",), **kw,
        )
        await rec.run_case(
            "bug.B-027.notify_remote_gone",
            body_b_027_notify_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-027",), **kw,
        )
        await rec.run_case(
            "bug.B-028.remote_notifier_methods_gone",
            body_b_028_remote_notifier_methods_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-028",), **kw,
        )
        await rec.run_case(
            "bug.B-029.handle_topic_request_gone",
            body_b_029_handle_topic_request_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-029",), **kw,
        )
        await rec.run_case(
            "bug.B-030.notify_remote_gone",
            body_b_030_notify_remote_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-030",), **kw,
        )
        await rec.run_case(
            "bug.B-032.handle_notify_gone",
            body_b_032_handle_notify_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-032",), **kw,
        )
        await rec.run_case(
            "bug.B-033.request_topic_stream_sync_gone",
            body_b_033_request_topic_stream_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-033",), **kw,
        )
        await rec.run_case(
            "bug.B-035.notify_method_gone",
            body_b_035_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-035",), **kw,
        )
        await rec.run_case(
            "bug.B-036.call_sub_method_gone",
            body_b_036_call_sub_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-036",), **kw,
        )
        await rec.run_case(
            "bug.B-039.request_topic_sync_gone",
            body_b_039_request_topic_sync_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-039",), **kw,
        )
        await rec.run_case(
            "bug.B-042.request_topic_stream_gone",
            body_b_042_request_topic_stream_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-042",), **kw,
        )
        await rec.run_case(
            "bug.B-053.subscription_handler_field_gone",
            body_b_053_subscription_handler_field_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-053",), **kw,
        )
        await rec.run_case(
            "bug.B-059.notify_method_gone",
            body_b_059_notify_method_gone,
            category=category,
            tags=("bug_repro", "legacy_removed"), bug_ids=("B-059",), **kw,
        )

    # ==================================================================
    # _b_addressed_in_pr3 — Recipe B
    # ==================================================================
    async def _b_addressed_in_pr3(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "addressed_in_pr3"

        # ---- B-003 ---------------------------------------------------
        async def body_b_003_disable_unregisters_subs(c):
            # B-003: notify dispatched to handlers on disabled plugin.
            # Stage B's _disable_plugin wrapper now calls
            # _unregister_plugin_subscriptions at end of on_disable per
            # Q23+C15. Verify: pop a plugin, confirm its subs vanish
            # from topic_registry, then restore via _ensure_loaded.
            target = TARGET
            if target not in self._plexus.plugins:
                c.skip(f"{target} not loaded — fixture order issue")
                return
            pre = await self._plexus.topic_registry.list_local_subs()
            pre_owned = [s for s in pre if s.plugin_name == target]
            if len(pre_owned) == 0:
                c.skip(
                    f"{target} has no subs registered — precondition fail"
                )
                return
            # Net-zero drift: pop + reload restores the plugin set, but
            # during the body the set transiently misses TARGET. Without
            # explicit declaration, _check_drift only sees the final
            # state — which matches snapshot. Defensive declaration
            # nonetheless:
            c.set_expected_drift(added=(), removed=())
            await self._plexus.pop_plugin(target)
            post = await self._plexus.topic_registry.list_local_subs()
            post_owned = [s for s in post if s.plugin_name == target]
            c.expect(len(post_owned), 0)
            # Restore so subsequent cases find TARGET loaded.
            restored = await self._ensure_loaded(target)
            if not restored:
                raise AssertionError(
                    f"failed to restore {target} after pop"
                )

        # ---- B-038 ---------------------------------------------------
        async def body_b_038_sync_pre_start_raises_request_exception(c):
            # B-038: pre-start sync wrappers used to raise TypeError.
            # Stage A Q1 added _check_framework_started guard to all
            # sync wrappers — fires FIRST (before event lookup, before
            # run_coroutine_threadsafe). Can't actually call before
            # framework start in this test (main_event_loop is set).
            # Instead, transiently null it and call. The event_id
            # passed below is intentionally bogus — guard fires before
            # lookup so the bogus id is never dereferenced.
            saved = self._plexus.main_event_loop
            self._plexus.main_event_loop = None
            try:
                c.expect_exception(
                    RequestException, match="Framework not started"
                )
                self.publish_event_sync("any_id_guard_fires_first")
            finally:
                self._plexus.main_event_loop = saved

        # ---- B-056 ---------------------------------------------------
        async def body_b_056_disabled_subs_excluded(c):
            # B-056: disabled YAML subs registered with enabled=False.
            # Verify topic_registry contains the disabled sub with
            # `.enabled == False`, AND _find_first skips it.
            #
            # The TestEventSuite YAML declares `disabled_event` (an
            # event with `enabled: false`) — but no matching sub for
            # it. Use a runtime sub instead: register one, mark it
            # disabled directly on the registry entry, then verify
            # _find_first returns no eligible subscriber.
            topic = "test_bugsuite/B056/disabled_probe"
            sub_uuid = await self.subscribe(
                topic,
                target_access_name="run",  # any handler — never invoked
            )
            try:
                subs = (
                    await self._plexus.topic_registry.list_local_subs()
                )
                owned = [s for s in subs if s.sub_uuid == sub_uuid]
                if len(owned) != 1:
                    raise AssertionError(
                        "B-056: runtime subscribe failed to register sub"
                    )
                # Toggle to disabled.
                owned[0].enabled = False
                # Disabled subs are skipped at match time (enabled is
                # checked inside find_all), so _find_first must return no
                # eligible subscriber for this topic.
                found = (
                    await self._plexus.topic_registry._find_first(topic)
                )
                if found is not None and found.sub_uuid == sub_uuid:
                    raise AssertionError(
                        "B-056: _find_first returned a disabled sub "
                        "(enabled=False not honored)"
                    )
            finally:
                await self.unsubscribe(sub_uuid)

        await rec.run_case(
            "bug.B-003.disable_unregisters_subs",
            body_b_003_disable_unregisters_subs,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-003",),
            **kw,
        )
        await rec.run_case(
            "bug.B-038.sync_pre_start_raises_request_exception",
            body_b_038_sync_pre_start_raises_request_exception,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-038",),
            **kw,
        )
        await rec.run_case(
            "bug.B-056.disabled_subs_excluded",
            body_b_056_disabled_subs_excluded,
            category=category,
            tags=("bug_repro", "addressed_in_pr3"), bug_ids=("B-056",),
            **kw,
        )

    # ==================================================================
    # _b_active — Recipe C
    # ==================================================================
    async def _b_active(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "active"

        # ---- B-018b --------------------------------------------------
        async def body_b_018b_uuid_spoof_denied(c):
            # B-018b consequence guard (real 2-node; replaces the old
            # source-grep canary execute_system_rewrite_alive, which only
            # checked that a benign local convenience rewrite still existed
            # in execute()'s source and could never run an actual spoof).
            #
            # A remote peer that spoofs author_id = a real LOCAL plugin uuid
            # must NOT gain local-plugin access. _apply_b018b_guard Part 2
            # (networking.py, runs before execute()) rewrites the spoofed
            # author_id to a remote-peer sentinel, so find_endpoint
            # (core.py is_local_plugin check) treats the call as REMOTE.
            # TestEventTarget is remote:false, so get_state is denied
            # ("Endpoint get_state not found"). Without the rewrite the
            # spoofed uuid would match a local plugin, take the local-access
            # path, and reach the endpoint — the original B-018b bypass.
            # author="remote" (not "system") isolates the author_id rewrite
            # from the system_caller gate covered by the denial/grant cases.
            peer = await self._b066_make_test_peer(system_caller=False)
            writer = None
            try:
                client_ctx = self._b066_make_client_ssl_context(peer)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1",
                        self._plexus.network.port,
                        ssl=client_ctx,
                    ),
                    timeout=5.0,
                )
                await _b066_send_msg(writer, MSG_EXECUTE, {
                    "plugin": "TestEventTarget",
                    "method": "get_state",
                    "args": None,
                    "author": "remote",
                    "author_id": self.plugin_uuid,  # spoof a real local uuid
                    "author_host": peer["spec"].hostname,
                    "request_id": "b018b-uuid-spoof-denied",
                })
                msg_type, data = await _b066_recv_msg(reader, timeout=5.0)
                # Denied: rewritten -> remote request -> remote:false endpoint.
                c.expect(msg_type, MSG_ERROR)
                c.expect("not found" in str(data).lower(), True)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                self._b066_cleanup_test_peer(peer)

        # ---- B-021 ---------------------------------------------------
        async def body_b_021_request_event_fallthrough_or_fail(c):
            # B-021 (regression): two subs on the SAME topic
            # "test_bugsuite/b021/leaf", declared in this order:
            #   1. b021_blocked_first  — blocked_authors=[TestBugSuite], so it
            #      does NOT accept this suite as the publisher.
            #   2. b021_eligible_second — accepts.
            # request_event must SKIP the non-eligible first match (it is
            # earlier in find_all insertion order) and fall through to the
            # eligible second — proving the 1:1 path uses find_all + the
            # filter chain, NOT the filter-blind _find_first. A regression to
            # first-topic-match would either raise "no subscriber" or
            # dispatch to the blocked handler.
            self.b021_blocked_calls = 0
            self.b021_eligible_calls = 0
            r = await self.request_event(
                "b021_event", payload={"x": 1}, timeout=2.0,
            )
            c.expect(r, {"who": "eligible"})
            c.expect(self.b021_blocked_calls, 0)
            c.expect(self.b021_eligible_calls, 1)

        # ---- B-044 ---------------------------------------------------
        async def body_b_044_silent_truncation_on_error(c):
            # B-044: FIXED in Stage G (utils.py Request.get_queue_stream now
            # yields the error tuple before breaking, so execute_stream's
            # `if error: raise RequestException(result)` branch fires).
            # This case asserts the FIXED behavior: a stream that yields N
            # items then raises must propagate RequestException to the
            # consumer (NOT silently truncate). Regression guard.
            received = []
            try:
                async for v in self.execute_stream(
                    STREAM_TARGET, "ea_gen_raises_after", (3,)
                ):
                    received.append(v)
            except RequestException:
                # Expected: error surfaces. Verify we got the pre-error
                # items first (so they weren't dropped on the floor).
                c.expect(len(received), 3)
                return
            raise AssertionError(
                f"B-044 regression: stream completed silently "
                f"(got {len(received)} items, no RequestException)"
            )

        # ---- B-045 ---------------------------------------------------
        async def body_b_045_stream_timeout_exception_type(c):
            # B-045: FIXED in Stage G (utils.py Request.get_queue_stream
            # now wraps asyncio.TimeoutError as RequestException, symmetric
            # with execute()). Asserts the FIXED behavior: stream timeout
            # surfaces as RequestException, never as raw asyncio.TimeoutError.
            # Regression guard.
            import asyncio as _asyncio
            try:
                async for _ in self.execute_stream(
                    STREAM_TARGET,
                    "ea_gen_hangs",
                    None,
                    timeout=0.2,
                ):
                    pass
            except RequestException:
                return  # Expected post-fix.
            except _asyncio.TimeoutError as e:
                raise AssertionError(
                    f"B-045 regression: stream timeout surfaced as "
                    f"asyncio.TimeoutError, not RequestException ({e!r})"
                )
            raise AssertionError(
                "B-045 regression: stream timeout produced no exception at all"
            )

        # ---- B-046 ---------------------------------------------------
        async def body_b_046_plugin_lock_held_across_on_enable(c):
            # B-046: FIXED in Stage O via per-plugin lifecycle locks.
            # The global plugin_lock is now held only for fast dict
            # reads/writes; user on_enable runs OUTSIDE plugin_lock
            # under the per-plugin lifecycle_lock. Regression guard:
            # while one plugin's on_enable is mid-flight (artificially
            # delayed), a concurrent get_plugin_info on a DIFFERENT
            # plugin must return promptly (well under 1s).
            core = self._plexus
            v_name = "TestLifecycleVictim"
            other_name = "TestLifecycleSuite"
            victim = core.plugins.get(v_name)
            if victim is None or other_name not in core.plugins:
                c.skip(
                    "B-046 regression guard requires TestLifecycleVictim "
                    "and TestLifecycleSuite both loaded"
                )
                return

            # Slow on_enable: 0.6s sleep. Configure flags directly so
            # we don't depend on the configure endpoint being callable
            # while the plugin is in mid-disable.
            victim._on_enable_delay_secs = 0.6
            try:
                # Disable then concurrently re-enable + ping a different
                # plugin's get_plugin_info. Pre-fix the call would block
                # on plugin_lock until on_enable finishes.
                await core.disable_plugin(v_name)

                async def _delayed_get_info():
                    # Tiny stagger so enable is in mid-on_enable when
                    # we hit get_plugin_info.
                    await asyncio.sleep(0.1)
                    t0 = asyncio.get_event_loop().time()
                    info = await core.get_plugin_info(other_name)
                    return info, asyncio.get_event_loop().time() - t0

                enable_task = asyncio.create_task(core.enable_plugin(v_name))
                info_task = asyncio.create_task(_delayed_get_info())
                info, elapsed = await info_task
                await enable_task

                if info is None or info.get("name") != other_name:
                    raise AssertionError(
                        f"B-046 regression: get_plugin_info({other_name}) "
                        f"returned {info!r}"
                    )
                # Should return well under the 0.5s remainder of the
                # on_enable sleep. R1 LOW-1 fix: threshold raised from
                # 0.2s to 1.0s — Windows scheduler timer resolution is
                # ~15.6ms and loaded CI can blow past 200ms. The actual
                # operation is a dict read (microseconds); 1s still
                # comfortably catches a regression where the lock is
                # held across the full 1.5s on_enable sleep.
                if elapsed > 1.0:
                    raise AssertionError(
                        f"B-046 regression: get_plugin_info on {other_name} "
                        f"took {elapsed:.3f}s while {v_name}.on_enable was "
                        f"sleeping — plugin_lock still held across on_enable"
                    )
            finally:
                # Restore configuration so subsequent suites are clean.
                victim = core.plugins.get(v_name)
                if victim is not None:
                    victim._on_enable_delay_secs = 0.0
                    if not victim.enabled:
                        try:
                            await core.enable_plugin(v_name)
                        except Exception:
                            pass

        # ---- B-047 ---------------------------------------------------
        async def body_b_047_task_list_grows_unboundedly(c):
            # B-047 (Stage Q FIXED): task_list now uses set + per-task
            # done_callback for O(1) self-eviction. This regression guard
            # asserts that a 200-event burst does NOT cause sustained
            # growth. b047_probe_event is registered → b047_probe_sub →
            # handle_b047_probe so every publish spawns one real fan-out
            # task that exercises the eviction path.
            core = self._plexus
            tlist = getattr(core, "task_list", None)
            if tlist is None:
                # Attribute removed — fixed-by-construction.
                return
            # Snapshot baseline tasks. We measure the delta from the
            # burst (tasks NOT in this snapshot) instead of total list
            # size, so concurrent unrelated activity adding/removing
            # its own tasks doesn't false-trigger the assertion.
            before_set = frozenset(tlist)
            for _ in range(200):
                await self.publish_event_for_repro()
            # Poll until burst-spawned tasks drain. Each fan-out task
            # awaits _process_request → endpoint dispatch → producer's
            # finally pops from self.requests (B-073
            # — was set_collected pre-migration) → done_callback fires
            # via call_soon. One asyncio.sleep(0) is NOT enough;
            # deadline-bounded poll handles slow CI.
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                remaining = sum(1 for t in tlist if t not in before_set)
                if remaining <= 5:
                    break
                await asyncio.sleep(0.01)
            remaining = sum(1 for t in tlist if t not in before_set)
            if remaining > 5:
                raise AssertionError(
                    f"B-047 regression: {remaining} burst-spawned tasks "
                    f"remain in task_list after 5s drain — done_callback "
                    f"eviction not firing"
                )

        # ---- B-048 ---------------------------------------------------
        async def body_b_048_find_endpoint_returns_none_tuple(c):
            # B-048: find_endpoint type annotation says Optional[tuple]
            # but returns 3-tuple of Nones on miss. Verify the actual
            # return shape against a guaranteed-miss lookup. Signature
            # is (access_name, hosts, blocked_hosts, plugin_uuid,
            # requester_id, target_plugin) — find_endpoint is async.
            core = self._plexus
            try:
                result = await core.find_endpoint(
                    "no_such_endpoint_for_b048_repro",
                    "any",
                )
            except TypeError:
                # Signature drift — skip to avoid spurious failure.
                c.skip(
                    "find_endpoint signature changed — re-verify in "
                    "follow-up"
                )
                return
            # Bug confirmed if result is the 3-tuple of Nones rather
            # than a single None.
            if (
                isinstance(result, tuple)
                and len(result) == 3
                and result == (None, None, None)
            ):
                raise AssertionError(
                    "B-048: find_endpoint returns (None, None, None) "
                    "instead of None on miss — annotation contract "
                    "broken"
                )

        # ---- B-051 ---------------------------------------------------
        async def body_b_051_normalize_hosts_authors_keyword(c):
            # B-051: _normalize_hosts was reused for the `authors` field.
            # The keyword-in-list guard rejects "remote"/"any" in lists
            # with other elements — appropriate for hosts but
            # inappropriate for authors (where "remote" could be a
            # literal plugin name). The fix split the normalizer into
            # `_normalize_authors` which skips the keyword guard. This
            # test now exercises that path: the ValueError must NOT
            # fire on authors-vocabulary input. Recorder marks "pass"
            # when no exception is raised.
            from plexus.core import _normalize_authors
            _normalize_authors(
                ["remote", "OtherPlugin"],
                param_name="authors",
                default=None,
            )

        # ---- B-054 ---------------------------------------------------
        async def body_b_054_request_event_stream_bypasses_request(c):
            # B-054: request_event_stream bypasses Request lifecycle —
            # stream-dispatch entries aren't tracked in core.requests.
            # Repro: verify that during a streaming dispatch, no
            # corresponding entry shows up in requests. Implementation-
            # bound: skip if requests dict isn't accessible or the
            # streaming primitive isn't routable here.
            core = self._plexus
            requests = getattr(core, "requests", None)
            if requests is None:
                c.skip(
                    "STAGE_F_FIXME: core.requests not accessible from "
                    "suite context — repro path implementation-bound"
                )
                return
            # No clean way to drive a streaming request and snapshot
            # the requests dict mid-flight without race-prone timing.
            # Defer to fixture work.
            c.skip(
                "STAGE_F_FIXME: request_event_stream lifecycle repro "
                "needs mid-flight snapshot of core.requests; race-prone "
                "without dedicated harness fixture"
            )

        # ---- B-064 ---------------------------------------------------
        async def body_b_064_subscribe_no_async_log_errors(c):
            # B-064: preventive — Plugin.subscribe must NOT have
            # @async_log_errors decorator. getsource inspects the
            # original source text; a post-class-definition wrapping
            # would slip past (low-risk false negative documented).
            src = inspect.getsource(Plugin.subscribe)
            c.expect("async_log_errors" in src, False)

        # -- run_case calls --------------------------------------------
        # B-018b consequence guard (positive): a spoofed author_id=<local uuid>
        # is rewritten by _apply_b018b_guard and then DENIED local access to a
        # remote:false endpoint. Replaces the retired source-grep canary
        # execute_system_rewrite_alive. Real 2-node coverage of the actual
        # security property, alongside the B-066 denial/grant cases.
        await rec.run_case(
            "bug.B-018b.uuid_spoof_denied_local_endpoint",
            body_b_018b_uuid_spoof_denied,
            category=category,
            tags=("bug_repro", "security", "b066"), bug_ids=("B-018",),
            hard_timeout_s=10.0,
            **kw,
        )
        # B-021: live regression guard (was skipped pending a fixture).
        await rec.run_case(
            "bug.B-021.request_event_fallthrough_or_fail",
            body_b_021_request_event_fallthrough_or_fail,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-021",),
            **kw,
        )
        # B-044: FIXED in Stage G. Case now asserts the FIXED behavior
        # (RequestException propagated to consumer). Regression guard.
        await rec.run_case(
            "bug.B-044.silent_truncation_on_error",
            body_b_044_silent_truncation_on_error,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-044",),
            **kw,
        )
        # B-045: FIXED in Stage G. Case asserts FIXED behavior
        # (RequestException for timeouts, never asyncio.TimeoutError).
        await rec.run_case(
            "bug.B-045.stream_timeout_exception_type",
            body_b_045_stream_timeout_exception_type,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-045",),
            **kw,
        )
        # B-046: FIXED in Stage O. Positive guard — body asserts that
        # a concurrent dict-read on another plugin completes promptly
        # while one plugin's on_enable is artificially delayed.
        await rec.run_case(
            "bug.B-046.plugin_lock_held_across_on_enable",
            body_b_046_plugin_lock_held_across_on_enable,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-046",),
            hard_timeout_s=15.0,
            **kw,
        )
        # B-047: expected_status="fail" — bug expected to repro
        # B-047: FIXED in Stage Q. Positive regression guard — body
        # asserts burst-spawned tasks drain via the per-task
        # done_callback within 5s. Success path completes in
        # milliseconds; the deadline only fires on a regression.
        # slow=True intentionally removed (no longer slow).
        await rec.run_case(
            "bug.B-047.task_list_grows_unboundedly",
            body_b_047_task_list_grows_unboundedly,
            category=category,
            tags=("bug_repro", "regression_guard"), bug_ids=("B-047",),
            **kw,
        )
        # B-048: expected_status="fail" — bug expected to repro
        # (3-tuple of Nones instead of None).
        await rec.run_case(
            "bug.B-048.find_endpoint_returns_none_tuple",
            body_b_048_find_endpoint_returns_none_tuple,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-048",),
            expected_status="fail",
            expected_signature={
                "exception_type": "AssertionError",
                "message_regex": r"None, None, None",
            },
            **kw,
        )
        # B-051: c.expect_exception drives the path — no
        # expected_status="fail" needed. ValueError matching =>
        # recorded as pass (bug confirmed).
        await rec.run_case(
            "bug.B-051.normalize_hosts_authors_keyword",
            body_b_051_normalize_hosts_authors_keyword,
            category=category,
            tags=("bug_repro", "active"), bug_ids=("B-051",),
            **kw,
        )
        # B-054: skip pending fixture work.
        await rec.run_case(
            "bug.B-054.request_event_stream_bypasses_request",
            body_b_054_request_event_stream_bypasses_request,
            category=category,
            tags=("bug_repro", "active", "deferred"), bug_ids=("B-054",),
            **kw,
        )
        # B-064: preventive — body uses c.expect (default
        # expected_status="pass"); pass = decorator absent (good).
        await rec.run_case(
            "bug.B-064.subscribe_no_async_log_errors",
            body_b_064_subscribe_no_async_log_errors,
            category=category,
            tags=("bug_repro", "active", "preventive"), bug_ids=("B-064",),
            **kw,
        )

    # Helper used by B-047 — publishes b047_probe_event which routes
    # via b047_probe_sub → handle_b047_probe. Each call spawns one
    # real fan-out task in Plexus.task_list; the test asserts
    # that the eviction path (Stage Q done_callback) drains them.
    async def publish_event_for_repro(self):
        try:
            await self.publish_event("b047_probe_event")
        except Exception:
            pass



    # ==================================================================
    # _b_security — PR4 Stage K B-066 regression guards (Tests 1, 1b, 2,
    # 2b, 3, 4, 5). Each test impersonates a peer locally inside the
    # parent's NetworkManager and exercises one mTLS pinning / SafeUnpickler
    # / B-018b guard code path.
    # ==================================================================
    async def _b_security(self, rec: CaseRecorder, kw: Dict) -> None:
        category = "security"






        async def body_b_066_execute_hostname_drift_errors(c):
            # C-106 follow-up regression guard: an EXECUTE whose wire
            # author_host does NOT match the cert-pinned hostname must get an
            # anti-spoof MSG_ERROR, not a silent drop. Before the fix the
            # EXECUTE / EXECUTE_STREAM drift gates returned with no wire
            # response, so the caller hung on its own receive until timeout
            # (the original failure mode of the denial case (deleted 2026-07-22; covered by _dispatch_selftest)). author is
            # "remote" (not "system") so the drift gate is exercised in
            # isolation, ahead of the B-018b system_caller check.
            peer = await self._b066_make_test_peer(system_caller=False)
            writer = None
            try:
                client_ctx = self._b066_make_client_ssl_context(peer)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1",
                        self._plexus.network.port,
                        ssl=client_ctx,
                    ),
                    timeout=5.0,
                )
                await _b066_send_msg(writer, MSG_EXECUTE, {
                    "plugin": "TestEventTarget",
                    "method": "get_state",
                    "args": None,
                    "author": "remote",
                    "author_id": "remote",
                    "author_host": peer["spec"].hostname + "-DRIFT",
                    "request_id": "b066-drift-execute",
                })
                msg_type, data = await _b066_recv_msg(reader, timeout=5.0)
                c.expect(msg_type, MSG_ERROR)
                c.expect("anti-spoof" in str(data), True)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                self._b066_cleanup_test_peer(peer)

        # ---- Test 4 — system_caller=True grant + sub-tests -------
        async def body_b_066_system_caller_privilege_grant(c):
            peer = await self._b066_make_test_peer(system_caller=True)
            writer = None
            try:
                client_ctx = self._b066_make_client_ssl_context(peer)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1",
                        self._plexus.network.port,
                        ssl=client_ctx,
                    ),
                    timeout=5.0,
                )

                async def _round_trip(*, author, author_id):
                    await _b066_send_msg(writer, MSG_REQUEST_EVENT, {
                        "topic": "test_b066/echo_author_id",
                        "payload": None,
                        "author": author,
                        "author_id": author_id,
                        "author_host": peer["spec"].hostname,
                        "timestamp": 0.0,
                        "timeout": 5.0,
                    })
                    mt1, d1 = await _b066_recv_msg(reader, timeout=5.0)
                    if mt1 != MSG_STREAM_CHUNK:
                        raise AssertionError(
                            f"expected MSG_STREAM_CHUNK ({MSG_STREAM_CHUNK}), "
                            f"got msg_type={mt1} data={d1!r}"
                        )
                    mt2, _ = await _b066_recv_msg(reader, timeout=5.0)
                    if mt2 != MSG_END_STREAM:
                        raise AssertionError(
                            f"expected MSG_END_STREAM ({MSG_END_STREAM}) "
                            f"trailing the chunk, got msg_type={mt2}"
                        )
                    return d1

                # 4-main — preserved author + pass-through author_id
                result = await _round_trip(
                    author="system", author_id="non-uuid-pass-through"
                )
                if result != {
                    "author": "system",
                    "author_id": "non-uuid-pass-through",
                }:
                    raise AssertionError(
                        f"Test 4-main: expected author='system' + "
                        f"pass-through author_id, got {result!r}"
                    )

                # 4a — privileged peer + author_id matches local UUID
                local_uuid = self.plugin_uuid
                result_4a = await _round_trip(
                    author="system", author_id=local_uuid
                )
                if not (
                    result_4a["author"] == "system"
                    and result_4a["author_id"].startswith("remote-peer:")
                ):
                    raise AssertionError(
                        f"Test 4a (privileged + spoofed UUID): expected "
                        f"author='system' AND author_id startswith "
                        f"'remote-peer:', got {result_4a!r}"
                    )

                # 4b — privileged peer + author_id NOT matching anything
                result_4b = await _round_trip(
                    author="system",
                    author_id="aaaa-bbbb-cccc-dddd-not-a-real-uuid",
                )
                if result_4b != {
                    "author": "system",
                    "author_id": "aaaa-bbbb-cccc-dddd-not-a-real-uuid",
                }:
                    raise AssertionError(
                        f"Test 4b (privileged + non-spoofed): expected "
                        f"author='system' + pass-through author_id, "
                        f"got {result_4b!r}"
                    )
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                self._b066_cleanup_test_peer(peer)


        # -- run_case calls -------------------------------------------
        await rec.run_case(
            "bug.B-066.execute_hostname_drift_errors",
            body_b_066_execute_hostname_drift_errors,
            category=category,
            tags=("bug_repro", "security", "b066"), bug_ids=("B-066",),
            hard_timeout_s=10.0, **kw,
        )
        await rec.run_case(
            "bug.B-066.system_caller_privilege_grant",
            body_b_066_system_caller_privilege_grant,
            category=category,
            tags=("bug_repro", "security", "b066"), bug_ids=("B-066",),
            hard_timeout_s=10.0, **kw,
        )

        # ==============================================================
        # B-090 — inbound request_event_stream must resolve access as the
        # local SUB OWNER, never as the wire-supplied author_id.
        #
        # These drive NetworkManager._RematchRegistry directly with a
        # synthetic PeerIdentity/CallerCtx. No sockets, no subprocess: the
        # bug lives entirely in which uuid reaches find_endpoint, so an
        # in-process cell pins it exactly and runs on every boot.
        #
        # B-090 is a REGRESSION of B-018b, whose guard (_apply_b018b_guard)
        # was removed with the old NetworkManager in the netcore rewrite.
        # The rewrite replaced one global guard with per-path gates and
        # missed the topic-stream path.
        # ==============================================================
        from plexus.netcore.manager import NetworkManager
        from plexus.netcore.types import CallerCtx, PeerIdentity

        b090_reg = NetworkManager._RematchRegistry(self._plexus)
        b090_identity = PeerIdentity("b090-peer", False)

        def _b090_caller(author_id: str):
            return CallerCtx(author="evil-peer", author_id=author_id,
                             author_host="b090-peer",
                             request_uuid=str(uuid.uuid4()))

        async def _b090_sub(c, target_access_name: str) -> tuple:
            """Subscribe TestBugSuite (owner) -> TestEventTarget (target).

            hosts="any" so the sub accepts a remote publisher, which is the
            precondition the bug needs and is also the common default.
            """
            target = self._plexus.plugins.get("TestEventTarget")
            if target is None:
                c.skip("TestEventTarget not loaded")
            topic = f"b090/{target_access_name}"
            sid = await self._plexus.subscribe_event(
                topic, self.plugin_name, self.plugin_uuid,
                target_access_name=target_access_name,
                target_plugin="TestEventTarget",
                target_plugin_uuid=target.plugin_uuid,
                hosts="any",
            )
            return topic, sid, target

        # ---- ATTACK: spoofed author_id must NOT reach a private endpoint
        async def body_b_090_stream_spoof_denied_private(c):
            from plexus.exceptions import RequestException
            topic, sid, target = await _b090_sub(c, "priv_stream")
            try:
                # The spoof: claim to BE the target plugin. Pre-fix this
                # cleared find_endpoint's accessible_by_other_plugins check
                # (core.py:5249, `plugin.plugin_uuid != requester_id`).
                # match= is load-bearing: NoLocalSubException SUBCLASSES
                # RequestException, so a bare expect_exception would also be
                # satisfied by the sub failing to wire up -- a green cell
                # asserting nothing. "not found" is the endpoint-denial text.
                c.expect_exception(RequestException, match="not found")
                async for _ in b090_reg.request_event_stream(
                        topic, {"value": 1}, b090_identity,
                        _b090_caller(target.plugin_uuid)):
                    pass
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- CONTROL: honest caller, accessible target, still works.
        # This is the cell that fails if the fix over-restricts (i.e. if it
        # copies the execute path's `plugin.remote AND ep.remote` gate):
        # TestEventTarget is remote:false and open_stream is remote:false.
        async def body_b_090_stream_honest_caller_allowed(c):
            topic, sid, _target = await _b090_sub(c, "open_stream")
            try:
                items = [x async for x in b090_reg.request_event_stream(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller("not-a-plugin-uuid-0000"))]
                c.expect(len(items), 3)
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- REACHABILITY: priv_stream must actually be streamable, or the
        # denial cell above proves nothing (it would pass identically if the
        # endpoint simply did not exist). Owner == target here, so the
        # self-call escape at core.py:5249 legitimately allows it.
        async def body_b_090_private_reachable_by_owner(c):
            target = self._plexus.plugins.get("TestEventTarget")
            if target is None:
                c.skip("TestEventTarget not loaded")
            topic = "b090/priv_reachable"
            sid = await self._plexus.subscribe_event(
                topic, "TestEventTarget", target.plugin_uuid,
                target_access_name="priv_stream",
                target_plugin="TestEventTarget",
                target_plugin_uuid=target.plugin_uuid,
                hosts="any",
            )
            try:
                items = [x async for x in b090_reg.request_event_stream(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller("not-a-plugin-uuid-0000"))]
                c.expect(len(items), 3)
            finally:
                await self._plexus.unsubscribe_event(sid)

        # ---- PARITY: the non-stream sibling must deny the same spoof the
        # same way, so the stream variant grants no more than request_event.
        async def body_b_090_request_event_parity(c):
            from plexus.exceptions import RequestException
            topic, sid, target = await _b090_sub(c, "priv_stream")
            try:
                # Same reasoning as the attack cell. Measured: request_event denies
                # with the SAME "Endpoint ... not found" text as the stream path,
                # which is itself the parity being asserted -- both variants refuse
                # the spoof the same way, at the same gate.
                c.expect_exception(RequestException, match="not found")
                await b090_reg.request_event(
                    topic, {"value": 1}, b090_identity,
                    _b090_caller(target.plugin_uuid),
                )
            finally:
                await self._plexus.unsubscribe_event(sid)

        for cid, body in (
            ("bug.B-090.stream_spoof_denied_private", body_b_090_stream_spoof_denied_private),
            ("bug.B-090.stream_honest_caller_allowed", body_b_090_stream_honest_caller_allowed),
            ("bug.B-090.private_reachable_by_owner", body_b_090_private_reachable_by_owner),
            ("bug.B-090.request_event_parity", body_b_090_request_event_parity),
        ):
            await rec.run_case(
                cid, body, category=category,
                tags=("regression_guard", "security", "b090"), bug_ids=("B-090",),
                hard_timeout_s=15.0, **kw,
            )


# Populate the sys.modules proxy with the final module globals — see the
# header comment near `_b066_proxy_mod = ...` for the rationale. Placing
# this at the bottom of the file means every module-level symbol defined
# above is visible to pickle's `find_class` resolution.
_b066_proxy_mod.__dict__.update(globals())
