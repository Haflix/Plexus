"""TestRemoteSuite — Phase 5.

Brings up a peer node as a subprocess (plugins_test/_remote_node/run_node.py)
and drives wire-bug repros + cross-node contract tests against it. If
networking is disabled OR the subprocess fails to come up, all cases are
recorded as skip with a clear reason.

Phase 5 cases all declare hosts=["remote"]. The recorder auto-skips a remote
sub-case when remote_available is False (subprocess never came up). The
suite calls _wait_for_subnode_advert() once before iterating cases so the
subnode's subscriptions are advertised to the parent before any
request_event(hosts="remote") fires.

Stage N (PR4) cleanup: legacy B-001 / B-042 / B-028 cases that targeted
the now-removed request_topic / notify_remote API surface have been
deleted. Those bugs are FIXED-BY-CONSTRUCTION (Stage D); structural
canaries in TestBugSuite (`bug.B-001.request_topic_method_gone` etc.)
remain authoritative. The same pass added five positive-guard cases
covering the new request_event / request_event_stream wire path
(remote.request_event.basic / .handler_raises / .timeout_honored,
remote.request_event_stream.basic / .mid_stream_raise).

Cases:
- remote.execute.basic / .remote_false_blocked
- remote.request_event.basic / .handler_raises / .timeout_honored
- remote.request_event_stream.basic / .mid_stream_raise
- remote.B-019 / B-021 / B-025 / B-011_B-012 / B-029 / B-030 / B-027 /
  B-032 / B-033 (skip — fixture wiring TBD)
- remote.B-024.huge_item
- remote.B-020.publish_event_sync_blocks_on_remote (positive regression
  guard after Stage M)
- remote.find_endpoints_by_tag
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from typing import Any, Dict, List, Optional  # noqa: E402

from plexus.utils import Plugin  # noqa: E402
from plexus.decorators import async_log_errors, log_errors  # noqa: E402

from _test_helpers import CaseRecorder  # noqa: E402


SUITE_VERSION = "0.8.2"  # realigned to plugin_config.yml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUBNODE_SCRIPT = REPO_ROOT / "plugins_test" / "_remote_node" / "run_node.py"
SUBNODE_CONFIG = "plugins_test/_remote_node/config.subnode.yml"
# test_application.py probes a free port per run and exports it (before this
# module is imported), so a stale node holding the previous port cannot make the
# next run fail to bind. The literal is only a standalone/smoke fallback.
SUBNODE_PORT_DEFAULT = int(os.environ.get("AIO_TEST_SUBNODE_PORT", 2511))


class TestRemoteSuite(Plugin):
    """Phase 5 suite plugin. See test_suite_plan.md §6 Phase 5."""

    @log_errors
    def on_load(self, *args, **kwargs):
        self._subproc: Optional[subprocess.Popen] = None
        self._ready_file: Optional[str] = None
        self._peer_info: Optional[Dict[str, Any]] = None
        self._remote_available: bool = False

    @async_log_errors
    async def on_enable(self):
        if not getattr(self._plexus, "networking_enabled", False):
            self._logger.info(
                "TestRemoteSuite: networking disabled in main config — "
                "subprocess peer not started; remote cases will skip"
            )
            return
        await self._spawn_subnode()

    @async_log_errors
    async def on_disable(self):
        await self._terminate_subnode()

    async def _wait_for_subnode_advert(self, timeout: float = 5.0) -> bool:
        """Poll until the subnode's exported subs/endpoints are visible to parent.

        Netcore has no advert layer (see the comment below): readiness is the
        subnode being REACHABLE with its directory PULLED, i.e. its exported
        subs/endpoints present in `network.snapshot()`. request_event(
        hosts='remote') falls through to remote dispatch only once route_* can
        find them. Returns True if that state is reached within `timeout`,
        False on timeout or if networking/peer state is missing. (The
        `_advert` in the name is historical; kept to avoid churning callers.)
        """
        if not self._remote_available or not self._peer_info:
            return False
        peer_hostname = self._peer_info.get("hostname")
        if not peer_hostname:
            return False
        network = getattr(self._plexus, "network", None)
        if network is None:
            return False
        # netcore rewrite: there is no advert layer. Readiness = the subnode is REACHABLE
        # and its directory has been PULLED (content_hash present in snapshot()), i.e. its
        # exported subs/endpoints are cached and route_* will find them.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                peer = (network.snapshot().get("peers") or {}).get(peer_hostname)
            except Exception:
                peer = None
            # Wait for the pull to bring the subnode's ACTUAL exported endpoints/subs,
            # not merely a (possibly-empty) snapshot hash — the subnode may pull once
            # before its plugins enable, so content_hash alone races the export.
            routing = (peer or {}).get("routing") or {}
            if peer and peer.get("reachable") and (routing.get("endpoints") or routing.get("subs")):
                return True
            await asyncio.sleep(0.05)
        self._logger.warning(
            "TestRemoteSuite: subnode advert did not appear within %.1fs "
            "(peer=%s) — request_event(hosts='remote') cases may fail",
            timeout, peer_hostname,
        )
        return False

    # ── Step 6: rate-limit control over the wire (topology A) ───────────
    async def _subnode_rl_configure(self, rate_limits) -> dict:
        """Apply (dict) or CLEAR (None) a rate_limits config on the subnode via
        its r_rl_configure control endpoint. The endpoint runs the real Step-4
        parser + rebuild on the subnode; the configuring call itself is admitted
        against the still-empty sideband, so it is never self-throttled."""
        return await self.execute(
            "TestRemoteTarget", "r_rl_configure",
            {"rate_limits": rate_limits}, hosts="remote", timeout=10.0,
        )

    async def _subnode_rl_reset(self) -> None:
        """Clear the subnode's rate-limit config (topology-A teardown). The clear
        call is itself an inbound execute charged against the (now dry) bucket, so
        REFILL-WAIT first: all topology-A cases use window=2.0, and ~2.2s refills
        any drained Nodes-IN / Framework-IN bucket fully so the clear is admitted.
        Best-effort + idempotent (the subnode dies at suite end regardless)."""
        await asyncio.sleep(2.2)
        try:
            await self._subnode_rl_configure(None)
        except Exception as e:
            self._logger.warning("TestRemoteSuite: subnode rl reset failed: %s", e)

    async def _spawn_subnode(self) -> None:
        """Spawn the peer subprocess and wait for the ready-file."""
        # Prepared OUTSIDE the try below on purpose: everything inside it is
        # swallowed into a warning that leaves _remote_available False, which
        # turns all 40 remote cases into skips while the gate still exits 0. A
        # log-directory problem must not be able to silently disable the remote
        # suite, so it is allowed to raise here instead.
        log_path = REPO_ROOT / "test_outputs" / "subnode.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmp_dir = Path(tempfile.gettempdir()) / "aio_test_subnode"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            self._ready_file = str(tmp_dir / f"ready_{os.getpid()}.json")
            if os.path.exists(self._ready_file):
                os.remove(self._ready_file)

            # PR4 Stage K (B-066): forward mTLS provisioning to subnode.
            # test_application.py pre-generated parent + subnode keypairs
            # and stashed them in env vars; pass them as flags to run_node.py.
            sub_keys_dir = os.environ.get("AIO_TEST_SUB_KEYS_DIR")
            parent_cert_pem_file = os.environ.get("AIO_TEST_PARENT_CERT_PEM_FILE")
            parent_hostname = os.environ.get("AIO_TEST_PARENT_HOSTNAME", "aio-test-parent")
            parent_port = os.environ.get("AIO_TEST_PARENT_PORT", "2510")

            cmd = [
                sys.executable,
                str(SUBNODE_SCRIPT),
                "--config", SUBNODE_CONFIG,
                "--port", str(SUBNODE_PORT_DEFAULT),
                "--ready-file", self._ready_file,
            ]
            if sub_keys_dir and parent_cert_pem_file:
                cmd.extend([
                    "--keys-dir", sub_keys_dir,
                    "--parent-cert-pem-file", parent_cert_pem_file,
                    "--parent-hostname", parent_hostname,
                    "--parent-port", parent_port,
                ])
            else:
                self._logger.warning(
                    "TestRemoteSuite: AIO_TEST_SUB_KEYS_DIR or "
                    "AIO_TEST_PARENT_CERT_PEM_FILE missing from env; subnode "
                    "will start with empty peers and fail at NetworkManager.start()"
                )
            self._logger.info(f"TestRemoteSuite: spawning subnode: {cmd}")
            child_env = dict(os.environ)
            # The subnode is a full Plexus node and logs continuously. Piping its
            # stdout/stderr without draining them deadlocks the child once the
            # ~64KB pipe buffer fills, and leaks the pipe handles per boot. Send
            # both streams to a log file instead (same shape as the multinode
            # harness) so the output stays inspectable without a reader task.
            # The `with` block closes the parent's handle as soon as Popen
            # returns OR raises, so no handle can leak on any path. That is safe
            # because Popen gives the child an inheritable DUPLICATE of the
            # handle, which is unaffected by the parent closing its own copy.
            with open(log_path, "w", encoding="utf-8") as logf:
                self._subproc = subprocess.Popen(
                    cmd,
                    cwd=str(REPO_ROOT),
                    stdin=subprocess.DEVNULL,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    env=child_env,
                )

            deadline = time.perf_counter() + 15.0
            while time.perf_counter() < deadline:
                if os.path.exists(self._ready_file):
                    try:
                        self._peer_info = json.loads(
                            Path(self._ready_file).read_text()
                        )
                        self._remote_available = True
                        self._logger.info(
                            f"TestRemoteSuite: peer up: {self._peer_info}"
                        )
                        return
                    except Exception:
                        pass
                if self._subproc.poll() is not None:
                    self._logger.warning(
                        f"TestRemoteSuite: subnode exited early "
                        f"(rc={self._subproc.returncode})"
                    )
                    return
                await asyncio.sleep(0.5)
            self._logger.warning(
                "TestRemoteSuite: subnode did not write ready-file within 15s"
            )
        except Exception as e:
            self._logger.warning(f"TestRemoteSuite: subnode spawn failed: {e}")

    async def _terminate_subnode(self) -> None:
        if self._subproc is None:
            return
        try:
            self._subproc.terminate()
            try:
                self._subproc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._subproc.kill()
                self._subproc.wait(timeout=2)
        except Exception:
            pass
        finally:
            self._subproc = None
            if self._ready_file and os.path.exists(self._ready_file):
                try:
                    os.remove(self._ready_file)
                except Exception:
                    pass

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
        rec = CaseRecorder("TestRemoteSuite", SUITE_VERSION, self._plexus)

        kw = dict(
            case_ids_filter=case_ids,
            bug_ids_filter=bug_ids,
            category_filter=category,
            host_filter=host,
            skip_slow=skip_slow,
            allow_destructive=allow_destructive,
            remote_available=self._remote_available,
        )

        await self._enumerate_cases(rec, kw)

        return rec.to_dict()

    # ====================================================================
    # All Phase 5 cases — bodies are stubs that exercise the remote path
    # and rely on remote_available=False auto-skipping when no peer is up.
    # ====================================================================

    async def _enumerate_cases(self, rec: CaseRecorder, kw: Dict) -> None:
        # Guard cell: every other case in this suite is hosts=("remote",), so if
        # the subnode never came up the recorder turns all of them into SKIPS and
        # the runner still exits 0 -- a green gate with zero cross-node coverage.
        # _spawn_subnode reaches that state on three paths that only log a
        # warning: the child exiting early, no ready-file within 15s, and its
        # blanket except. This cell is hosts=("local",) so it can never be
        # auto-skipped, and it FAILS when networking is enabled but no peer
        # arrived, turning a silent 40-case skip into a visible failure.
        async def body_subnode_up(c):
            if not getattr(self._plexus, "networking_enabled", False):
                c.skip("networking disabled in this config — no peer expected")
            c.expect(self._remote_available, True)

        await rec.run_case(
            "remote.subnode.up",
            body_subnode_up,
            hosts=("local",),
            tags=("infra", "regression_guard"),
            **kw,
        )

        peer_host = (
            self._peer_info.get("hostname") if self._peer_info else "test-subnode"
        )
        peer_ip = self._peer_info.get("ip") if self._peer_info else "127.0.0.1"

        # Stage N (PR4): wait once for the subnode's advert to land before
        # iterating cases. Without this, request_event(hosts="remote")
        # cases fired immediately after subnode startup race the advert
        # protocol and intermittently raise "no subscriber matches resolved
        # topic". No-op when remote_available=False.
        await self._wait_for_subnode_advert()

        async def body_remote_open(c):
            r = await self.execute(
                "TestRemoteTarget", "r_open", {"value": "x"},
                hosts=c.hosts,
            )
            c.expect(r, "x")

        async def body_remote_false_blocked(c):
            from plexus.exceptions import RequestException
            c.expect_exception(RequestException, match=r"[Ee]ndpoint.*not found")
            await self.execute(
                "TestRemoteVictim", "r_local_only", {"value": "x"},
                hosts=c.hosts,
            )

        # ── Stage N (PR4): request_event coverage ──────────────────────
        # Five positive-guard cases for the new request_event /
        # request_event_stream wire path. Subnode-side handlers live on
        # TestRemoteTarget (subscribed at runtime in on_enable to four
        # dedicated topics: test/r/req_basic, test/r/req_raise,
        # test/r/req_stream_basic, test/r/req_stream_raise).

        async def body_request_event_basic(c):
            """Happy path: parent → subnode → handler returns dict.
            Verifies payload preservation across the wire."""
            r = await self.request_event(
                "r_request_basic", payload={"v": "x"},
                hosts="remote", timeout=5.0,
            )
            c.expect(r, {"echoed": {"v": "x"}})

        async def body_request_event_handler_raises(c):
            """Remote handler raising ValueError must surface to caller as
            RequestException with the original message preserved."""
            from plexus.exceptions import RequestException
            c.expect_exception(RequestException, match=r"requested-error-marker")
            await self.request_event(
                "r_request_raise", payload={},
                hosts="remote", timeout=5.0,
            )

        async def body_request_event_timeout_honored(c):
            """request_event(timeout=2.0) against a hanging remote handler
            must raise within budget. Peer-side enforcement (Request.
            wait_for_result_async) sends the timeout result back, which
            unblocks the client receive loop. Regression guard for the
            B-028-class concern in the Stage-D-replacement API."""
            from plexus.exceptions import RequestException
            loop = asyncio.get_running_loop()
            start = loop.time()
            raised = False
            try:
                await self.request_event(
                    "r_hang", payload={},
                    hosts="remote", timeout=2.0,
                )
            except RequestException:
                raised = True
            elapsed = loop.time() - start
            if not raised:
                c.set_marker("no_exception")
                raise AssertionError(
                    f"request_event(timeout=2.0) returned without raising "
                    f"after {elapsed:.2f}s — timeout not honored"
                )
            # Budget = 2.0s timeout + 3.0s wire/scheduling slack. If the
            # call returned WAY late, peer-side enforcement is broken.
            if elapsed > 5.0:
                c.set_marker("timeout_too_late")
                raise AssertionError(
                    f"request_event(timeout=2.0) raised after {elapsed:.2f}s "
                    f"(budget 5.0s) — timeout enforcement is too slow"
                )

        async def body_request_event_stream_basic(c):
            """Happy-path streaming: 3 chunks. First chunk arrives wrapped
            in an Event object (LOCKED I); subsequent chunks are raw."""
            from plexus.utils import Event
            chunks = []
            async for chunk in self.request_event_stream(
                "r_request_stream_basic", payload={},
                hosts="remote", timeout=10.0,
            ):
                chunks.append(chunk)
            c.expect(len(chunks), 3)
            if not isinstance(chunks[0], Event):
                c.set_marker("first_chunk_not_event")
                raise AssertionError(
                    f"first chunk should be Event-wrapped per LOCKED I; "
                    f"got {type(chunks[0]).__name__}"
                )
            c.expect(chunks[0].payload, {"chunk": 0})
            c.expect(chunks[1], {"chunk": 1})
            c.expect(chunks[2], {"chunk": 2})

        async def body_request_event_stream_mid_stream_raise(c):
            """Mid-stream handler raise: 2 chunks then RequestException
            with original message preserved. Caller's `async for` exits
            via the exception, not silent termination."""
            from plexus.exceptions import RequestException
            chunks = []
            raised: Optional[BaseException] = None
            try:
                async for chunk in self.request_event_stream(
                    "r_request_stream_raise", payload={},
                    hosts="remote", timeout=10.0,
                ):
                    chunks.append(chunk)
            except RequestException as e:
                raised = e
            if raised is None:
                c.set_marker("no_exception")
                raise AssertionError(
                    f"request_event_stream completed without raising; "
                    f"got {len(chunks)} chunk(s)"
                )
            if "midstream-error-marker" not in str(raised):
                c.set_marker("error_message_lost")
                raise AssertionError(
                    f"RequestException raised but original message lost: "
                    f"{raised!r}"
                )
            # The handler raised ValueError; the wire-error wrap must carry the
            # exception TYPE NAME so the message is not opaque ("ValueError: ..."
            # not just "..."). Asserts the type-name enrichment on the stream
            # path (the `except Exception` branch of _handle_request_event_stream).
            if "ValueError" not in str(raised):
                c.set_marker("error_type_lost")
                raise AssertionError(
                    f"mid-stream error message dropped the exception type: "
                    f"{raised!r}"
                )
            if len(chunks) != 2:
                c.set_marker("chunk_count_wrong")
                raise AssertionError(
                    f"expected 2 chunks before mid-stream raise, "
                    f"got {len(chunks)}"
                )

        async def body_request_event_stream_mid_stream_raise_reqexc(c):
            """Mid-stream handler raise of a RequestException (not a plain
            Exception): 2 chunks then the RequestException reaches the caller
            with its original message preserved. Covers the
            `except RequestException` raw-send branch of
            _handle_request_event_stream — distinct from the ValueError case
            above, which drives the `except Exception` wrap branch."""
            from plexus.exceptions import RequestException
            chunks = []
            raised: Optional[BaseException] = None
            try:
                async for chunk in self.request_event_stream(
                    "r_request_stream_raise_reqexc", payload={},
                    hosts="remote", timeout=10.0,
                ):
                    chunks.append(chunk)
            except RequestException as e:
                raised = e
            if raised is None:
                c.set_marker("no_exception")
                raise AssertionError(
                    f"request_event_stream completed without raising; "
                    f"got {len(chunks)} chunk(s)"
                )
            if "reqexc-midstream-marker" not in str(raised):
                c.set_marker("error_message_lost")
                raise AssertionError(
                    f"RequestException raised but original message lost: "
                    f"{raised!r}"
                )
            if len(chunks) != 2:
                c.set_marker("chunk_count_wrong")
                raise AssertionError(
                    f"expected 2 chunks before mid-stream raise, "
                    f"got {len(chunks)}"
                )

        # ── Wave-1 cross-node gap coverage ────────────────────────────

        async def body_request_event_handler_raises_type(c):
            """TP-17 strengthen: the RequestException surfaced from a remote
            handler raise must preserve the original exception TYPE NAME
            (ValueError), not just the message — mirrors the mid_stream_raise
            type assertion on the stream path."""
            from plexus.exceptions import RequestException
            raised: Optional[BaseException] = None
            try:
                await self.request_event(
                    "r_request_raise", payload={},
                    hosts="remote", timeout=5.0,
                )
            except RequestException as e:
                raised = e
            if raised is None:
                c.set_marker("no_exception")
                raise AssertionError(
                    "request_event did not raise for a raising handler"
                )
            if "requested-error-marker" not in str(raised):
                c.set_marker("error_message_lost")
                raise AssertionError(
                    f"original message lost: {raised!r}"
                )
            if "ValueError" not in str(raised):
                c.set_marker("error_type_lost")
                raise AssertionError(
                    f"surfaced exception dropped the type name: {raised!r}"
                )

        async def body_hosts_explicit_list(c):
            """TP-57: hosts=[explicit list] targeting reaches a LISTED host and
            NOT an all-non-listed list. MULTI-element lists on BOTH arms so the
            list-membership branch of _matches_remote_node is actually reached:
            a single-element list collapses to a bare string in _normalize_hosts
            (helpers/config.py) and would only exercise scalar-hostname matching
            (identical to hosts=peer_host, already covered elsewhere). peer_host
            is the resolved subnode hostname."""
            from plexus.exceptions import RequestException
            # Positive: peer_host is ONE OF a real multi-entry list.
            r = await self.execute(
                "TestRemoteTarget", "r_open", {"value": "x"},
                hosts=[peer_host, "decoy-host-a"],
            )
            c.expect(r, "x")
            # Control: a real list of hosts, NONE of which is the peer, must NOT
            # reach the endpoint (proves the list branch, not just a bare miss).
            raised: Optional[BaseException] = None
            try:
                await self.execute(
                    "TestRemoteTarget", "r_open", {"value": "x"},
                    hosts=["decoy-host-a", "decoy-host-b"], timeout=10.0,
                )
            except RequestException as e:
                raised = e
            if raised is None:
                c.set_marker("control_reached")
                raise AssertionError(
                    "hosts=[non-matching list] unexpectedly resolved to a live "
                    "endpoint"
                )

        async def body_execute_uuid_targeted(c):
            """TP-52a (happy path only): discover the subnode TestRemoteTarget
            instance's plugin_uuid (via find_endpoints_by_tag), then execute
            targeting that uuid reaches it and returns its value — i.e. supplying
            a valid plugin_uuid does not BREAK cross-node execute. NOTE: only one
            remote instance exists here, so this does NOT prove uuid SELECTIVITY
            (a broken/ignored uuid would still resolve by name+host to the sole
            instance). Selectivity is the deferred TP-52b negative (a same-name
            different-uuid peer must return NO_ENDPOINT), a rewrite-only guarantee
            built in the wave-2 socket harness."""
            res = await self._plexus.find_endpoints_by_tag("r_probe")
            entry = next(
                (e for e in res if e.get("access_name") == "r_open"), None
            )
            if entry is None:
                raise AssertionError(f"r_open not discovered: {res}")
            remote_instances = [
                i for i in entry["instances"] if i["host"] != "local"
            ]
            if not remote_instances:
                raise AssertionError(
                    f"no remote instance: {entry['instances']}"
                )
            target_uuid = remote_instances[0]["plugin_uuid"]
            r = await self.execute(
                "TestRemoteTarget", "r_open", {"value": "uuidtarget"},
                plugin_uuid=target_uuid, hosts=c.hosts,
            )
            c.expect(r, "uuidtarget")

        async def body_execute_huge_unary_result(c):
            """TP-13: a large (6 MB) UNARY execute result round-trips byte-exact.
            The unary result path splits the serialized value across CHUNK frames
            (parity with execute_stream) and reassembles it. 6 MB (96 chunks) is
            a genuine multi-chunk value UNDER the 8 MB per-cid reassembly bound —
            the OVER-bound rejection is covered separately by TP-73/TG-24 + the
            netcore wire/transport self-tests."""
            r = await self.execute(
                "TestRemoteTarget", "r_huge_result", {},
                hosts=c.hosts, timeout=30.0,
            )
            expected_size = 6 * 1024 * 1024  # large multi-chunk value, under the 8MB per-cid bound
            if not isinstance(r, dict) or "data" not in r:
                raise AssertionError(
                    f"expected dict with 'data', got {type(r).__name__}"
                )
            if len(r["data"]) != expected_size:
                raise AssertionError(
                    f"huge unary result corrupted: got {len(r['data'])} "
                    f"bytes, expected {expected_size}"
                )
            # FULL byte-exact verification (single linear scan, no second
            # buffer): every byte must be the 0xab fill, so an interior
            # corruption that preserves total length is still caught.
            if r["data"].count(0xAB) != expected_size:
                raise AssertionError(
                    "huge unary result not byte-exact: "
                    f"{r['data'].count(0xAB)}/{expected_size} bytes are 0xab "
                    "(interior corruption despite correct length)"
                )

        async def body_publish_event_per_peer_order(c):
            """TP-16 (B-019): per-peer publish ORDER preserved. Publish N events
            in order to the peer, then read the recorded order back — must
            match with no reorder."""
            await self.execute(
                "TestRemoteTarget", "r_reset_order", {}, hosts=c.hosts,
            )
            n = 10
            for k in range(n):
                await self.publish_event(
                    "r_order", payload={"i": k}, hosts="remote",
                )
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5.0
            recorded: List[Any] = []
            while loop.time() < deadline:
                recorded = await self.execute(
                    "TestRemoteTarget", "r_read_order", {}, hosts=c.hosts,
                )
                if len(recorded) >= n:
                    break
                await asyncio.sleep(0.05)
            c.expect(len(recorded), n)
            order = [p.get("i") for p in recorded]
            c.expect(order, list(range(n)))

        async def body_request_event_stream_empty(c):
            """TP-12: an empty successful stream → clean close, ZERO items.
            Control: a 1-item stream yields exactly 1."""
            chunks: List[Any] = []
            async for chunk in self.request_event_stream(
                "r_req_stream_empty", payload={},
                hosts="remote", timeout=10.0,
            ):
                chunks.append(chunk)
            c.expect(len(chunks), 0)
            control: List[Any] = []
            async for chunk in self.request_event_stream(
                "r_req_stream_one", payload={},
                hosts="remote", timeout=10.0,
            ):
                control.append(chunk)
            c.expect(len(control), 1)

        async def body_request_event_stream_timeout_type(c):
            """TG-11 (B-045): a remote stream that hangs after the first chunk
            must surface the idle/chunk-deadline TIMEOUT as RequestException /
            NetworkRequestException, NOT a raw asyncio.TimeoutError."""
            from plexus.exceptions import RequestException
            chunks: List[Any] = []
            raised: Optional[BaseException] = None
            try:
                async for chunk in self.request_event_stream(
                    "r_req_stream_hang", payload={},
                    hosts="remote", timeout=2.0,
                ):
                    chunks.append(chunk)
            except BaseException as e:
                raised = e
            if raised is None:
                c.set_marker("no_exception")
                raise AssertionError(
                    f"hung stream did not raise; got {len(chunks)} chunk(s)"
                )
            if isinstance(raised, asyncio.TimeoutError):
                c.set_marker("raw_timeout_error")
                raise AssertionError(
                    f"stream timeout surfaced as raw asyncio.TimeoutError, "
                    f"not RequestException: {raised!r}"
                )
            if not isinstance(raised, RequestException):
                c.set_marker("wrong_exc_type")
                raise AssertionError(
                    f"stream timeout surfaced as {type(raised).__name__}, "
                    f"expected RequestException: {raised!r}"
                )
            if len(chunks) != 1:
                c.set_marker("chunk_count_wrong")
                raise AssertionError(
                    f"expected 1 chunk before the hang, got {len(chunks)}"
                )


        # B-018 spoof cases retired 2026-06-14: the spoofer harness was removed
        # in PR3 Stage D so these were permanent skips.
        #
        # Citation updated 2026-07-22: this used to point at the B-066 suite
        # and bug.B-018b.uuid_spoof_denied_local_endpoint, both of which have
        # since been deleted (they were silently skipping). B-018b is now
        # covered by bug.B-091.execute_private_endpoint_denied (the author_id
        # spoof proper), .execute_nonremote_plugin_denied and
        # .execute_uuid_spoof_denied in TestBugSuite.

        async def body_b019_count_per_node(c):
            # TP-04 (B-019): publish_event's scheduled-count must be per matching
            # SUBSCRIPTION, not per node. RELOCATED to the multinode harness. This
            # case needs the parent to KNOW the subnode's test/r/multi subs to fan
            # out to them (a directory-propagation dependency), but the in-process
            # subnode topology here routes remote traffic via on-demand endpoint
            # probes / node-broadcast, so the directory is empty at this point.
            # Per-sub fan-out count over the wire is exactly the
            # directory-propagation class the multinode harness owns (cf. B-082).
            c.skip(
                "TP-04/B-019 per-sub fan-out count is directory-propagation "
                "dependent; the in-process-subnode topology's directory is empty "
                "here (probe-based routing) — relocated to "
                "plugins_test/networking_multinode/."
            )

        async def body_b021_first_sub_not_remote_eligible(c):
            c.skip(
                "B-021 needs paired subs on the peer where the first registered "
                "is remote=False — wiring TBD"
            )

        async def body_b024_huge_item(c):
            # B-024 (FIXED, positive round-trip guard): a single yielded stream
            # item larger than one CHUNK is SPLIT across CHUNK frames and
            # reassembled at the ITEM_END boundary (parity with execute_stream).
            # B-024 was that the request_event_stream path did NOT split, killing
            # the stream on a large item. This item is 6 MB (96 chunks): a genuine
            # multi-chunk value UNDER the 8 MB per-cid reassembly bound, so it must
            # arrive intact. (The OVER-bound rejection is covered by TP-73/TG-24 +
            # the netcore self-tests.) Fails on revert (stream aborts).
            from plexus.utils import Event
            items = []
            async for chunk in self.request_event_stream(
                "r_huge_stream", hosts=c.hosts,
            ):
                items.append(chunk)
            c.expect(len(items), 1)
            # First (and only) item is Event-wrapped per LOCKED I.
            first = items[0]
            payload = first.payload if isinstance(first, Event) else first
            expected_size = 6 * 1024 * 1024  # large multi-chunk item, under the 8MB per-cid bound
            if not isinstance(payload, dict) or "data" not in payload:
                raise AssertionError(
                    f"B-024: expected dict with 'data', got "
                    f"{type(payload).__name__}"
                )
            if len(payload["data"]) != expected_size:
                raise AssertionError(
                    f"B-024: huge item corrupted: got {len(payload['data'])} "
                    f"bytes, expected {expected_size}"
                )

        async def body_b025_partial_then_failover(c):
            c.skip(
                "B-025 requires two peer nodes with same handler — Phase 5 "
                "scaffold only spawns one subnode; multi-peer TBD"
            )

        async def body_b011_b012_stream_error_sentinel(c):
            c.skip(
                "B-011 / B-012 require the server to emit __STREAM_ERROR__ "
                "sentinels — fixture for the unpicklable-payload trigger TBD"
            )

        async def body_b029_code_driven_timeout_ignored(c):
            # TG-12 (B-029): a request_event to a slow remote handler with a
            # timeout must CANCEL the callee handler on expiry (no leak).
            # RELOCATED to plugins_test/networking_multinode (TG-12.callee_cancel
            # _on_timeout, MultinodeDriver). request_event ROUTED BY TOPIC to a
            # remote handler needs the parent's directory to hold the subnode's
            # exported sub; in the in-process-subnode topology here that pull
            # races, so the request falls through to a no-match instead of
            # reaching the slow handler. Same directory-propagation class the
            # real-socket multinode harness owns.
            c.skip(
                "TG-12/B-029 callee-cancel-on-timeout needs request_event-by-topic "
                "to reach a remote handler, which is directory-propagation "
                "dependent and races in the in-process-subnode topology — "
                "relocated to the networking_multinode socket harness."
            )

        async def body_b030_unpicklable_args(c):
            # TG-13 (B-030): a cross-node execute carrying an UNPICKLABLE arg
            # (a lambda) must raise (NetworkRequestException / RequestException),
            # never be silently lost. The arg is serialized before the wire
            # send, so the serialize-fail surfaces to the caller.
            from plexus.exceptions import RequestException
            raised: Optional[BaseException] = None
            try:
                await self.execute(
                    "TestRemoteTarget", "r_open", {"value": (lambda: 1)},
                    hosts=c.hosts, timeout=10.0,
                )
            except RequestException as e:
                raised = e
            if raised is None:
                c.set_marker("no_exception")
                raise AssertionError(
                    "cross-node execute with an unpicklable (lambda) arg did "
                    "not raise — the arg was silently lost"
                )

        async def body_b027_publish_event_return_count(c):
            c.skip(
                "B-027 needs to inject a transport failure on "
                "publish_event_remote — fixture TBD"
            )

        async def body_b032_head_of_line_blocking(c):
            c.skip(
                "B-032 requires a slow peer-side handler + a fast call on the "
                "same pooled connection — fixture wiring TBD"
            )

        async def body_b033_sync_stream_host_remote(c):
            c.skip(
                "B-033 (sync request_event_stream silently routing local) is "
                "covered as Phase 3 skip; remote variant duplicate"
            )

        async def body_b020_publish_event_sync_blocks_on_remote(c):
            await c.assert_hang(
                asyncio.to_thread(self.publish_event_sync, "r_hang"),
                timeout_s=2.0,
                marker="outer_wait_for_fired",
            )

        async def body_find_endpoints_by_tag(c):
            # Unmatched tag -> empty list (never None).
            r = await self._plexus.find_endpoints_by_tag("nonexistent")
            assert isinstance(r, list)
            assert r == []

            # TestRemoteTarget.r_open on the subnode is tagged "r_probe".
            # Discover it over the wire and assert the merged entry shape.
            res = await self._plexus.find_endpoints_by_tag("r_probe")
            assert isinstance(res, list)
            entry = next(
                (e for e in res if e.get("access_name") == "r_open"), None
            )
            assert entry is not None, f"r_open not discovered remotely: {res}"
            assert entry["plugin_name"] == "TestRemoteTarget"
            assert isinstance(entry["endpoint"], dict)
            assert "plugin_version" in entry
            # remote-eligibility recoverable from the endpoint dict
            assert entry["endpoint"].get("remote") is True
            # the subnode shows up as a non-local host with a real uuid
            remote_instances = [
                i for i in entry["instances"] if i["host"] != "local"
            ]
            assert remote_instances, f"no remote instance: {entry['instances']}"
            assert all(i.get("plugin_uuid") for i in remote_instances)
            peer_host = self._peer_info["hostname"]
            assert peer_host in entry["hosts"], (peer_host, entry["hosts"])

        # ── Step 6: rate-limit two-node throttle (topology A) ───────────
        # The subnode is the RECEIVER; the parent fires N+1 remote ops and the
        # (N+1)th is rejected by the subnode's limiter, surfacing to the parent's
        # own call as a RateLimitException-derived RequestException. Per-case the
        # subnode limit is injected via r_rl_configure (no static config that
        # would throttle the other ~30 remote cases) and cleared (refill-wait) in
        # finally. window=2.0 (>> the sub-second probe) so no mid-probe refill.
        from plexus.exceptions import RequestException as _ReqExc

        async def body_rl_nodes_in_throttle(c):
            # nodes_in(default=3): probes 1-3 admit, the 4th is rejected on the
            # subnode's Nodes-IN(parent) bucket; the throttle round-trips the wire.
            await self._subnode_rl_configure(
                {"nodes_in": {"default": {"max": 3, "window": 2}}}
            )
            try:
                oks, throttled = 0, False
                for _ in range(4):
                    try:
                        await self.execute(
                            "TestRemoteTarget", "r_open", {"value": "x"},
                            hosts="remote", timeout=10.0,
                        )
                        oks += 1
                    except _ReqExc as e:
                        if "rate limit" in str(e).lower():
                            throttled = True
                            break
                        raise
                if oks != 3 or not throttled:
                    raise AssertionError(
                        f"nodes_in(default=3): expected 3 admits then a rate-limit "
                        f"reject over the wire; oks={oks} throttled={throttled}"
                    )
            finally:
                await self._subnode_rl_reset()

        async def body_rl_execute_framework_in_once(c):
            # framework_in(max=3), NO nodes_in. A remote execute charges
            # Framework-IN exactly ONCE via the subnode's re-entry (the execute
            # handler passes include_framework=False). max=3 is LOAD-BEARING: with
            # 4 probes, single-charge rejects on call 4; a double-charge (2
            # tokens/call) would reject on call 2. Distinguishable only at max=3.
            await self._subnode_rl_configure(
                {"framework_in": {"max": 3, "window": 2}}
            )
            try:
                oks, throttled = 0, False
                for _ in range(4):
                    try:
                        await self.execute(
                            "TestRemoteTarget", "r_open", {"value": "x"},
                            hosts="remote", timeout=10.0,
                        )
                        oks += 1
                    except _ReqExc as e:
                        if "rate limit" in str(e).lower():
                            throttled = True
                            break
                        raise
                if oks != 3 or not throttled:
                    raise AssertionError(
                        f"framework_in(max=3) must admit exactly 3 remote executes "
                        f"then reject the 4th (proves Framework-IN charged ONCE per "
                        f"remote execute via re-entry); oks={oks} throttled={throttled}"
                    )
            finally:
                await self._subnode_rl_reset()

        def _fw_charged(stats):
            from plexus.ratelimiter import DIM_FRAMEWORK_IN, FRAMEWORK_IN_KEY
            for r in (stats or []):
                if r.get("dim") == DIM_FRAMEWORK_IN and r.get("key") == FRAMEWORK_IN_KEY:
                    return r.get("charged", 0)
            return 0

        async def body_rl_event_framework_in(c):
            # Remote-event Framework-IN carve-out (Step 3e) proven by COUNTING the
            # subnode's Framework-IN charges, NOT by throttle timing: a remote
            # request_event must charge Framework-IN EXACTLY ONCE. publish_event's
            # reject is silent post-Step-5 and its readback would compete for the
            # same bucket, so request_event is the observable path. A generous
            # framework_in (no throttle) sidesteps the teardown-throttle trap; the
            # r_rl_stats readback execute itself charges Framework-IN once (proven
            # deterministic by the execute_framework_in_once case), so the final
            # read's own +1 is subtracted.
            await self._subnode_rl_configure(
                {"framework_in": {"max": 100000, "window": 1000}}
            )
            try:
                s0 = await self.execute(
                    "TestRemoteTarget", "r_rl_stats", {}, hosts="remote", timeout=10.0,
                )
                fw0 = _fw_charged(s0)
                for _ in range(3):
                    await self.request_event(
                        "r_request_basic", payload={"v": "x"},
                        hosts="remote", timeout=10.0,
                    )
                s1 = await self.execute(
                    "TestRemoteTarget", "r_rl_stats", {}, hosts="remote", timeout=10.0,
                )
                fw1 = _fw_charged(s1)
                # delta = 3 request_events + 1 (the s1 read execute's own charge).
                event_charges = (fw1 - fw0) - 1
                if event_charges != 3:
                    raise AssertionError(
                        f"3 remote request_events must charge Framework-IN exactly "
                        f"3 times (once each -- the carve-out); got {event_charges} "
                        f"(fw0={fw0} fw1={fw1})"
                    )
            finally:
                await self._subnode_rl_reset()

        async def body_rl_execute_stream_nodes_in(c):
            # _handle_execute_stream charges Nodes-IN with its OWN admit + a
            # reject-BEFORE-first-chunk path (no e2e coverage before Step 6).
            # nodes_in(default=3): 3 stream opens admit + yield; the 4th open is
            # rejected before any chunk -> the async-for raises.
            await self._subnode_rl_configure(
                {"nodes_in": {"default": {"max": 3, "window": 2}}}
            )
            try:
                opens, throttled = 0, False
                for _ in range(4):
                    try:
                        chunks = []
                        async for x in self.execute_stream(
                            "TestRemoteTarget", "r_async_gen", {"n": 2},
                            hosts="remote",
                        ):
                            chunks.append(x)
                        opens += 1
                    except _ReqExc as e:
                        if "rate limit" in str(e).lower():
                            throttled = True
                            break
                        raise
                if opens != 3 or not throttled:
                    raise AssertionError(
                        f"nodes_in(default=3): expected 3 remote stream opens then "
                        f"a reject-before-first-chunk on the 4th; opens={opens} "
                        f"throttled={throttled}"
                    )
            finally:
                await self._subnode_rl_reset()

        # Run all cases in order (each declares hosts=("remote",); recorder
        # auto-skips when remote_available=False).
        cases = [
            ("remote.ratelimit.nodes_in_throttle", body_rl_nodes_in_throttle,
             ("ratelimit", "slow"), ()),
            ("remote.ratelimit.execute_framework_in_once",
             body_rl_execute_framework_in_once, ("ratelimit", "slow"), ()),
            ("remote.ratelimit.event_framework_in", body_rl_event_framework_in,
             ("ratelimit", "slow"), ()),
            ("remote.ratelimit.execute_stream_nodes_in",
             body_rl_execute_stream_nodes_in, ("ratelimit", "slow"), ()),
            ("remote.execute.basic", body_remote_open, ("basic",), ()),
            ("remote.execute.remote_false_blocked",
             body_remote_false_blocked, ("access",), ()),
            # Stage N (PR4) — request_event coverage
            ("remote.request_event.basic",
             body_request_event_basic,
             ("basic", "request_event"), ()),
            ("remote.request_event.handler_raises",
             body_request_event_handler_raises,
             ("basic", "request_event"), ()),
            ("remote.request_event.timeout_honored",
             body_request_event_timeout_honored,
             ("basic", "request_event", "regression_guard"), ()),
            ("remote.request_event_stream.basic",
             body_request_event_stream_basic,
             ("basic", "request_event_stream"), ()),
            ("remote.request_event_stream.mid_stream_raise",
             body_request_event_stream_mid_stream_raise,
             ("basic", "request_event_stream", "regression_guard"), ()),
            ("remote.request_event_stream.mid_stream_raise_reqexc",
             body_request_event_stream_mid_stream_raise_reqexc,
             ("basic", "request_event_stream", "regression_guard"), ()),
            # ── Wave-1 cross-node gap coverage ────────────────────────
            # TP-17 — exception TYPE fidelity on the unary request_event path
            ("remote.request_event.handler_raises_type",
             body_request_event_handler_raises_type,
             ("basic", "request_event", "regression_guard"), ()),
            # TP-57 — hosts=[explicit list] targeting + non-listed control
            ("remote.hosts_explicit_list", body_hosts_explicit_list,
             ("access", "regression_guard"), ()),
            # TP-52a — uuid-targeted cross-node execute reaches the instance
            ("remote.execute.uuid_targeted", body_execute_uuid_targeted,
             ("basic", "discovery"), ()),
            # TP-13 — large (6MB, multi-chunk, under-bound) unary execute result byte-exact
            ("remote.execute.huge_unary_result",
             body_execute_huge_unary_result,
             ("basic", "regression_guard", "slow"), ("B-024",)),
            # TP-16 — per-peer publish_event ORDER preserved
            ("remote.publish_event.per_peer_order",
             body_publish_event_per_peer_order,
             ("basic", "request_event"), ("B-019",)),
            # TP-12 — empty stream clean close (+ 1-item control)
            ("remote.request_event_stream.empty",
             body_request_event_stream_empty,
             ("basic", "request_event_stream"), ()),
            # TG-11 — remote stream timeout surfaces as RequestException
            ("remote.request_event_stream.timeout_type",
             body_request_event_stream_timeout_type,
             ("basic", "request_event_stream", "regression_guard", "slow"),
             ("B-045",)),
            ("remote.B-024.huge_item", body_b024_huge_item,
             ("request_event_stream", "regression_guard", "slow"), ("B-024",)),
            # End Stage N additions
            ("remote.B-019.publish_event_count_per_node_not_per_sub",
             body_b019_count_per_node,
             ("bug_repro",), ("B-019",)),
            ("remote.B-021.first_sub_not_remote_eligible",
             body_b021_first_sub_not_remote_eligible,
             ("bug_repro",), ("B-021",)),
            ("remote.B-025.partial_then_failover",
             body_b025_partial_then_failover,
             ("bug_repro",), ("B-025",)),
            ("remote.B-011_B-012.stream_error_sentinel",
             body_b011_b012_stream_error_sentinel,
             ("bug_repro",), ("B-011", "B-012")),
            ("remote.B-029.code_driven_timeout_ignored",
             body_b029_code_driven_timeout_ignored,
             ("bug_repro",), ("B-029",)),
            ("remote.B-030.unpicklable_args",
             body_b030_unpicklable_args,
             ("bug_repro",), ("B-030",)),
            ("remote.B-027.publish_event_return_count_misleading",
             body_b027_publish_event_return_count,
             ("bug_repro",), ("B-027",)),
            ("remote.B-032.head_of_line_blocking",
             body_b032_head_of_line_blocking,
             ("bug_repro", "slow"), ("B-032",)),
            ("remote.B-033.request_event_stream_sync_host_remote",
             body_b033_sync_stream_host_remote,
             ("bug_repro",), ("B-033",)),
            ("remote.B-020.publish_event_sync_blocks_on_remote",
             body_b020_publish_event_sync_blocks_on_remote,
             ("bug_repro", "regression_guard"), ("B-020",)),
            ("remote.find_endpoints_by_tag", body_find_endpoints_by_tag,
             ("discovery", "basic"), ()),
        ]

        for case_id, body, tags, bug_ids in cases:
            extra: Dict[str, Any] = {}
            if "bug_repro" in tags:
                # Bug-repro cases that drive a bug need expected_status="fail"
                # with a signature; cases that skip via c.skip(...) don't need
                # wiring. (B-024 was here as an xfail asserting the huge-item
                # abort; it is now FIXED and registered as a positive
                # regression_guard, so no wiring.) Other bug_repro cases skip
                # via c.skip(...) inside the body.
                pass
            case_hard_timeout = 30.0
            await rec.run_case(
                case_id, body,
                hosts=("remote",),
                tags=tags, bug_ids=bug_ids,
                hard_timeout_s=case_hard_timeout,
                **extra,
                **kw,
            )
