"""Black-box tests derived only from docs/specs/controller-ha.md.

All credentials, hosts, HTTP workers and durable executor state are disposable
fixtures.  Executor probes run in separate processes to exercise real restarts.
"""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import html.parser
import http.client
import http.server
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse


HERE = Path(__file__).resolve().parent
BUILD = "fixture-build"
IDENTITY = "controller-a"


class FixtureConsul:
    """Authenticated authority stand-in; it grants only the fixture's tuple."""

    def __init__(self, state_path):
        self.state_path = Path(state_path)

    def authority(self, node, epoch, session):
        record = json.loads(self.state_path.read_text())
        if (node, epoch, session) != (
            record["holder"],
            record["epoch"],
            record["session"],
        ):
            raise RuntimeError("fixture quorum rejected authority")
        return record


HELPER = r'''#!/usr/bin/env python3
import base64, json, os, sys, time
from pathlib import Path
root = Path(__file__).resolve().parent
request = json.loads(sys.stdin.read())
mode = (root / "mode").read_text().strip()
def event(kind):
    with (root / "calls.jsonl").open("a") as out:
        out.write(json.dumps({"kind": kind, "pid": os.getpid(),
                              "argv": sys.argv[1:], "request": request}) + "\n")
        out.flush()
        os.fsync(out.fileno())
event("start")
if mode == "slow":
    time.sleep(2)
else:
    time.sleep(0.08)
if mode == "crash":
    os._exit(23)
event("end")
if mode == "malformed":
    print("not-json")
elif mode == "error":
    print(json.dumps({"ok": False, "stdout_b64": "", "error": "ambiguous fixture dispatch"}))
elif mode == "badbase64":
    print(json.dumps({"ok": True, "stdout_b64": "!!!"}))
elif mode == "missingstdout":
    print(json.dumps({"ok": True}))
else:
    print(json.dumps({"ok": True, "stdout_b64": base64.b64encode(b"fixture-result").decode()}))
'''


def transport():
    return {
        "host": "fixture.invalid",
        "user": "root",
        "port": 22,
        "timeout_ms": 5_000,
        "operation": "exec",
        "remote_cmd": "printf fixture",
    }


def execute_request(epoch=1, session="session-1"):
    return {
        "epoch": epoch,
        "session": session,
        "build": BUILD,
        "transport": transport(),
    }


def probe_main():
    spec = json.load(sys.stdin)
    module = importlib.import_module("executor")
    executor = module.Executor(
        spec["root"],
        FixtureConsul(spec["state"]),
        spec["helper"],
        spec["key"],
        BUILD,
    )

    def invoke(item):
        try:
            method = item["method"]
            if method == "status":
                result = executor.status()
            elif method == "second":
                second = module.Executor(
                    spec["root"],
                    FixtureConsul(spec["state"]),
                    spec["helper"],
                    spec["key"],
                    BUILD,
                )
                result = second.status()
            else:
                result = getattr(executor, method)(
                    item.get("identity", IDENTITY), item["request"]
                )
            return {"returned": result}
        except Exception as error:
            return {"raised": type(error).__name__, "message": str(error)}

    if spec.get("parallel"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(invoke, spec["actions"]))
    else:
        results = [invoke(item) for item in spec["actions"]]
    print(json.dumps(results), flush=True)


class ExecutorContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpnctl-ha-spec-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "executor-state"
        self.helper = self.base / "helper"
        self.helper.write_text(HELPER)
        self.helper.chmod(0o700)
        self.key = self.base / "deploy-key"
        self.key.write_text("fixture key bytes only\n")
        self.key.chmod(0o600)
        self.mode = self.base / "mode"
        self.mode.write_text("ok")
        self.state = self.base / "authority.json"
        self.set_authority()

    def set_authority(self, holder=IDENTITY, epoch=1, session="session-1"):
        previous = None if epoch == 1 else {"node_id": IDENTITY, "epoch": epoch - 1}
        record = {
            "holder": holder,
            "node": holder,
            "node_id": holder,
            "epoch": epoch,
            "session": session,
            "previous": previous,
        }
        staging = self.state.with_suffix(".new")
        staging.write_text(json.dumps(record))
        staging.replace(self.state)

    def specification(self, actions, parallel=False):
        return {
            "root": str(self.root),
            "state": str(self.state),
            "helper": str(self.helper),
            "key": str(self.key),
            "actions": actions,
            "parallel": parallel,
        }

    def probe(self, *actions, parallel=False):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--executor-probe"],
            input=json.dumps(self.specification(actions, parallel)),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def events(self):
        path = self.base / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def assert_rejected(self, result):
        self.assertTrue(
            "raised" in result or result.get("returned", {}).get("ok") is False,
            result,
        )

    def assert_uncertain(self, result):
        self.assert_rejected(result)
        status = self.probe({"method": "status"})[0]["returned"]
        self.assertFalse(status["ready"], status)
        self.assertTrue(status["blocked_jobs"], status)
        return status

    def test_success_dispatches_pinned_helper_once_and_survives_restart(self):
        request = execute_request()
        result = self.probe({"method": "execute", "request": request})[0]
        self.assertTrue(result["returned"]["ok"], result)
        self.assertEqual(
            base64.b64decode(result["returned"]["stdout_b64"], validate=True),
            b"fixture-result",
        )
        events = self.events()
        self.assertEqual([event["kind"] for event in events], ["start", "end"])
        self.assertEqual(events[0]["argv"], ["--ha-execute"])
        self.assertEqual(events[0]["request"], request["transport"])
        status = self.probe({"method": "status"})[0]["returned"]
        self.assertTrue(status["ready"], status)
        self.assertEqual(status["blocked_jobs"], [])
        self.assertEqual(len(self.events()), 2, "restart replayed a completed intent")

    def test_authority_and_build_rejection_dispatch_nothing(self):
        requests = [execute_request(epoch=0), execute_request(session="stale-session")]
        mismatched = execute_request()
        mismatched["build"] = "other-fixture-build"
        requests.append(mismatched)
        actions = [{"method": "execute", "request": request} for request in requests]
        actions.append(
            {"method": "execute", "identity": "unrecognized-controller", "request": execute_request()}
        )
        for result in self.probe(*actions):
            self.assert_rejected(result)
        self.assertEqual(self.events(), [])
        status = self.probe({"method": "status"})[0]["returned"]
        self.assertTrue(status["ready"], status)
        self.assertEqual(status["blocked_jobs"], [])

    def test_durable_barrier_denies_old_epoch_after_restart(self):
        first = self.probe({"method": "execute", "request": execute_request()})[0]
        self.assertTrue(first["returned"]["ok"], first)
        self.set_authority("controller-b", 2, "session-2")
        barrier = self.probe(
            {
                "method": "barrier",
                "identity": "controller-b",
                "request": {"epoch": 2, "session": "session-2"},
            }
        )[0]["returned"]
        self.assertEqual(barrier["successor_epoch"], 2)
        self.assertTrue(barrier["external_actions_fenced"], barrier)
        # A stale authority service cannot reopen admission closed by a durable fence.
        self.set_authority()
        denied = self.probe({"method": "execute", "request": execute_request()})[0]
        self.assert_rejected(denied)
        self.assertEqual(len(self.events()), 2)
        status = self.probe({"method": "status"})[0]["returned"]
        self.assertGreaterEqual(status["closed_through"], 1)

    def test_error_or_malformed_helper_is_durable_uncertainty(self):
        for mode in ("crash", "malformed", "error", "badbase64", "missingstdout"):
            with self.subTest(mode=mode):
                self.root = self.base / ("executor-" + mode)
                self.mode.write_text(mode)
                before = len(self.events())
                response = self.probe({"method": "execute", "request": execute_request()})[0]
                status = self.assert_uncertain(response)
                blocked = status["blocked_jobs"]
                self.set_authority("controller-b", 2, "session-2")
                barrier = self.probe(
                    {
                        "method": "barrier",
                        "identity": "controller-b",
                        "request": {"epoch": 2, "session": "session-2"},
                    }
                )[0]
                self.assert_rejected(barrier)
                after = self.probe({"method": "status"})[0]["returned"]
                self.assertEqual(after["blocked_jobs"], blocked)
                starts = [event for event in self.events()[before:] if event["kind"] == "start"]
                self.assertEqual(len(starts), 1, "uncertain intent was replayed")
                self.set_authority()

    def test_executor_crash_preserves_unfinished_intent_without_replay(self):
        self.mode.write_text("slow")
        with (self.base / "probe-output").open("w") as output:
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--executor-probe"],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=output,
                text=True,
            )
            try:
                child.stdin.write(json.dumps(self.specification([
                    {"method": "execute", "request": execute_request()}
                ])))
                child.stdin.close()
                deadline = time.monotonic() + 5
                while not self.events() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(self.events(), "helper was never dispatched")
                child.kill()
                child.wait(timeout=3)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)
        status = self.probe({"method": "status"})[0]["returned"]
        self.assertFalse(status["ready"], status)
        self.assertTrue(status["blocked_jobs"], status)
        self.assertEqual(sum(event["kind"] == "start" for event in self.events()), 1)

    def test_parallel_requests_serialize_helper_dispatch(self):
        actions = [{"method": "execute", "request": execute_request()} for _ in range(4)]
        for result in self.probe(*actions, parallel=True):
            self.assertTrue(result["returned"]["ok"], result)
        self.assertEqual([event["kind"] for event in self.events()], ["start", "end"] * 4)

    def test_live_root_is_exclusively_locked(self):
        result = self.probe({"method": "second"})[0]
        self.assertIn("raised", result, "two executors obtained the same durable root")


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self.current = {"action": attributes.get("action", "/admin/ha"), "fields": {}}
            self.forms.append(self.current)
        elif self.current is not None and tag in ("input", "button"):
            if "name" in attributes:
                self.current["fields"][attributes["name"]] = attributes.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class GatewayContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpnctl-ha-gateway-spec-")
        self.addCleanup(self.temp.cleanup)
        token = Path(self.temp.name) / "admin-token"
        token.write_text("fixture-admin-token\n")
        token.chmod(0o600)
        self.requests = []
        self.actions = []
        self.first_chunk = threading.Event()
        self.finish_stream = threading.Event()
        self.addCleanup(self.finish_stream.set)
        outer = self

        class Upstream(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            do_PUT = do_POST
            do_PATCH = do_POST
            do_DELETE = do_POST
            do_OPTIONS = do_POST
            do_HEAD = do_GET

            def respond(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                outer.requests.append({"method": self.command, "path": self.path,
                                       "headers": dict(self.headers), "body": body})
                if self.path.startswith("/ambiguous"):
                    self.close_connection = True
                    self.connection.shutdown(2)
                    self.connection.close()
                    return
                if self.path.startswith("/stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", "12")
                    self.end_headers()
                    self.wfile.write(b"first\n")
                    self.wfile.flush()
                    outer.first_chunk.set()
                    outer.finish_stream.wait(5)
                    self.wfile.write(b"last!\n")
                    self.wfile.flush()
                    return
                self.send_response(207)
                self.send_header("Set-Cookie", "one=1; Path=/")
                self.send_header("Set-Cookie", "two=2; Path=/")
                self.send_header("Connection", "X-Upstream-Hop")
                self.send_header("X-Upstream-Hop", "remove-me")
                self.send_header("Content-Length", "7")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(b"fixture")

        self.worker = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.worker.daemon_threads = True
        self.worker_thread = threading.Thread(target=self.worker.serve_forever, daemon=True)
        self.worker_thread.start()
        self.addCleanup(self.worker.server_close)
        self.addCleanup(self.worker.shutdown)
        worker_url = "http://127.0.0.1:" + str(self.worker.server_address[1])

        class App:
            config = {
                "node_id": IDENTITY,
                "peers": [IDENTITY, "controller-b"],
                "trusted_proxies": [],
                "admin_token_file": str(token),
            }

            def upstream(self):
                return worker_url, None

            def local_upstream(self):
                return worker_url

            def status(self):
                return {
                    "role": "Follower", "leader": "controller-b", "quorum": True,
                    "generation": "fixture-generation", "snapshot_age_ms": 10,
                    "rpo_ms": 10, "replication_interval_ms": 1000,
                    "max_replica_age_ms": 2000, "fencing_ready": True,
                    "blocked_reason": "fixture blocked reason",
                }

            def action(self, name, target):
                outer.actions.append((name, target))
                return {"ok": True}

        module = importlib.import_module("gateway")
        self.app = App()
        self.gateway = module.Server(("127.0.0.1", 0), self.app)
        self.gateway_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.gateway_thread.start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)
        self.port = self.gateway.server_address[1]
        self.auth = "Basic " + base64.b64encode(b"ha:fixture-admin-token").decode()

    @contextlib.contextmanager
    def connection(self, timeout=3):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            yield connection
        finally:
            connection.close()

    def request(self, method, path, body=None, headers=None):
        with self.connection() as connection:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()

    def test_preserves_raw_uri_status_body_and_all_cookies(self):
        path = "/sub/a%2Fb//c?token=a%2Bb&x=1&x=2&empty=&escaped=%252F"
        status, headers, body = self.request("GET", path)
        self.assertEqual(status, 207)
        self.assertEqual(body, b"fixture")
        self.assertEqual(self.requests[0]["path"], path)
        self.assertEqual([value for key, value in headers if key.lower() == "set-cookie"],
                         ["one=1; Path=/", "two=2; Path=/"])
        self.assertNotIn("x-upstream-hop", {key.lower() for key, _ in headers})

    def test_strips_spoofed_ip_and_connection_nominated_headers(self):
        self.request("POST", "/operation", body=b"fixture-body", headers={
            "Content-Type": "application/octet-stream",
            "Connection": "X-Client-Hop, keep-alive",
            "X-Client-Hop": "remove-me",
            "X-Real-IP": "198.51.100.10",
            "X-Forwarded-For": "198.51.100.11",
            "X-Forwarded-Host": "spoof.invalid",
            "X-Forwarded-Proto": "https",
            "Forwarded": "for=198.51.100.12;host=spoof.invalid",
        })
        forwarded = {key.lower(): value for key, value in self.requests[0]["headers"].items()}
        self.assertEqual(forwarded["x-real-ip"], "127.0.0.1")
        for forbidden in ("x-client-hop", "x-forwarded-for", "x-forwarded-host",
                          "x-forwarded-proto", "forwarded"):
            self.assertNotIn(forbidden, forwarded)
        self.assertEqual(self.requests[0]["body"], b"fixture-body")

    def test_ambiguous_mutation_is_sent_once(self):
        status, _headers, _body = self.request("POST", "/ambiguous", body=b"mutate-once")
        self.assertIn(status, (502, 503))
        self.assertEqual(len(self.requests), 1, "gateway replayed an ambiguous mutation")

    def test_every_application_method_reaches_worker_once(self):
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, _headers, body = self.request(method, "/method?raw=%2f", body=b"fixture-input")
                self.assertEqual(status, 207)
                self.assertEqual(body, b"" if method == "HEAD" else b"fixture")
                self.assertEqual(self.requests[-1]["method"], method)
                self.assertEqual(self.requests[-1]["path"], "/method?raw=%2f")
                self.assertEqual(self.requests[-1]["body"], b"fixture-input")
        self.assertEqual(len(self.requests), 7)

    def test_explicit_trusted_proxy_preserves_verified_client_ip(self):
        self.app.config["trusted_proxies"] = ["127.0.0.0/8"]
        self.request("GET", "/trusted-proxy", headers={
            "X-Real-IP": "198.51.100.27",
            "X-Forwarded-For": "198.51.100.28",
        })
        forwarded = {key.lower(): value for key, value in self.requests[0]["headers"].items()}
        self.assertEqual(forwarded["x-real-ip"], "198.51.100.27")
        self.assertNotIn("x-forwarded-for", forwarded)

    def test_sse_delivers_first_bytes_before_upstream_finishes(self):
        with self.connection(timeout=1.5) as connection:
            connection.request("GET", "/stream")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(self.first_chunk.wait(1))
            try:
                self.assertEqual(response.read(6), b"first\n")
            finally:
                self.finish_stream.set()
            self.assertEqual(response.read(), b"last!\n")

    def admin_form(self):
        status, _headers, _body = self.request("GET", "/admin/ha")
        self.assertEqual(status, 401)
        status, _headers, page = self.request("GET", "/admin/ha", headers={"Authorization": self.auth})
        self.assertEqual(status, 200)
        parser = FormParser()
        parser.feed(page.decode())
        self.assertTrue(parser.forms, "management page exposes no web controls")
        form = parser.forms[0]
        csrf_names = [name for name in form["fields"] if "csrf" in name.lower()]
        self.assertTrue(csrf_names, "management form has no CSRF field")
        headers = {"Authorization": self.auth,
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Origin": "http://127.0.0.1:" + str(self.port)}
        return form, csrf_names, headers

    def test_management_requires_auth_and_csrf(self):
        form, csrf_names, headers = self.admin_form()
        fields = dict(form["fields"])
        for name in csrf_names:
            del fields[name]
        status, _headers, _body = self.request("POST", form["action"], urllib.parse.urlencode(fields), headers)
        self.assertIn(status, (400, 403))
        self.assertEqual(self.actions, [])
        status, _headers, _body = self.request("POST", form["action"], urllib.parse.urlencode(form["fields"]), headers)
        self.assertIn(status, (200, 202, 303))
        self.assertEqual(len(self.actions), 1)
        self.assertEqual(self.requests, [], "management accessed the inventory worker")

    def test_management_rejects_cross_origin_post_with_valid_csrf(self):
        form, _csrf_names, headers = self.admin_form()
        bad_origin = dict(headers, Origin="https://attacker.invalid")
        status, _headers, _body = self.request("POST", form["action"], urllib.parse.urlencode(form["fields"]), bad_origin)
        self.assertIn(status, (400, 403))
        self.assertEqual(self.actions, [])
        self.assertEqual(self.requests, [], "management accessed the inventory worker")


if __name__ == "__main__":
    if sys.argv[1:] == ["--executor-probe"]:
        probe_main()
    else:
        unittest.main()
