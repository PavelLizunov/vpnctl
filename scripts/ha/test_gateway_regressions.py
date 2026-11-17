"""Regression tests for independently reviewed proxy/fencing defects."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest

from gateway import Server


class ReviewedGatewayRegression(unittest.TestCase):
    def test_connection_cannot_remove_request_framing_and_smuggle_trusted_request(self):
        hits = []
        class Worker(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
            def log_message(self, *args): pass
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        class App:
            config = {"peers": [], "trusted_proxies": []}
            def upstream(self): return "http://127.0.0.1:" + str(upstream.server_port), None
        gateway = Server(("127.0.0.1", 0), App())
        for server in (upstream, gateway):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        body = b"POST /smuggled HTTP/1.1\r\nHost: fixture\r\nX-Real-IP: 198.51.100.1\r\nContent-Length: 0\r\n\r\n"
        with socket.create_connection(gateway.server_address, timeout=3) as stream:
            stream.sendall(b"POST /outer HTTP/1.1\r\nHost: fixture\r\nConnection: Content-Length\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            self.assertIn(b"502", stream.recv(4096).split(b"\r\n", 1)[0])
        self.assertEqual(hits, [], "framing-nominated request reached the worker")

    def test_eof_before_header_terminator_never_dispatches_application_request(self):
        calls = []
        class App:
            config = {"peers": [], "trusted_proxies": []}
            def upstream(self):
                calls.append("dispatched")
                raise RuntimeError("must never reach application")
        server = Server(("127.0.0.1", 0), App())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        with socket.create_connection(server.server_address, timeout=3) as stream:
            stream.sendall(b"POST /mutate HTTP/1.1\r\nHost: fixture\r\nContent-Length: 0\r\n")
            stream.shutdown(socket.SHUT_WR)
            self.assertIn(b"400", stream.recv(4096).split(b"\r\n", 1)[0])
        self.assertEqual(calls, [])

    def test_management_form_errors_keep_the_admin_prefix_and_browser_back_link(self):
        from test_spec_runtime import GatewayContract
        fixture = GatewayContract("test_preserves_raw_uri_status_body_and_all_cookies")
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        headers = {"Authorization": fixture.auth, "Content-Type": "application/x-www-form-urlencoded"}
        status, fields, body = fixture.request("POST", "/admin/ha", body=b"csrf=wrong&action=handover", headers=headers)
        self.assertEqual(status, 403)
        self.assertTrue(body.startswith(b"vpnctl admin: ")); self.assertTrue(body.endswith(b"\n"))
        headers["Accept"] = "text/html"
        status, fields, body = fixture.request("POST", "/admin/ha", body=b"csrf=wrong&action=handover", headers=headers)
        self.assertEqual(status, 403)
        self.assertIn(b"<h1>Controller availability</h1>", body)
        self.assertIn(b"vpnctl admin: ", body)
        self.assertIn(b'href="/admin/ha"', body)
        self.assertEqual(fixture.actions, [])

    def test_progress_does_not_renew_the_absolute_header_deadline(self):
        class App:
            config = {"peers": [], "trusted_proxies": []}
        server = Server(("127.0.0.1", 0), App())
        server.header_timeout_seconds = .35
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        stream = socket.create_connection(server.server_address, timeout=2)
        self.addCleanup(stream.close)
        stream.sendall(b"GET / HTTP/1.1\r\nHost: fixture\r\nX-Trickle: ")
        disconnected = threading.Event()
        stop = threading.Event()
        self.addCleanup(stop.set)
        def trickle():
            while not stop.wait(.04):
                try:
                    stream.sendall(b"x")
                except OSError:
                    disconnected.set()
                    return
        feeder = threading.Thread(target=trickle, daemon=True); feeder.start()
        self.assertTrue(disconnected.wait(1.5), "progress kept an incomplete header alive beyond its deadline")
        stop.set(); feeder.join(timeout=1)
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            self.assertEqual(response.status, 503)  # normal request is admitted again
            response.read()
        finally:
            connection.close()

    def test_slow_connections_are_bounded_and_slots_are_reused(self):
        class App:
            config = {"peers": [], "trusted_proxies": []}
        server = Server(("127.0.0.1", 0), App())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        streams = []
        try:
            for _ in range(65):
                stream = socket.create_connection(server.server_address, timeout=3)
                streams.append(stream)
                try:
                    stream.sendall(b"GET / HTTP/1.1\r\nHost: fixture\r\nX-Pending: ")
                except ConnectionResetError:
                    pass
            closed = 0
            for stream in streams:
                stream.settimeout(.03)
                try:
                    if stream.recv(1) == b"": closed += 1
                except ConnectionResetError: closed += 1
                except socket.timeout: pass
            self.assertGreaterEqual(closed, 1, "slow headers exceeded the gateway connection budget")
        finally:
            for stream in streams: stream.close()
        # Releasing incomplete connections must restore admission to the server.
        deadline = time.monotonic() + 3
        while True:
            try:
                connection = http.client.HTTPConnection(*server.server_address, timeout=1)
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertEqual(response.status, 503)  # fixture app has no upstream
                response.read(); connection.close()
                break
            except (ConnectionError, http.client.HTTPException):
                if time.monotonic() >= deadline: raise
                time.sleep(.03)

    def test_two_gateway_sse_survives_idle_time_beyond_connect_timeout(self):
        release = threading.Event()
        class Worker(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"data: first\n\n"); self.wfile.flush()
                release.wait(8)
                self.wfile.write(b"data: after-idle\n\n"); self.wfile.flush()
            def log_message(self, *args): pass
        worker = ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        class App:
            config = {"peers": [], "trusted_proxies": []}
            def __init__(self, upstream): self.url = "http://127.0.0.1:" + str(upstream.server_port)
            def upstream(self): return self.url, None
        leader = Server(("127.0.0.1", 0), App(worker))
        follower = Server(("127.0.0.1", 0), App(leader))
        leader.header_timeout_seconds = .35
        follower.header_timeout_seconds = .35
        for server in (worker, leader, follower):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        self.addCleanup(release.set)
        conn = http.client.HTTPConnection(*follower.server_address, timeout=8)
        self.addCleanup(conn.close)
        conn.request("GET", "/events")
        response = conn.getresponse()
        self.assertEqual(response.fp.readline(), b"data: first\n")
        self.assertEqual(response.fp.readline(), b"\n")
        time.sleep(3.3)
        release.set()
        self.assertEqual(response.fp.readline(), b"data: after-idle\n")


class ExecutorDeadlineRegression(unittest.TestCase):
    def test_pinned_jump_stage_budget_is_not_cut_short_by_single_exec_timeout(self):
        import json
        from pathlib import Path
        import tempfile
        from executor import Executor
        class Consul:
            def authority(self, node, epoch, session):
                return {"holder": node, "epoch": epoch, "session": session, "previous": None}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "helper"
            helper.write_text('#!/usr/bin/env python3\nimport json,sys,time\nfrom pathlib import Path\nr=json.load(sys.stdin)\np=Path(__file__).with_name("dispatches")\np.write_text("one dispatch")\ntime.sleep(6.2)\nprint(json.dumps({"ok":True,"stdout_b64":"ZG9uZQ=="}))\n')
            helper.chmod(0o700)
            executor = Executor(root / "state", Consul(), helper, root / "fixture-key", "fixture-build")
            self.addCleanup(executor.instance_lock.close)
            result = executor.execute("controller-a", {
                "epoch": 1, "session": "fixture-session", "build": "fixture-build",
                "transport": {"timeout_ms": 1000, "jump": {"host": "jump.fixture.invalid"}},
            })
            self.assertTrue(result["ok"], "enclosing helper budget interrupted valid jump preparation")
            self.assertEqual((root / "dispatches").read_text(), "one dispatch")
            self.assertTrue(executor.status()["ready"])
