"""Single-attempt HTTP/1 gateway, including streaming bodies and duplicate cookies."""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import ipaddress
import json
from pathlib import Path
import ssl
import threading
import time
import socket
import urllib.parse

from common import MAX_FRAME, canonical, connection

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "transfer-encoding", "upgrade"}
FORWARDING = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
              "x-real-ip", "x-ssl-ja3", "x-ssl-ja4"}


def connection_tokens(headers):
    nominated = set()
    for value in headers.get_all("Connection", []):
        nominated.update(name.strip().lower() for name in value.split(","))
    return nominated


def stripped(headers):
    return HOP | connection_tokens(headers)


def peer_identity(handler):
    cert = handler.connection.getpeercert()
    names = [value for rdn in cert.get("subject", ()) for key, value in rdn if key == "commonName"]
    if len(names) != 1 or names[0] not in handler.server.allowed_peers:
        raise PermissionError("unrecognized control identity")
    return names[0]


def proxy(handler, upstream, context, client_ip, forwarded=False):
    """No retry, redirect following, URI normalization or whole-response buffering."""
    conn, prefix = connection(upstream, context, timeout=3)
    started = False
    try:
        lengths = handler.headers.get_all("Content-Length", [])
        encodings = handler.headers.get_all("Transfer-Encoding", [])
        if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
            raise ValueError("ambiguous request framing")
        if encodings and encodings[0].lower() != "chunked":
            raise ValueError("unsupported transfer encoding")
        conn.putrequest(handler.command, prefix + handler.path, skip_host=True, skip_accept_encoding=True)
        dropped = stripped(handler.headers) | FORWARDING
        nominated = connection_tokens(handler.headers)
        if nominated & {"content-length", "transfer-encoding", "host"}:
            raise ValueError("Connection cannot nominate request framing or Host")
        for key, value in handler.headers.raw_items():
            if key.lower() not in dropped and not key.lower().startswith("x-vpnctl-ha-"):
                conn.putheader(key, value)
        conn.putheader("X-Real-IP", client_ip)
        if forwarded:
            conn.putheader("X-Vpnctl-Ha-Application", "1")
        chunked = handler.headers.get("Transfer-Encoding", "").lower() == "chunked"
        if chunked:
            # Forward the exact framed request stream once; never parse and replay.
            conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        if chunked:
            while True:
                line = handler.rfile.readline(8193)
                if len(line) > 8192 or not line.endswith(b"\r\n"):
                    raise ValueError("invalid chunk framing")
                count = int(line.split(b";", 1)[0], 16)
                if count < 0 or count > MAX_FRAME:
                    raise ValueError("request chunk too large")
                conn.send(line)
                if count == 0:
                    # Strip trailers: their names can bypass header sanitization.
                    while True:
                        trailer = handler.rfile.readline(8193)
                        if trailer == b"\r\n":
                            break
                        if not trailer or len(trailer) > 8192:
                            raise ValueError("invalid request trailer")
                    conn.send(b"\r\n")
                    break
                remaining = count + 2
                while remaining:
                    data = handler.rfile.read(min(65536, remaining))
                    if not data:
                        raise ValueError("incomplete request body")
                    conn.send(data)
                    remaining -= len(data)
        else:
            remaining = int(handler.headers.get("Content-Length", "0"))
            if remaining < 0:
                raise ValueError("negative request length")
            while remaining:
                data = handler.rfile.read(min(65536, remaining))
                if not data:
                    raise ValueError("incomplete request body")
                conn.send(data)
                remaining -= len(data)
        # Set this before getresponse(): Connection:close responses detach the
        # socket from HTTPConnection while their body continues using it.
        if conn.sock:
            conn.sock.settimeout(None)
        response = conn.getresponse()
        handler.send_response_only(response.status, response.reason)
        dropped = stripped(response.headers)
        body_allowed = handler.command != "HEAD" and response.status not in (204, 304) and response.status >= 200
        for key, value in response.headers.raw_items():
            if key.lower() not in dropped:
                handler.send_header(key, value)
        # Connection close delimits indefinite streams; data is flushed as it arrives.
        handler.send_header("Connection", "close")
        handler.end_headers()
        started = True
        if body_allowed:
            while data := response.read1(65536):
                handler.wfile.write(data)
                handler.wfile.flush()
        handler.close_connection = True
    except Exception:
        handler.close_connection = True
        if not started:
            handler.reply(502, {"error": "upstream outcome unknown; request was not replayed"})
    finally:
        conn.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app, control=False, context=None):
        self.app = app
        self.control = control
        self.allowed_peers = set(app.config["peers"])
        self.connection_slots = threading.BoundedSemaphore(64)
        self.header_timeout_seconds = 15
        super().__init__(address, Handler)
        self.tls_context = context

    def process_request(self, stream, peer):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(stream)
            return
        try:
            super().process_request(stream, peer)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, stream, peer):
        try:
            super().process_request_thread(stream, peer)
        finally:
            self.connection_slots.release()

    def get_request(self):
        stream, peer = super().get_request()
        stream.settimeout(15)
        if self.tls_context:
            stream = self.tls_context.wrap_socket(stream, server_side=True, do_handshake_on_connect=False)
        return stream, peer


class _HeaderBudget:
    def __init__(self, connection, seconds):
        self.connection = connection
        self.deadline = time.monotonic() + seconds
        self.lock = threading.Lock()
        self.admitted = False
        self.expired = False
        self.timer = threading.Timer(seconds, self.expire)
        self.timer.daemon = True

    def expire(self):
        with self.lock:
            if self.admitted:
                return
            self.expired = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def admit(self):
        with self.lock:
            if self.expired or time.monotonic() >= self.deadline:
                return False
            self.admitted = True
            self.timer.cancel()
            return True


class _HeaderReader:
    def __init__(self, source):
        self.source = source
        self.complete = False

    def readline(self, *args):
        line = self.source.readline(*args)
        if line in (b"\r\n", b"\n"):
            self.complete = True
        return line


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, TimeoutError):
            self.close_connection = True

    def handle_one_request(self):
        budget = _HeaderBudget(self.connection, self.server.header_timeout_seconds)
        self.header_budget = budget
        budget.timer.start()
        try:
            super().handle_one_request()
        finally:
            budget.timer.cancel()

    def parse_request(self):
        source = self.rfile
        headers = _HeaderReader(source)
        self.rfile = headers
        try:
            parsed = super().parse_request()
        finally:
            self.rfile = source
        if parsed and not headers.complete:
            self.close_connection = True
            self.send_error(400, "complete HTTP headers are required")
            return False
        return parsed

    def setup(self):
        self.request.settimeout(15)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def log_message(self, *args):
        pass  # Raw URLs include subscription identities; never access-log here.

    def reply(self, code, value, content_type="application/json", fields=None):
        data = value if isinstance(value, bytes) else canonical(value)
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, val in (fields or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.headers.get("Transfer-Encoding") or not 0 <= size <= MAX_FRAME:
            raise ValueError("invalid control body length")
        data = self.rfile.read(size)
        if len(data) != size:
            raise ValueError("incomplete control body")
        return json.loads(data) if data else {}

    def dispatch(self):
        if not self.header_budget.admit():
            self.close_connection = True
            return
        self.connection.settimeout(15)
        try:
            app = self.server.app
            if self.server.control:
                identity = peer_identity(self)
                if self.path.startswith("/_ha/") and self.headers.get("X-Vpnctl-Ha-Application") != "1":
                    value = app.control(identity, self.command, self.path, self.read_json() if self.command == "POST" else {})
                    self.reply(200, value)
                else:
                    if identity == app.config.get("witness"):
                        raise PermissionError("application forwarding requires a controller identity")
                    upstream = app.local_upstream()
                    # Only an authenticated configured controller may assert this IP.
                    client_ip = str(ipaddress.ip_address(self.headers.get("x-real-ip", self.client_address[0])))
                    proxy(self, upstream, None, client_ip)
            elif urllib.parse.urlsplit(self.path).path == "/admin/ha":
                self.management()
            else:
                address = ipaddress.ip_address(self.client_address[0])
                trusted = any(address in ipaddress.ip_network(net) for net in app.config.get("trusted_proxies", []))
                client_ip = str(address)
                if trusted and self.headers.get("x-real-ip"):
                    client_ip = str(ipaddress.ip_address(self.headers["x-real-ip"]))
                upstream, context = app.upstream()
                proxy(self, upstream, context, client_ip, forwarded=context is not None)
        except PermissionError:
            self.close_connection = True
            if not self.server.control and urllib.parse.urlsplit(self.path).path == "/admin/ha":
                self._management_error(403, "HA form authentication or same-origin check rejected.")
            else:
                self.reply(403, {"error": "control identity or authority rejected"})
        except Exception as error:
            # Runtime blocked reasons deliberately contain no request/secret bytes.
            message = str(error) if isinstance(error, RuntimeError) else "HA request unavailable"
            if not self.server.control and urllib.parse.urlsplit(self.path).path == "/admin/ha":
                self._management_error(503, message)
            else:
                self.reply(503, {"error": message})
            self.close_connection = True

    def _management_error(self, code, message):
        text = "vpnctl admin: " + message
        if "text/html" in self.headers.get("Accept", ""):
            body = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                    '<title>Controller availability · vpnctl</title><style>body{font:16px system-ui;line-height:1.5;max-width:62rem;margin:2rem auto;padding:0 1rem;background:#101a21;color:#eef4f5}a{color:#9ad9d3}</style>'
                    '<main><h1>Controller availability</h1><p role="alert">' + html.escape(text) + '</p>'
                    '<a href="/admin/ha">Back to controller availability</a></main></html>\n').encode()
            self.reply(code, body, "text/html; charset=utf-8", {"X-Frame-Options": "DENY"})
        else:
            self.reply(code, (text + "\n").encode(), "text/plain; charset=utf-8")

    def management(self):
        app = self.server.app
        token = Path(app.config["admin_token_file"]).read_bytes().strip()
        expected = b"ha:" + token
        try:
            auth = self.headers.get("Authorization", "")
            provided = base64.b64decode(auth.removeprefix("Basic "), validate=True) if auth.startswith("Basic ") else b""
        except Exception:
            provided = b""
        if not token or not hmac.compare_digest(provided, expected):
            self.close_connection = True
            self.reply(401, b"vpnctl admin: HA operator authentication required.\n", "text/plain", {"WWW-Authenticate": 'Basic realm="vpnctl HA"'})
            return
        csrf = hmac.new(token, b"vpnctl-ha-management", hashlib.sha256).hexdigest()
        if self.command == "POST":
            origin = self.headers.get("Origin")
            expected_origin = app.config.get("public_origin")
            if expected_origin is None:
                expected_origin = ("https://" if isinstance(self.connection, ssl.SSLSocket) else "http://") + self.headers.get("Host", "")
            if origin is not None and origin != expected_origin:
                raise PermissionError("management origin rejected")
            if self.headers.get("Sec-Fetch-Site") in ("cross-site", "none"):
                raise PermissionError("management request is not same-origin")
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or not 0 < size < 4096:
                raise PermissionError("invalid management form")
            form = urllib.parse.parse_qs(self.rfile.read(size).decode())
            if not hmac.compare_digest(form.get("csrf", [""])[0], csrf):
                raise PermissionError("management CSRF rejected")
            app.action(form.get("action", [""])[0], form.get("target", [None])[0])
            self.reply(303, b"", fields={"Location": "/admin/ha"})
            return
        status = app.status()
        controls = [("readiness", "Test readiness"), ("initialize", "Initialize stopped seed"),
                    ("pause", "Pause automatic failover"), ("resume", "Resume automatic failover"),
                    ("handover", "Hand over to peer")]
        buttons = "".join('<button name="action" value="' + key + '">' + title + '</button>' for key, title in controls)
        peers = "".join('<option value="' + html.escape(node) + '">' + html.escape(node) + '</option>'
                        for node in app.config["peers"] if node != app.config["node_id"] and node != app.config.get("witness"))
        age = status.get("snapshot_age_ms")
        executor = status.get("executor") or {}
        jobs = executor.get("blocked_jobs", [])
        executor_label = ("Ready for fencing barrier" if executor.get("ready") else
                          "Unresolved jobs: " + ", ".join(job["id"] for job in jobs) if jobs else
                          executor.get("blocked_reason", "Readiness has not checked the executor"))
        settings = status.get("automatic_failover", {})
        values = [("This controller", status.get("node", app.config["node_id"])),
                  ("Role", status.get("role", "isolated")), ("Current leader", status.get("leader") or "No admitted leader"),
                  ("Quorum", "Verified" if status.get("quorum") else "Unavailable or not verified"),
                  ("Snapshot generation", status.get("generation") or "No verified generation"),
                  ("Snapshot age / possible data loss", "Unknown" if age is None else f"{age / 1000:.2f} seconds"),
                  ("Replication interval", f"{status.get('replication_interval_ms', 0) / 1000:g} seconds"),
                  ("Maximum promotion age", f"{status.get('maximum_promotion_age_ms', status.get('max_replica_age_ms', 0)) / 1000:g} seconds"),
                  ("Worker admission", "Open" if status.get("worker_admitted") else "Closed"),
                  ("Local fencing", "Closed through epoch " + str(status.get("fenced_through", 0))),
                  ("External executor", executor_label),
                  ("Automatic failover", "Paused" if settings.get("paused", True) else "Enabled")]
        rows = "".join("<tr><th scope=\"row\">" + html.escape(key) + "</th><td>" + html.escape(str(value)) + "</td></tr>" for key, value in values)
        blocked = status.get("blocked_reason")
        message = ('<p class="blocked" role="status"><strong>Blocked:</strong> ' + html.escape(blocked) + '</p>') if blocked else '<p role="status">No blocking condition reported.</p>'
        body = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                '<title>Controller availability · vpnctl</title><style>'
                'body{font:16px system-ui;line-height:1.5;max-width:62rem;margin:2rem auto;padding:0 1rem;background:#101a21;color:#eef4f5}'
                'h1{font-size:1.8rem;margin-top:2rem}p{max-width:72ch}a{color:#9ad9d3;text-underline-offset:.2em}'
                'table{border-collapse:collapse;width:100%;margin:1.5rem 0}th,td{text-align:left;vertical-align:top;padding:.7rem .3rem;border-bottom:1px solid #3e535d;overflow-wrap:anywhere}th{width:45%;font-weight:500;color:#c8dce2}td{font-variant-numeric:tabular-nums}'
                '.blocked{padding:1rem;background:#382c20;color:#ffe1ac}button,select{font:inherit;margin:.3rem .3rem .3rem 0;padding:.65rem;border:1px solid #8aadb7;border-radius:4px;background:#24434c;color:#fff;cursor:pointer}'
                'button:hover{background:#345b65}button:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #a8e4d6;outline-offset:3px}'
                '::selection{background:#b8e3db;color:#101a21}@media(max-width:480px){body{margin:1rem auto}th{width:46%}button{width:100%;text-align:left}}'
                '</style><a href="/admin/">Back to administration</a><h1>Controller availability</h1>'
                '<p>Asynchronous replication can lose acknowledged changes since the latest verified snapshot. Snapshot age shows the current recovery point.</p>'
                + message + '<table aria-label="Controller readiness"><tbody>' + rows + '</tbody></table>'
                '<form method="post"><input type="hidden" name="csrf" value="' + csrf + '"><label>Handover target '
                '<select name="target">' + peers + '</select></label><p>' + buttons + '</p></form>'
                '<p>Initialization requires a stopped seed and no cluster history. An unresolved remote execution blocks promotion until its outcome is proven.</p></html>').encode()
        self.reply(200, body, "text/html; charset=utf-8", {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_PATCH = dispatch
    do_DELETE = dispatch
    do_OPTIONS = dispatch
