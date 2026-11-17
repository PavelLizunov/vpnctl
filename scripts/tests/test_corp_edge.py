"""Loopback Caddy integration; run with CADDY_BINARY=/path/to/installed/caddy.

Uses no production endpoints, credentials, certificates or Caddy admin API.
The template must be copied alongside this script in the repository layout.
"""
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest


HOST = 'admin.corp.ninitux.com'
ORIGIN = 'https://' + HOST
REPORT_ID = 'a1' * 32
DELETE_PATH = '/api/corp/reports/' + REPORT_ID
CADDY = os.environ.get('CADDY_BINARY')
TEMPLATE = Path(__file__).resolve().parents[2] / 'deploy' / 'corp-portal.caddy'


class MockUpstream(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, role):
        super().__init__(('127.0.0.1', 0), MockHandler)
        self.role = role
        self.calls = []
        self.status = None
        self.company = 'synthetic-policy-id'
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=3)

    @property
    def address(self):
        return '%s:%s' % self.server_address


class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.server.calls.append((self.command, self.path, body, headers))
        if self.server.role == 'receiver':
            code = self.server.status or 200
            payload = {'schema': 1, 'state': 'deleted', 'freed_bytes': 1234}
        elif self.command == 'POST' and self.path == '/api/corp/normalize':
            # Model only the existing backend gate's observable contract.
            valid = (headers.get('cookie') == 'corp_session=synthetic-session' and
                     headers.get('origin') == ORIGIN and
                     headers.get('x-corp-csrf') == 'synthetic-csrf' and
                     headers.get('x-real-ip') == '127.0.0.1' and
                     headers.get('host') == HOST and
                     headers.get('x-forwarded-proto') == 'https' and
                     json.loads(body) == {'site': 'example.com'})
            code = self.server.status or (200 if valid else 403)
            payload = {'domain': 'example.com'} if code == 200 else {'error': 'safe backend denial'}
        else:
            code, payload = 200, {'passthrough': self.path, 'method': self.command}
        if code != 200 and self.server.role == 'receiver':
            payload = {'error': 'safe receiver failure'}
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        if self.server.role == 'backend' and code == 200 and self.path == '/api/corp/normalize' and self.server.company is not None:
            self.send_header('X-Corp-Company', self.server.company)
        self.end_headers()
        self.wfile.write(raw)

    do_GET = handle_request
    do_POST = handle_request
    do_DELETE = handle_request


@unittest.skipUnless(CADDY, 'set CADDY_BINARY to an existing Caddy >= 2.11 binary')
class CorpEdgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='corp-edge-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = MockUpstream('backend')
        self.addCleanup(self.backend.close)
        self.receiver = MockUpstream('receiver')
        self.addCleanup(self.receiver.close)
        assets = self.root / 'assets'
        assets.mkdir()
        self.assets = {'corp.css': b'body { color: #123; }',
                       'corp.js': b'// synthetic portal',
                       'corp-phone.js': b'// synthetic compatibility',
                       'corp-diagnostics.js': b'// synthetic diagnostics'}
        for name, content in self.assets.items():
            (assets / name).write_bytes(content)
        private_header = self.root / 'service-header.caddy'
        private_header.write_text('header_up Authorization "Bearer synthetic-service-capability"\n')
        private_header.chmod(0o600)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        config = TEMPLATE.read_text().replace(
            HOST + ' {', 'http://127.0.0.1:%s {' % self.port, 1)
        for placeholder, value in {
            '__CORP_BACKEND__': self.backend.address,
            '__CORP_RECEIVER__': self.receiver.address,
            '__CORP_ASSETS__': str(assets),
            '__CORP_SERVICE_HEADER__': str(private_header),
        }.items():
            config = config.replace(placeholder, value)
        # Match production's imported site file: import performs token
        # replacement, which must preserve the escaped JSON body braces.
        site_path = self.root / 'corp-portal.caddy'
        site_path.write_text(config)
        config_path = self.root / 'Caddyfile'
        config_path.write_text('{\n admin off\n auto_https off\n}\nimport ' + str(site_path) + '\n')
        self.log = (self.root / 'caddy.log').open('w+b')
        self.addCleanup(self.log.close)
        env = dict(os.environ, XDG_DATA_HOME=str(self.root / 'data'),
                   XDG_CONFIG_HOME=str(self.root / 'config'))
        self.process = subprocess.Popen(
            [str(Path(CADDY).resolve()), 'run', '--config', str(config_path), '--adapter', 'caddyfile'],
            cwd=self.root, env=env, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop_caddy)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                self.fail('Caddy exited: ' + self.log.read().decode(errors='replace'))
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        self.fail('temporary Caddy did not start within eight seconds')

    def stop_caddy(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)

    def request(self, method, path, body=b'{}', headers=None):
        fields = {'Cookie': 'corp_session=synthetic-session', 'Origin': ORIGIN,
                  'X-Corp-CSRF': 'synthetic-csrf', 'Authorization': 'Bearer browser-only',
                  'X-Real-IP': '203.0.113.9', 'Forwarded': 'for=203.0.113.9',
                  'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Host': 'spoof.invalid',
                  'X-Forwarded-Proto': 'http', 'X-Browser-Only': 'drop-me'}
        fields.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=fields)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_exact_assets_are_static_and_other_get_routes_pass_through(self):
        for name, expected in self.assets.items():
            code, headers, body = self.request('GET', '/assets/' + name, body=None)
            self.assertEqual((code, body), (200, expected))
            self.assertEqual(headers.get('Cache-Control'), 'no-store')
            self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(self.backend.calls, [])
        for path in ('/diagnostics', '/api/corp/reports', '/assets/other.js'):
            code, _, body = self.request('GET', path, body=None)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)['passthrough'], path)
        self.assertEqual(self.receiver.calls, [])

    def test_authorized_delete_uses_existing_gate_then_service_only_request(self):
        code, _, body = self.request('DELETE', DELETE_PATH, body=b'ignored')
        self.assertEqual((code, json.loads(body)),
                         (200, {'schema': 1, 'state': 'deleted', 'freed_bytes': 1234}))
        method, path, auth_body, auth_headers = self.backend.calls[0]
        self.assertEqual((method, path, json.loads(auth_body)),
                         ('POST', '/api/corp/normalize', {'site': 'example.com'}))
        self.assertEqual(auth_headers['content-length'], str(len(auth_body)))
        self.assertEqual(auth_headers['x-real-ip'], '127.0.0.1')
        self.assertEqual(auth_headers['cookie'], 'corp_session=synthetic-session')
        self.assertEqual(auth_headers['origin'], ORIGIN)
        self.assertEqual(auth_headers['x-corp-csrf'], 'synthetic-csrf')
        self.assertNotIn('forwarded', auth_headers)
        self.assertNotIn('x-forwarded-for', auth_headers)
        self.assertNotIn('x-forwarded-host', auth_headers)
        self.assertEqual(len(self.receiver.calls), 1)
        method, path, delete_body, headers = self.receiver.calls[0]
        self.assertEqual((method, path, delete_body),
                         ('DELETE', '/internal/corp-diagnostics/reports/' + REPORT_ID, b'{}'))
        self.assertEqual(headers['authorization'], 'Bearer synthetic-service-capability')
        self.assertEqual(headers['content-type'], 'application/json')
        self.assertEqual(headers['x-corp-company'], 'synthetic-policy-id')
        self.assertEqual(headers['content-length'], '2')
        for name in ('cookie', 'origin', 'x-corp-csrf', 'x-real-ip', 'forwarded',
                     'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-browser-only'):
            self.assertNotIn(name, headers)
        self.assertNotIn(b'synthetic-service-capability', body)

    def test_authorized_delete_rewrites_body_and_lengths_for_browser_empty_json(self):
        for original in (b'{}', b'', b'ignored', b'x' * 22, b'x' * 1024):
            with self.subTest(original_length=len(original)):
                self.backend.calls.clear()
                self.receiver.calls.clear()
                code, _, body = self.request('DELETE', DELETE_PATH, body=original)
                self.assertEqual(code, 200, body)
                self.assertEqual(len(self.backend.calls), 1)
                method, path, auth_body, auth_headers = self.backend.calls[0]
                self.assertEqual((method, path, auth_body, auth_headers['content-length']),
                                 ('POST', '/api/corp/normalize', b'{"site":"example.com"}', '22'))
                self.assertEqual(len(self.receiver.calls), 1)
                method, path, delete_body, headers = self.receiver.calls[0]
                self.assertEqual((method, path, delete_body, headers['content-length']),
                                 ('DELETE', '/internal/corp-diagnostics/reports/' + REPORT_ID, b'{}', '2'))

    def test_caller_cannot_select_company_and_missing_authority_fails_closed(self):
        self.assertEqual(self.request('DELETE', DELETE_PATH, headers={'X-Corp-Company': 'foreign-policy'})[0], 200)
        self.assertNotIn('x-corp-company', self.backend.calls[-1][3])
        self.assertEqual(self.receiver.calls[-1][3]['x-corp-company'], 'synthetic-policy-id')
        self.backend.company = None
        self.receiver.calls.clear()
        for method, path in [('DELETE', DELETE_PATH), ('POST', '/api/corp/categories/state')]:
            self.assertEqual(self.request(method, path)[0], 503)
        self.assertEqual(self.receiver.calls, [])

    def test_category_utf8_body_is_restored_with_authoritative_company(self):
        body = json.dumps({'expected_revision': 0, 'categories': [{'id': 'work', 'name': 'Работа'}],
                           'assignments': []}, ensure_ascii=False).encode()
        code, _, _ = self.request('POST', '/api/corp/categories/save', body=body,
                                  headers={'X-Corp-Company': 'foreign-policy'})
        self.assertEqual(code, 200)
        self.assertNotIn('x-corp-company', self.backend.calls[-1][3])
        method, path, forwarded, headers = self.receiver.calls[-1]
        self.assertEqual((method, path, forwarded), ('POST', '/internal/corp-categories/save', body))
        self.assertEqual(headers['x-corp-company'], 'synthetic-policy-id')
        self.assertEqual(headers['x-corp-expected-length'], str(len(body)))
        self.assertEqual(headers['authorization'], 'Bearer synthetic-service-capability')

    def test_backend_denials_never_call_receiver(self):
        for override in ({'Origin': 'https://spoof.invalid'}, {'X-Corp-CSRF': 'bad'},
                         {'Cookie': 'corp_session=bad'}):
            with self.subTest(headers=override):
                code, _, body = self.request('DELETE', DELETE_PATH, headers=override)
                self.assertEqual((code, json.loads(body)), (403, {'error': 'safe backend denial'}))
        for status in (201, 202, 302, 401, 503):
            self.backend.status = status
            with self.subTest(status=status):
                self.assertEqual(self.request('DELETE', DELETE_PATH)[0], status)
        self.assertEqual(self.receiver.calls, [])

    def test_invalid_paths_and_other_methods_never_delete(self):
        for path in ('/api/corp/reports/' + 'A' * 64, DELETE_PATH + '/retry',
                     DELETE_PATH + '?extra=1', '/api/corp/reports/../other',
                     '/api/corp/reports/%2e%2e/other', '/api/corp/reports/short'):
            self.request('DELETE', path)
        self.request('POST', DELETE_PATH)
        self.assertEqual(self.receiver.calls, [])
        self.assertFalse(any(call[1] == '/api/corp/normalize' for call in self.backend.calls))

    def test_oversized_or_unknown_body_length_never_reaches_upstreams(self):
        self.assertEqual(self.request('DELETE', DELETE_PATH, body=b'x' * 1025)[0], 413)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.putrequest('DELETE', DELETE_PATH)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            connection.close()
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.receiver.calls, [])

    def test_receiver_error_passes_through(self):
        for status in (404, 503):
            self.receiver.status = status
            with self.subTest(status=status):
                code, _, body = self.request('DELETE', DELETE_PATH)
                self.assertEqual((code, json.loads(body)), (status, {'error': 'safe receiver failure'}))
        self.assertEqual(len(self.receiver.calls), 2)


if __name__ == '__main__':
    unittest.main()
