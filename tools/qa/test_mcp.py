"""Black-box MCP stdio contract tests for `python tools/qa/qa.py mcp`.

Only the published contract is asserted here: no implementation imports, no
Rust APIs, no source inspection.  Protocol-level tests run without a bundle;
the navigation run is an integration test that skips when no candidate bundle
is provided via VPNCTL_QA_BUNDLE.
"""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QA_ENTRY = ROOT / "tools" / "qa" / "qa.py"

SUITES = ["navigation", "users", "servers", "settings"]
PROTOCOL_VERSION = "2024-11-05"
FORBIDDEN_INPUTS = (
    "url", "uri", "host", "hostname", "endpoint", "port", "address",
    "user", "username", "password", "passwd", "credential", "credentials",
    "token", "secret", "apikey", "api_key", "command", "cmd", "argv", "exec",
    "db", "database", "sqlite", "db_path", "database_path", "dsn",
    "selector", "selectors", "css", "xpath", "browser", "profile",
    "ssh", "key", "identity", "cookie", "session",
)
NAVIGATION_TIMEOUT = 900


class McpError(AssertionError):
    pass


class McpClient:
    """Minimal newline-delimited JSON-RPC 2.0 client over stdio."""

    def __init__(self, env=None, cwd=ROOT):
        python = sys.executable or "python3"
        self.proc = subprocess.Popen(
            [python, str(QA_ENTRY), "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._messages = queue.Queue()
        self._stderr = []
        self._noise = []
        self._next_id = 0
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self):
        try:
            for line in self.proc.stdout:
                self._messages.put(line)
        finally:
            self._messages.put(None)

    def _pump_stderr(self):
        try:
            for line in self.proc.stderr:
                self._stderr.append(line)
        except (ValueError, OSError):
            pass

    def _send(self, payload):
        if self.proc.poll() is not None:
            raise McpError("server exited before request: " + self.diagnostics())
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise McpError(f"cannot write to server ({exc}): {self.diagnostics()}")

    def _read(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpError(f"timed out after {timeout}s waiting for a response: {self.diagnostics()}")
            try:
                line = self._messages.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                raise McpError("server closed stdout: " + self.diagnostics())
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._noise.append(line)
                continue
            if not isinstance(message, dict):
                self._noise.append(line)
                continue
            return message

    def request(self, method, params=None, timeout=60):
        """Return (result, error) for a JSON-RPC request; never raises on error."""
        self._next_id += 1
        request_id = self._next_id
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)
        deadline = time.monotonic() + timeout
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            message = self._read(remaining)
            if message.get("id") == request_id:
                if "error" in message:
                    return None, message["error"]
                return message.get("result"), None
            if "method" in message and "id" in message:
                # Reverse request from the server: keep the channel alive.
                self._send({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": "method not supported by test client"},
                })

    def notify(self, method, params=None):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

    def initialize(self):
        result, error = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "vpnctl-qa-spec", "version": "0.0.0"},
            },
            timeout=60,
        )
        if error is not None:
            raise McpError(f"initialize failed: {error!r}: {self.diagnostics()}")
        self.notify("notifications/initialized", {})
        return result

    def call_tool(self, name, arguments=None, timeout=60):
        params = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        return self.request("tools/call", params, timeout=timeout)

    def children(self):
        """Best-effort child PIDs of the server process (Linux /proc)."""
        children = set()
        for path in Path(f"/proc/{self.proc.pid}/task").glob("*/children"):
            try:
                children.update(int(pid) for pid in path.read_text().split())
            except FileNotFoundError:
                continue
        return children

    def diagnostics(self):
        tail = "".join(self._stderr[-15:]).strip()
        parts = [f"exit={self.proc.poll()}"]
        if self._noise:
            parts.append("non-JSON stdout: " + " | ".join(self._noise[-3:]))
        if tail:
            parts.append("stderr: " + tail)
        return "; ".join(parts)

    def close(self):
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def parse_tool_json(result):
    """Extract the JSON payload a tool returns, from text or structured content."""
    if isinstance(result, dict):
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
    texts = []
    if isinstance(result, dict):
        for block in result.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text") or "")
    joined = "".join(texts).strip()
    if not joined:
        raise McpError(f"tool returned no text payload: {result!r}")
    try:
        return json.loads(joined)
    except json.JSONDecodeError as exc:
        raise McpError(f"tool payload is not JSON ({exc}): {joined[:500]!r}")


def tool_failed(result, error):
    if error is not None:
        return True, json.dumps(error)
    if isinstance(result, dict) and result.get("isError"):
        return True, json.dumps(result)
    return False, ""


def normalize_name(name):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    tokens = [token for token in re.split(r"[^a-z0-9]+", spaced.lower()) if token]
    return "_".join(tokens), tokens


def schema_property_names(schema, found=None):
    """Collect property names from a JSON Schema, including nested combinators."""
    if found is None:
        found = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            found.update(properties)
        for key in ("$defs", "definitions"):
            if isinstance(schema.get(key), dict):
                for subschema in schema[key].values():
                    schema_property_names(subschema, found)
        for key in ("anyOf", "oneOf", "allOf", "items", "additionalProperties", "not", "then", "else"):
            value = schema.get(key)
            if isinstance(value, (dict, list)):
                schema_property_names(value, found)
    elif isinstance(schema, list):
        for item in schema:
            schema_property_names(item, found)
    return found


class ProtocolTests(unittest.TestCase):
    """Handshake, discovery and argument validation. No bundle or stand needed."""

    @classmethod
    def setUpClass(cls):
        if not QA_ENTRY.is_file():
            raise AssertionError(f"missing QA entry point: {QA_ENTRY}")
        env = os.environ.copy()
        # Keep protocol tests independent of integration state.
        env.pop("VPNCTL_QA_BUNDLE", None)
        cls.client = McpClient(env=env)
        cls.init_result = cls.client.initialize()

    @classmethod
    def tearDownClass(cls):
        client = getattr(cls, "client", None)
        if client is not None:
            client.close()

    def diag(self):
        return self.client.diagnostics()

    def list_tools(self):
        result, error = self.client.request("tools/list", {}, timeout=60)
        self.assertIsNone(error, f"tools/list failed: {error!r}: {self.diag()}")
        tools = (result or {}).get("tools")
        self.assertIsInstance(tools, list, f"tools/list returned no tools array: {result!r}")
        return {tool.get("name"): tool for tool in tools if isinstance(tool, dict)}

    # -- handshake / discovery -------------------------------------------------

    def test_01_handshake(self):
        result = self.init_result
        self.assertIsInstance(result, dict, f"initialize returned {result!r}")
        self.assertIsInstance(result.get("protocolVersion"), str, f"missing protocolVersion: {result!r}")
        self.assertIsInstance(result.get("capabilities"), dict, f"missing capabilities: {result!r}")
        server_info = result.get("serverInfo")
        self.assertIsInstance(server_info, dict, f"missing serverInfo: {result!r}")
        self.assertIsInstance(server_info.get("name"), str, f"serverInfo.name must be a string: {server_info!r}")
        self.assertTrue(server_info.get("name", "").strip(), f"serverInfo.name is empty: {server_info!r}")

    def test_02_tools_list_exposes_only_qa_tools(self):
        tools = self.list_tools()
        self.assertEqual(set(tools), {"qa_catalog", "qa_run"}, f"unexpected tool set: {sorted(tools)}")
        for name, tool in tools.items():
            self.assertIsInstance(tool.get("inputSchema"), dict, f"{name} has no object inputSchema: {tool!r}")

    def test_03_catalog_returns_exact_suites(self):
        result, error = self.client.call_tool("qa_catalog", {}, timeout=60)
        failed, detail = tool_failed(result, error)
        self.assertFalse(failed, f"qa_catalog failed: {detail}: {self.diag()}")
        payload = parse_tool_json(result)
        self.assertIsInstance(payload, dict, f"catalog payload is not an object: {payload!r}")
        self.assertEqual(payload.get("suites"), SUITES, f"catalog suites mismatch: {payload.get('suites')!r}")

    def test_04_schemas_accept_no_forbidden_inputs(self):
        tools = self.list_tools()
        for name in ("qa_catalog", "qa_run"):
            properties = schema_property_names(tools[name].get("inputSchema") or {})
            for prop in properties:
                _, tokens = normalize_name(prop)
                compact = "".join(tokens)
                for forbidden in FORBIDDEN_INPUTS:
                    forbidden_compact = forbidden.replace("_", "")
                    self.assertNotEqual(
                        compact,
                        forbidden_compact,
                        f"{name} schema exposes forbidden input {prop!r} "
                        f"(URL/host/credentials/command/DB path/selector are not accepted)",
                    )

    # -- input rejection -------------------------------------------------------

    def assert_rejected(self, arguments, label, tool="qa_run"):
        children_before = self.client.children()
        result, error = self.client.call_tool(tool, arguments, timeout=60)
        failed, detail = tool_failed(result, error)
        self.assertTrue(failed, f"{label} was accepted; result: {result!r}")
        time.sleep(0.2)
        new_children = sorted(set(self.client.children()) - set(children_before))
        self.assertEqual(new_children, [], f"{label} started work before failing (child pids {new_children})")

    def test_05_missing_suite_is_rejected(self):
        self.assert_rejected({}, "qa_run with empty arguments")
        self.assert_rejected(None, "qa_run without arguments")

    def test_06_unknown_suite_is_rejected(self):
        for value in ("nope", "all_suites", "", "navigation,users"):
            with self.subTest(suite=value):
                self.assert_rejected({"suite": value}, f"qa_run suite={value!r}")

    def test_07_extra_inputs_are_rejected(self):
        forbidden_values = {
            "url": "http://127.0.0.1:1/",
            "host": "127.0.0.1",
            "username": "operator",
            "password": "not-a-secret",
            "command": "id",
            "db_path": "/tmp/qa.db",
            "selector": "#login",
        }
        for key, value in forbidden_values.items():
            with self.subTest(extra=key):
                self.assert_rejected(
                    {"suite": "navigation", key: value},
                    f"qa_run with extra input {key!r}",
                )
                self.assert_rejected({key: value}, f"qa_catalog with extra input {key!r}", tool="qa_catalog")

    def test_08_wrong_argument_types_are_rejected(self):
        for value in (5, [], {"suite": "navigation"}, True):
            with self.subTest(suite=value):
                self.assert_rejected({"suite": value}, f"qa_run suite={value!r}")

    def test_09_server_survives_rejected_inputs(self):
        self.assertTrue(self.client.proc.poll() is None, f"server died during error handling: {self.diag()}")
        result, error = self.client.call_tool("qa_catalog", {}, timeout=60)
        failed, detail = tool_failed(result, error)
        self.assertFalse(failed, f"qa_catalog failed after input errors: {detail}: {self.diag()}")
        self.assertEqual(parse_tool_json(result).get("suites"), SUITES)


class NavigationIntegrationTests(unittest.TestCase):
    """Real bundle/browser run; skipped unless a candidate bundle is supplied."""

    @classmethod
    def setUpClass(cls):
        bundle_raw = os.environ.get("VPNCTL_QA_BUNDLE", "").strip()
        if not bundle_raw:
            raise unittest.SkipTest("VPNCTL_QA_BUNDLE not set; skipping navigation integration")
        bundle = Path(bundle_raw)
        missing = [
            rel for rel in ("bin/vpnctl", "bin/vpnctld", "assets")
            if not (bundle / rel).exists()
        ]
        if missing:
            raise unittest.SkipTest(f"bundle {bundle} is missing {missing}; skipping navigation integration")
        if not QA_ENTRY.is_file():
            raise AssertionError(f"missing QA entry point: {QA_ENTRY}")
        env = os.environ.copy()
        env["VPNCTL_QA_BUNDLE"] = str(bundle)
        cls.client = McpClient(env=env)
        cls.client.initialize()

    @classmethod
    def tearDownClass(cls):
        client = getattr(cls, "client", None)
        if client is not None:
            client.close()

    def test_navigation_run_returns_real_checks(self):
        result, error = self.client.call_tool("qa_run", {"suite": "navigation"}, timeout=NAVIGATION_TIMEOUT)
        failed, detail = tool_failed(result, error)
        if failed and re.search(
            r"browser|chromium|chrome|playwright|display|headless|not (?:installed|available)",
            detail,
            re.IGNORECASE,
        ):
            self.skipTest(f"no usable browser available: {detail[:300]}")
        self.assertFalse(failed, f"qa_run navigation failed: {detail}: {self.client.diagnostics()}")
        payload = parse_tool_json(result)
        self.assertIsInstance(payload, dict, f"qa_run payload is not an object: {payload!r}")
        checks = payload.get("checks")
        self.assertIsInstance(checks, list, f"payload has no checks array: {payload!r}")
        self.assertTrue(checks, "checks must be non-empty")
        for index, check in enumerate(checks):
            self.assertIsInstance(check, dict, f"check[{index}] is not an object: {check!r}")
            name = check.get("name")
            self.assertIsInstance(name, str, f"check[{index}] name must be a string: {check!r}")
            self.assertTrue(name.strip(), f"check[{index}] name is empty: {check!r}")
            self.assertIn("passed", check, f"check[{index}] has no passed field: {check!r}")
            self.assertIsInstance(check["passed"], bool, f"check[{index}] passed must be boolean: {check!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
