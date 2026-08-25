#!/usr/bin/env python3
"""vpnctl protocol-assurance external runner.

Reads one non-secret target request on stdin. Probe credentials live only in
root-owned engine-native templates under CONFIG_DIR. Emits exactly one compact
JSON result and never prints client config or subprocess output.
"""

import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("VPNCTL_ASSURANCE_CONFIG_DIR", "/etc/vpnctl/protocol-assurance.d"))
SING_BOX = os.environ.get("VPNCTL_ASSURANCE_SING_BOX", "/usr/local/libexec/vpnctl/sing-box")
XRAY = os.environ.get("VPNCTL_ASSURANCE_XRAY", "/usr/local/libexec/vpnctl/xray")
CHECK_URL = os.environ.get("VPNCTL_ASSURANCE_CHECK_URL", "https://cp.cloudflare.com/generate_204")
SAFE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}
START_TIMEOUT = 3.0
TRANSFER_TIMEOUT = 15.0
PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9+_-]{0,63}$")


def emit(stage, state, code=None, latency=None, client="external-runner"):
    result = {
        "stage": stage,
        "state": state,
        "latency_ms": latency,
        "failure_code": code,
        "client_kind": client,
    }
    print(json.dumps(result, separators=(",", ":")))


def fail(code, stage="handshake"):
    emit(stage, "blocked", code)
    raise SystemExit(0)


def load_request():
    raw = sys.stdin.buffer.read(65537)
    if not raw or len(raw) > 65536:
        fail("request_invalid", "render")
    try:
        request = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("request_invalid", "render")
    server = request.get("server")
    protocol = request.get("protocol")
    if not isinstance(server, str) or not server or len(server) > 255:
        fail("request_invalid", "render")
    if not isinstance(protocol, str) or not PROTOCOL_RE.fullmatch(protocol):
        fail("request_invalid", "render")
    return server, protocol


def trusted_config_dir():
    try:
        info = CONFIG_DIR.lstat()
    except OSError:
        fail("probe_config_missing", "client_import")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("probe_config_unsafe", "client_import")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("probe_config_unsafe", "client_import")


def trusted_file(path):
    try:
        info = path.lstat()
    except OSError:
        fail("probe_config_missing", "client_import")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("probe_config_unsafe", "client_import")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        fail("probe_config_unsafe", "client_import")


def replace_port(value, port):
    if isinstance(value, dict):
        return {key: replace_port(item, port) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_port(item, port) for item in value]
    if value == "__PORT__":
        return port
    return value


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def trusted_engine(path):
    path = Path(path)
    if not path.is_absolute():
        fail("probe_engine_unsafe", "client_import")
    try:
        info = path.lstat()
    except OSError:
        fail("probe_engine_missing", "client_import")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("probe_engine_unsafe", "client_import")
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022 or not info.st_mode & 0o111:
        fail("probe_engine_unsafe", "client_import")
    return str(path)


def engine_command(engine, config_path):
    if engine == "sing-box":
        return [trusted_engine(SING_BOX), "run", "-c", str(config_path)], "sing-box"
    if engine == "xray":
        return [trusted_engine(XRAY), "run", "-config", str(config_path)], "xray"
    fail("probe_engine_invalid", "client_import")


def main():
    server, protocol = load_request()
    if not CHECK_URL.startswith("https://"):
        fail("check_url_invalid", "transfer")
    trusted_config_dir()
    name = hashlib.sha256(server.encode()).hexdigest() + "." + protocol + ".json"
    template_path = CONFIG_DIR / name
    trusted_file(template_path)
    try:
        wrapper = json.loads(template_path.read_bytes())
        engine = wrapper["engine"]
        config = wrapper["config"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        fail("probe_config_invalid", "client_import")

    port = free_port()
    config = replace_port(config, port)
    with tempfile.TemporaryDirectory(prefix="vpnctl-assurance-") as tmp:
        os.chmod(tmp, 0o700)
        config_path = Path(tmp) / "config.json"
        config_path.write_text(json.dumps(config, separators=(",", ":")))
        os.chmod(config_path, 0o600)
        command, client_kind = engine_command(engine, config_path)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                env=SAFE_ENV,
            )
        except OSError:
            fail("client_start_failed", "client_import")
        try:
            deadline = time.monotonic() + START_TIMEOUT
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    fail("client_start_failed", "client_import")
                with socket.socket() as sock:
                    sock.settimeout(0.1)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(0.05)
            else:
                fail("client_start_timeout", "client_import")

            started = time.monotonic()
            result = subprocess.run(
                [
                    "/usr/bin/curl",
                    "-q",
                    "--proto",
                    "=https",
                    "--silent",
                    "--show-error",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "--connect-timeout",
                    "8",
                    "--max-time",
                    str(int(TRANSFER_TIMEOUT)),
                    "--socks5-hostname",
                    f"127.0.0.1:{port}",
                    CHECK_URL,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=TRANSFER_TIMEOUT + 2,
                check=False,
                env=SAFE_ENV,
            )
            latency = int((time.monotonic() - started) * 1000)
            if result.returncode != 0:
                fail("handshake_timeout", "handshake")
            if result.stdout.strip() != "204":
                fail("transfer_failed", "transfer")
            emit("transfer", "verified", latency=latency, client=client_kind)
        except subprocess.TimeoutExpired:
            fail("handshake_timeout", "handshake")
        except OSError:
            fail("transfer_tool_failed", "transfer")
        finally:
            stop_process(process)


if __name__ == "__main__":
    main()
