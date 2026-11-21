#!/usr/bin/env python3
"""Adapt the installed one-shot DNSTT check to vpnctl assurance results."""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

PROBE = Path("/usr/local/libexec/vpnctl/dnstt-assurance-check")
PROBE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}


def observation(stage, state, code=None, latency=None):
    return {
        "client_kind": "dnstt-on-demand",
        "stage": stage,
        "state": state,
        "failure_code": code,
        "latency_ms": latency,
    }


def interpret(exit_code, output):
    if len(output) > 4096:
        return observation("client_import", "unknown", "runner_invalid_result")
    try:
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError("result must be an object")
    except (ValueError, UnicodeDecodeError):
        return observation("client_import", "unknown", "runner_invalid_result")
    latency = result.get("elapsed_ms")
    if (exit_code == 0 and result.get("result") == "verified"
            and result.get("protocol") == "dnstt" and result.get("stage") == "transfer"
            and result.get("https_requests") == 1 and type(latency) is int
            and 0 <= latency <= 36_000):
        return observation("transfer", "verified", latency=latency)
    reason = result.get("reason")
    if exit_code == 1 and result.get("result") == "failed" and isinstance(reason, str):
        if re.fullmatch(r"curl_exit_[0-9]{1,3}", reason):
            return observation("transfer", "degraded", reason)
        if reason in {
            "config_or_runtime_error", "template_permissions_invalid", "template_route_invalid",
            "client_config_rejected", "engine_untrusted", "client_exited",
            "local_socks_unavailable", "unexpected_health_response",
        }:
            return observation("client_import", "unknown", reason)
    return observation("client_import", "unknown", "runner_invalid_result")


def probe(raw):
    if len(raw) > 65_536:
        return observation("client_import", "unknown", "request_invalid")
    try:
        request = json.loads(raw)
        if not isinstance(request, dict) or request.get("protocol") != "dnstt":
            raise ValueError("DNSTT request required")
        server = request.get("server")
        if not isinstance(server, str) or str(ipaddress.IPv4Address(server)) != server:
            raise ValueError("literal IPv4 address required")
    except (ValueError, UnicodeDecodeError):
        return observation("client_import", "unknown", "request_invalid")
    try:
        info = PROBE.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not info.st_mode & 0o111):
            return observation("client_import", "unknown", "probe_unsafe")
        for parent in PROBE.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return observation("client_import", "unknown", "probe_unsafe")
        template = hashlib.sha256(server.encode()).hexdigest() + ".dnstt.json"
        env = PROBE_ENV.copy()
        if temp_dir := os.environ.get("TMPDIR"):
            env["TMPDIR"] = temp_dir
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                [str(PROBE), template], stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, env=env, timeout=36, check=False,
            )
            output.seek(0)
            return interpret(result.returncode, output.read(4097))
    except (OSError, subprocess.TimeoutExpired):
        return observation("client_import", "unknown", "probe_unavailable")


if __name__ == "__main__":
    print(json.dumps(probe(sys.stdin.buffer.read(65_537)), separators=(",", ":")))
