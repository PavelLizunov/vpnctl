"""Authenticated control transport and durable local state for opt-in HA."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import tempfile
import time
import urllib.parse

MAX_FRAME = 384 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value))
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_bytes())
    except FileNotFoundError:
        return default


def now_ms():
    return time.time_ns() // 1_000_000


def tls_context(config, server=False):
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH,
        cafile=config["ca"],
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(config["cert"], config["key"])
    if server:
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def connection(url, context=None, timeout=3):
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("control URL must not contain credentials, query or fragment")
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=timeout)
    elif parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1", "localhost"):
        # Local Consul agent / worker only; cross-host traffic always uses TLS.
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    else:
        raise ValueError("control URL requires HTTPS (HTTP allowed only on loopback)")
    return conn, parsed.path.rstrip("/")


def request(url, method, path, value=None, context=None, headers=None, timeout=3):
    conn, prefix = connection(url, context, timeout)
    try:
        body = None if value is None else canonical(value)
        fields = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, prefix + path, body=body, headers=fields)
        response = conn.getresponse()
        data = response.read(MAX_FRAME + 1)
        if len(data) > MAX_FRAME:
            raise ValueError("control response too large")
        if response.status == 404:
            return None
        if not 200 <= response.status < 300:
            detail = ""
            # HA handlers expose sanitized fixed messages/job IDs only. Never
            # include arbitrary Consul or application response bodies in errors.
            if path.startswith("/_ha/"):
                try:
                    value = json.loads(data).get("error")
                    if isinstance(value, str) and len(value) <= 1024:
                        detail = ": " + value
                except (ValueError, AttributeError):
                    pass
            raise RuntimeError(f"control request rejected: HTTP {response.status}" + detail)
        return json.loads(data) if data else None
    finally:
        conn.close()


class Consul:
    """Consul sessions and CAS+lock transaction; no local election fallback."""
    TTL = 15

    def __init__(self, config, context=None):
        self.url = config["url"]
        self.prefix = config.get("prefix", "vpnctl/ha")
        if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-" for c in self.prefix):
            raise ValueError("invalid Consul prefix")
        self.context = context
        self.headers = {}
        if config.get("token_file"):
            self.headers["X-Consul-Token"] = Path(config["token_file"]).read_text().strip()

    def call(self, method, path, value=None):
        try:
            return request(self.url, method, "/v1/" + path, value, self.context, self.headers)
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise RuntimeError("Consul coordination unavailable or invalid (" + type(error).__name__ + ")") from error

    def get(self, name):
        result = self.call("GET", "kv/" + self.prefix + "/" + name + "?consistent")
        if not result:
            return None
        item = result[0]
        item["record"] = json.loads(base64.b64decode(item["Value"], validate=True))
        return item

    def session(self, name):
        return self.call("PUT", "session/create", {
            "Name": "vpnctl-ha-" + name, "TTL": "15s", "LockDelay": "0s",
            "Behavior": "release", "Checks": [],
        })["ID"]

    def renew(self, session):
        start = time.monotonic()
        result = self.call("PUT", "session/renew/" + session)
        if not result or result[0]["ID"] != session:
            raise RuntimeError("Consul session no longer exists")
        # Never trust a larger returned TTL to extend our configured bound.
        return start + self.TTL

    def release(self, session):
        self.call("PUT", "session/destroy/" + session)

    def acquire(self, node, session):
        old = self.get("lease")
        if old and old.get("Session"):
            return None
        previous = old["record"] if old else None
        epoch = 1 if previous is None else previous["epoch"] + 1
        value = {"holder": node, "epoch": epoch, "session": session,
                 "previous": None if previous is None else {
                     "holder": previous["holder"], "epoch": previous["epoch"]}}
        key = self.prefix + "/lease"
        checks = [{"KV": {"Verb": "check-index", "Key": key, "Index": old["ModifyIndex"]}}] if old else [
            {"KV": {"Verb": "check-not-exists", "Key": key}}]
        checks.append({"KV": {"Verb": "lock", "Key": key, "Session": session,
                                "Value": base64.b64encode(canonical(value)).decode()}})
        self.call("PUT", "txn", checks)
        current = self.get("lease")
        if not current or current.get("Session") != session or current["record"] != value:
            raise RuntimeError("Consul grant changed during acquisition")
        return value

    def authority(self, node, epoch, session):
        item = self.get("lease")
        if not item or item.get("Session") != session:
            raise RuntimeError("no current quorum-backed session")
        record = item["record"]
        if record["holder"] != node or record["epoch"] != epoch or record["session"] != session:
            raise RuntimeError("controller epoch is no longer authoritative")
        return record

    def verify_voters(self):
        configuration = self.call("GET", "operator/raft/configuration")
        voters = [server for server in configuration["Servers"] if server.get("Voter") is True]
        if len(voters) != 3 or len({voter["ID"] for voter in voters}) != 3:
            raise RuntimeError("Consul must have exactly three distinct voting servers")

    def settings(self):
        item = self.get("settings")
        return {**item["record"], "_index": item["ModifyIndex"]} if item else {"paused": True, "target": None, "_index": 0}

    def set_settings(self, settings):
        value = {key: val for key, val in settings.items() if key != "_index"}
        result = self.call("PUT", "kv/" + self.prefix + "/settings?cas=" + str(settings.get("_index", 0)), value)
        if result is not True:
            raise RuntimeError("HA settings changed concurrently; refresh readiness and retry")
