#!/usr/bin/env python3
"""Atomically install one engine-native assurance template from stdin."""

import hashlib
import json
import os
import re
import sys
import tempfile
import pwd
from pathlib import Path

PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9+_-]{0,63}$")
CONFIG_DIR = Path(os.environ.get("VPNCTL_ASSURANCE_CONFIG_DIR", "/etc/vpnctl/protocol-assurance.d"))


def die(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 3:
        die("usage: install-protocol-assurance-config.py <server> <protocol>")
    server, protocol = sys.argv[1:]
    if not server or len(server) > 255 or not PROTOCOL_RE.fullmatch(protocol):
        die("invalid server/protocol")
    raw = sys.stdin.buffer.read(262145)
    if not raw or len(raw) > 262144:
        die("invalid template size")
    try:
        wrapper = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        die("invalid JSON")
    if not isinstance(wrapper, dict):
        die("invalid template contract")
    if wrapper.get("engine") not in ("sing-box", "xray") or not isinstance(wrapper.get("config"), dict):
        die("invalid template contract")
    owner = os.environ.get("VPNCTL_ASSURANCE_USER", "user")
    try:
        account = pwd.getpwnam(owner)
    except KeyError:
        die("assurance user does not exist")
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if os.geteuid() == 0:
        os.chown(CONFIG_DIR, account.pw_uid, account.pw_gid)
    name = hashlib.sha256(server.encode()).hexdigest() + "." + protocol + ".json"
    fd, temporary = tempfile.mkstemp(prefix=".assurance-", dir=CONFIG_DIR)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(wrapper, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if os.geteuid() == 0:
            os.chown(temporary, account.pw_uid, account.pw_gid)
        os.replace(temporary, CONFIG_DIR / name)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print(name)


if __name__ == "__main__":
    main()
