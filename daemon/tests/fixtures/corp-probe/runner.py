#!/usr/bin/python3
"""Actual child-owned SOCKS/TLS fixture. Paths/settings are prepended by Rust."""
import json
import os
import select
import socket
import ssl
import stat
import struct
import sys


def exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


control = socket.socket(socket.AF_UNIX)
control.connect(EVENT_PATH)


def event(kind, **data):
    control.sendall((json.dumps(dict(kind=kind, **data)) + "\n").encode())


try:
    assert len(sys.argv) == 4 and sys.argv[1:3] == ["run", "-c"]
    with open(sys.argv[3], encoding="utf-8") as source:
        config = json.load(source)
    event(
        "config", config=config, pid=os.getpid(), argv=sys.argv,
        env=[item.decode() for item in open("/proc/self/environ", "rb").read().split(b"\x00") if item], cwd=os.getcwd(),
        config_mode=stat.S_IMODE(os.stat(sys.argv[3]).st_mode),
        dir_mode=stat.S_IMODE(os.stat(os.getcwd()).st_mode),
        stdio=[os.readlink("/proc/self/fd/" + str(fd)) for fd in range(3)],
    )
    if MODE == "early_exit":
        sys.exit(17)
    inbound = config["inbounds"][0]
    assert inbound["type"] == "socks" and inbound["listen"] == "127.0.0.1"
    if MODE == "foreign":
        # This unrelated Rust-owned process binds and accepts the actual port.
        relay = socket.socket(socket.AF_UNIX)
        relay.connect(FOREIGN_PATH)
        relay.sendall((str(inbound["listen_port"]) + "\n").encode())
        relay.recv(1)
        sys.exit(0)
    listener = socket.socket()
    listener.bind(("127.0.0.1", inbound["listen_port"]))
    listener.listen(1)
    pending_remote = None
    if MODE == "delayed_accept":
        event("listening")
        # Readability establishes that the kernel queued a real connection,
        # without installing its accepted socket in this process's fd table.
        select.select([listener], [], [])
        local = "0100007F:%04X" % inbound["listen_port"]

        def pending_snapshot():
            with open("/proc/self/net/tcp", encoding="ascii") as source:
                rows = [line.split() for line in source.readlines()[1:]]
            rows = [row for row in rows if row[1] == local and row[3] != "0A"]
            assert len(rows) == 1, "exactly one retained TCP connection is required"
            row = rows[0]
            assert row[3] == "01", "the original connection must stay established"
            assert int(row[9]) == 0, "accepted fd must not exist before release"
            queued_bytes = int(row[4].split(":")[1], 16)
            assert queued_bytes == 0, "SOCKS bytes arrived before child ownership"
            return dict(remote=row[2], inode=0, queued_bytes=queued_bytes,
                        connections=len(rows))

        pending = pending_snapshot()
        pending_remote = pending["remote"]
        event("pending_accept", **pending)
        while True:
            command = b""
            while not command.endswith(b"\n"):
                command += exact(control, 1)
            pending = pending_snapshot()
            assert pending["remote"] == pending_remote, "runner replaced its TCP stream"
            if command == b"release\n":
                break
            assert command == b"inspect\n"
            event("pending_accept_checked", **pending)
    stream, peer = listener.accept()
    if pending_remote is not None:
        assert peer == ("127.0.0.1", int(pending_remote.split(":")[1], 16))
        listener.setblocking(False)
        try:
            extra, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            extra.close()
            raise AssertionError("runner queued a second TCP connection")
    listener.close()
    event("accepted")
    if MODE in ("stall", "controlled"):
        # Event/control IO, rather than elapsed sleeps, establishes this state.
        while control.recv(1) != b"\n":
            pass
    assert exact(stream, 3) == b"\x05\x01\x02"
    if MODE == "no_auth":
        stream.sendall(b"\x05\x00")
        sys.exit(0)
    if MODE == "refused_method":
        stream.sendall(b"\x05\xff")
        sys.exit(0)
    stream.sendall(b"\x05\x02")
    assert exact(stream, 1) == b"\x01"
    username = exact(stream, exact(stream, 1)[0]).decode()
    password = exact(stream, exact(stream, 1)[0]).decode()
    assert inbound["users"] == [{"username": username, "password": password}]
    event("authenticated")
    stream.sendall(b"\x01\x01" if MODE == "auth_failure" else b"\x01\x00")
    if MODE == "auth_failure":
        sys.exit(0)
    assert exact(stream, 4) == b"\x05\x01\x00\x03"
    assert exact(stream, exact(stream, 1)[0]) == b"admin.corp.ninitux.com"
    assert exact(stream, 2) == struct.pack("!H", 443)
    if MODE == "wrong_socks":
        stream.sendall(b"\x05\x00\x01\x01\x7f\x00\x00\x01\x01\xbb")
        sys.exit(0)
    if MODE == "connect_denied":
        stream.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x01\xbb")
        sys.exit(0)
    if MODE == "ipv6":
        stream.sendall(b"\x05\x00\x00\x04" + bytes(16) + b"\x01\xbb")
    elif MODE == "domain":
        stream.sendall(b"\x05\x00\x00\x03\x09localhost\x01\xbb")
    else:
        stream.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
    exec(HTTPS_TRANSCRIPT)
except Exception as error:
    event("helper_error", category=type(error).__name__)
finally:
    control.close()
