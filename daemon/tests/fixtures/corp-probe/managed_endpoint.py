"""Loopback-only managed-artifact observer or pending endpoint fixture."""
import json
import os
import socket
import ssl
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
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    event("endpoint_ready", port=listener.getsockname()[1], pid=os.getpid())
    stream, _ = listener.accept()
    listener.close()
    event("endpoint_accepted")
    if ROLE == "observer":
        exec(HTTPS_TRANSCRIPT)
    else:
        assert ROLE == "hold"
        while control.recv(1):
            pass
except Exception as error:
    event("helper_error", category=type(error).__name__)
finally:
    control.close()
