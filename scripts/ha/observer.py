"""Send one authenticated round of public controller health observations."""
from __future__ import annotations

import argparse
from contextlib import closing
import http.client
import ipaddress
import json
from pathlib import Path
import queue
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit


HEALTH_PATH = "/_vpnctl_ha/health"
CHALLENGE_PATH = "/_ha/observer-challenge"
REPORT_PATH = "/_ha/observer-report"
MAX_BODY = 4096
PHASE_SECONDS = 1.4
CONNECT_SECONDS = 0.7


class TcpUnavailable(OSError):
    """Every resolved address refused or timed out during TCP connect."""


def https_origin(value):
    if not isinstance(value, str) or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 or char in "?#\\"
        for char in value
    ):
        raise ValueError("expected an HTTPS origin")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.path not in ("", "/") or parsed.netloc.endswith(":")):
        raise ValueError("expected an HTTPS origin")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    port = 443 if parsed.port is None else parsed.port
    if not host or not port:
        raise ValueError("expected an HTTPS origin")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return host, port


def json_object(data):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    result = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise ValueError("expected a JSON object")
    return result


def verified_context(ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca is None:
        context.load_default_certs()
    else:
        context.load_verify_locations(cafile=ca)
    return context


def load_config(path):
    def credential_path(value):
        if not isinstance(value, str) or not value:
            raise ValueError("expected a credential path")
        return path.parent / value

    config = json_object(path.read_bytes())
    required = {"collector", "tls", "controllers"}
    if not required <= set(config) <= required | {"probe_ca"}:
        raise ValueError("invalid observer config fields")
    collector = https_origin(config["collector"])
    origins = config["controllers"]
    if not isinstance(origins, dict) or len(origins) != 2 or any(not node for node in origins):
        raise ValueError("expected two controller nodes")
    controllers = {node: https_origin(origin) for node, origin in origins.items()}
    if len(set(controllers.values())) != 2:
        raise ValueError("expected distinct controller origins")
    tls = config["tls"]
    if not isinstance(tls, dict) or set(tls) != {"ca", "cert", "key"}:
        raise ValueError("invalid collector TLS fields")
    collector_tls = verified_context(credential_path(tls["ca"]))
    collector_tls.minimum_version = ssl.TLSVersion.TLSv1_3
    collector_tls.load_cert_chain(credential_path(tls["cert"]), credential_path(tls["key"]))
    probe_ca = credential_path(config["probe_ca"]) if "probe_ca" in config else None
    return collector, collector_tls, controllers, verified_context(probe_ca)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("observer operation expired")
    return seconds


def tcp_connection(host, port, deadline):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    connect_deadline = min(deadline, time.monotonic() + CONNECT_SECONDS)
    only_unavailable = bool(addresses)
    for index, (family, kind, protocol, _, address) in enumerate(addresses):
        timeout = remaining(connect_deadline) / (len(addresses) - index)
        stream = socket.socket(family, kind, protocol)
        try:
            stream.settimeout(timeout)
            stream.connect(address)
        except (ConnectionRefusedError, TimeoutError):
            stream.close()
        except OSError:
            stream.close()
            only_unavailable = False
        else:
            return stream
    if only_unavailable:
        raise TcpUnavailable("controller TCP connection unavailable")
    raise OSError("TCP connection outcome unknown")


def read_response(response):
    lengths = response.headers.get_all("Content-Length", [])
    # HA endpoints send small JSON replies with Content-Length. Refuse transfer
    # codings to keep malformed chunk framing from bypassing the read bound.
    if (response.status != 200 or response.headers.defects or len(lengths) > 1
            or "Transfer-Encoding" in response.headers or "Content-Encoding" in response.headers):
        raise ValueError("invalid observer response")
    length = None
    if lengths:
        declared = lengths[0].strip(" \t")
        if not declared.isascii() or not declared.isdecimal():
            raise ValueError("invalid observer response length")
        length = int(declared)
        if length > MAX_BODY:
            raise ValueError("observer response too large")
    data = response.read(MAX_BODY + 1)
    if len(data) > MAX_BODY or (length is not None and len(data) != length):
        raise ValueError("invalid observer response length")
    return json_object(data)


def request(origin, context, method, path, deadline, value=None):
    host, port = origin
    headers = {"Connection": "close"}
    body = None
    if value is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    # Only the TCP connect above the verified TLS layer can attest unreachability.
    with tcp_connection(host, port, deadline) as stream:
        stream.settimeout(remaining(deadline))
        with context.wrap_socket(stream, server_hostname=host) as encrypted:
            encrypted.settimeout(remaining(deadline))
            with closing(http.client.HTTPSConnection(host, port, context=context)) as connection:
                connection.sock = encrypted
                connection.request(method, path, body=body, headers=headers)
                with connection.getresponse() as response:
                    return read_response(response)


def probe(node, origin, context, deadline):
    try:
        reply = request(origin, context, "GET", HEALTH_PATH, deadline)
    except TcpUnavailable:
        return "unreachable"
    if (set(reply) == {"node", "status"} and reply["node"] == node
            and reply["status"] in ("active", "standby", "unavailable", "unknown")):
        return reply["status"]
    return "unknown"


def bounded_calls(calls):
    """Bound each phase even when name resolution or an HTTP read stalls."""
    deadline = time.monotonic() + PHASE_SECONDS
    completed = queue.Queue()

    def run(name, call):
        try:
            value = call(deadline)
            remaining(deadline)
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            value = None
        completed.put((name, value))

    for name, call in calls.items():
        threading.Thread(target=run, args=(name, call), daemon=True).start()

    results = {}
    for _ in calls:
        try:
            name, value = completed.get(timeout=remaining(deadline))
        except (queue.Empty, TimeoutError):
            break
        results[name] = value
    return results


def observe(collector, collector_tls, controllers, probe_tls):
    challenge = bounded_calls({
        "challenge": lambda deadline: request(collector, collector_tls, "POST", CHALLENGE_PATH, deadline, {}),
    }).get("challenge")
    if (challenge is None or set(challenge) != {"nonce"}
            or not isinstance(challenge["nonce"], str) or not challenge["nonce"]):
        raise RuntimeError("observer challenge failed or was rejected")

    observations = bounded_calls({
        node: lambda deadline, node=node, origin=origin: probe(node, origin, probe_tls, deadline)
        for node, origin in controllers.items()
    })
    report = {
        "nonce": challenge["nonce"],
        "checks": {node: observations.get(node) or "unknown" for node in controllers},
    }
    reply = bounded_calls({
        "report": lambda deadline: request(collector, collector_tls, "POST", REPORT_PATH, deadline, report),
    }).get("report")
    if reply is None or set(reply) != {"accepted"} or reply["accepted"] is not True:
        raise RuntimeError("observer report failed or was rejected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except (OSError, ValueError, RecursionError):
        print("observer configuration or TLS credentials could not be loaded", file=sys.stderr)
        return 1
    try:
        observe(*config)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
