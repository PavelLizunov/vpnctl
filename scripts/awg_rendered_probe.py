#!/usr/bin/env python3
"""Probe public-renderer fixtures against an official native AWG client.

Binaries must already exist; no builds, downloads, default routes or host-network
changes. Example (root, fresh NET namespace, explicitly NO PID namespace):
  unshare --net -- python3 scripts/awg_rendered_probe.py --isolated-netns \
    --helpers /exact/approved/scripts/awg_official_interop.py \
    --fixtures /tmp/vpnctl-awg-rendered-PID-N --sing-box /path/sing-box \
    --official /path/amneziawg-go --official-sha256 SHA256 \
    --awg-tool /path/awg --awg-tool-sha256 SHA256

The caller attests both official binaries' source revisions using their build
hashes. --helpers imports trusted Python code, and all binaries are trusted code.
The guarded run uses the generated payload with ONLY logging disabled. Before
it, a separate fresh mutation-control run validates the original guards, then
sets ONLY route.rules=[] in its private copy (in addition to disabled logging).
All three negative IPv4 targets must succeed with nonzero TCP/UDP counters in
that control, then be rejected in the guarded run; both runs must pass. No
endpoint, DNS, API, or port rewriting. Imports the generated
native file using official `awg setconf`, stripping ONLY Interface Address/DNS/
MTU (the applicable awg-quick fields). No handwritten UAPI set translation.

Both native Address families are installed. Source-selected policy tables have
ONLY exact test host routes, overriding local delivery for bound probe sockets.
This is deliberate test safety, not a test of installing OS default routes.
Unbound sing-box direct sockets and native outer UDP remain on loopback. All
changed routes/rules live in the guarded disposable namespace. Generated input
files remain caller-owned; our private copies, children and sockets are cleaned.
Output is fixed-schema JSONL, never configurations, UAPI replies or child logs.
Use --self-test alone for the offline strip/validation check (no runtime proof).
"""
import argparse
import base64
import contextlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True


class Failure(Exception):
    """Fixed internal reason code, never external exception text."""


class Interrupted(BaseException):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("arguments")


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def require(condition, code):
    if not condition:
        raise Failure(code)


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                "fixture_permissions")
        data = source.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024, "fixture_size")
        return data


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def strip_native(text, version):
    """Retain every non-quick line verbatim, including HP base64 and booleans."""
    section, fields, stripped = "", {}, []
    for line in text.splitlines(keepends=True):
        clean = line.split("#", 1)[0].strip()
        if clean.startswith("["):
            section = clean.lower()
        elif "=" in clean:
            name, value = (part.strip() for part in clean.split("=", 1))
            key = (section, name.lower())
            require(key not in fields, "native_duplicate")
            fields[key] = value
            if section == "[interface]" and name.lower() in ("address", "dns", "mtu"):
                continue
        stripped.append(line)
    addresses = [ipaddress.ip_interface(item.strip())
                 for item in fields.get(("[interface]", "address"), "").split(",")]
    require(len(addresses) == 2 and {a.version for a in addresses} == {4, 6}, "native_address")
    require(all(a.network.prefixlen == a.max_prefixlen for a in addresses), "native_address")
    require(fields.get(("[peer]", "endpoint")) == f"198.18.0.1:{51819 + version}", "native_endpoint")
    allowed = fields.get(("[peer]", "allowedips"), "")
    require({a.strip() for a in allowed.split(",")} == {"0.0.0.0/0", "::/0"}, "native_allowed_ips")
    require(fields.get(("[interface]", "mtu")) == "1280", "native_mtu")
    if version == 3:
        hp = fields.get(("[interface]", "headerprotectionkey"), "")
        require(len(base64.b64decode(hp, validate=True)) == 32, "native_hp_base64")
        require(fields.get(("[interface]", "randomtrailers")) == "on"
                and fields.get(("[interface]", "disablecookies")) == "on", "native_booleans")
    return "".join(stripped).encode(), {a.version: str(a.ip) for a in addresses}


def run(command, code):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=20)
    require(result.returncode == 0, code)


def routed_probe(h, address, port, source, udp, timeout):
    """Bound native source, exact helper payloads; supports both socket families."""
    received = b""
    try:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
            sock.bind((source, 0))
            deadline = time.monotonic() + timeout
            sock.settimeout(timeout)
            sock.connect((address, port))
            if udp:
                for payload in h.UDP_PAYLOADS:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    sock.send(payload)
                    received = sock.recv(4096)
                    if received != payload:
                        return "mismatch"
                return "ok"
            sock.sendall(h.REQUEST)
            while len(received) < len(h.RESPONSE):
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                part = sock.recv(len(h.RESPONSE) + 1 - len(received))
                if not part:
                    return "mismatch"
                received += part
            return "ok" if received == h.RESPONSE else "mismatch"
    except TimeoutError:
        return "mismatch" if received else "timeout"
    except OSError:
        return "io_error"


def services(h, cleanup, address):
    counter = {"tcp": 0, "udp": 0}
    lock = threading.Lock()

    class HTTP(h.HTTPHandler):
        def handle(self):
            with lock:
                counter["tcp"] += 1  # Conservative: any accepted connection counts.
            super().handle()

    class UDP(h.UDPHandler):
        def handle(self):
            with lock:
                counter["udp"] += 1  # Count even malformed application requests.
            super().handle()

    class TCP6(h.TCPServer):
        address_family = socket.AF_INET6

    class UDP6(h.UDPServer):
        address_family = socket.AF_INET6

    v6 = ":" in address
    tcp = h.serve(cleanup, TCP6 if v6 else h.TCPServer, address, HTTP)
    udp = h.serve(cleanup, UDP6 if v6 else h.UDPServer, address, UDP)
    return {"address": address, "tcp": tcp, "udp": udp, "counter": counter, "lock": lock}


def pair_probe(h, service, address, source, timeout):
    if source is None and ":" not in address:
        return {"tcp": h.http_probe(address, service["tcp"], timeout),
                "udp": h.udp_probe(address, service["udp"], timeout)}
    source = source or "::"
    return {kind: routed_probe(h, address, service[kind], source, kind == "udp", timeout)
            for kind in ("tcp", "udp")}


def route_proof(network, target, source, interface):
    family = "-6" if ":" in target else "-4"
    route = network.inspect(family, "route", "get", target, "from", source)
    require(len(route) == 1 and route[0].get("dev") == interface, "route_capture")


def scenario(args, h, network, version, mutation_control=False):
    config = json.loads(private_read(args.fixtures / f"awg{version}.server.json"))
    native, addresses = strip_native(private_read(args.fixtures / f"awg{version}.conf").decode(), version)
    endpoints = config.get("endpoints", [])
    require(len(endpoints) == 1, "server_endpoints")
    endpoint = endpoints[0]
    require(endpoint.get("listen_port") == 51819 + version and endpoint.get("system") is False,
            "server_endpoint")
    require(endpoint.get("address") == [f"10.{70 + version}.0.1/32", f"fd{70 + version}:{70 + version}::1/128"],
            "server_address")
    require(set(endpoint["peers"][0]["allowed_ips"]) == {addresses[4] + "/32", addresses[6] + "/128"},
            "server_peer_address")
    # Refuse fixtures missing the actual public renderer's guards; never synthesize them.
    tags = [f"awg{version}-in"]
    require(config.get("route") == {"rules": [
        {"inbound": tags, "ip_is_private": True, "action": "reject"},
        {"inbound": tags, "ip_cidr": ["198.18.0.1/32"], "action": "reject"}], "final": "direct"},
        "server_guards")
    require(endpoint.get("tag") == tags[0], "server_tag")
    # Guarded run changes only logging to avoid host filesystem writes. The
    # separate mutation control removes ONLY the validated route rules in this
    # private in-memory copy; the original fixture is reloaded for every run.
    config["log"] = {"disabled": True}
    if mutation_control:
        config["route"]["rules"] = []
    interface = "awr" + secrets.token_hex(5)
    socket_path = Path("/var/run/amneziawg") / (interface + ".sock")
    require(not os.path.lexists(socket_path), "socket_collision")
    identity = []
    with tempfile.TemporaryDirectory(prefix="awg-rendered-probe-") as directory, contextlib.ExitStack() as cleanup:
        cleanup.callback(h.unlink_owned, socket_path, identity)
        env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
               "LOG_LEVEL": "silent", "WG_PROCESS_FOREGROUND": "1"}
        native_process = h.launch(cleanup, [str(args.official), "-f", interface], env)
        cleanup.callback(h.remember_socket, socket_path, identity)

        def ready():
            h.remember_socket(socket_path, identity)
            return bool(identity) and bool(h.uapi(socket_path, "get=1\n\n"))

        h.wait_ready(ready, [native_process])
        stripped_path = Path(directory) / "native.conf"
        private_write(stripped_path, native)
        run([str(args.awg_tool), "setconf", interface, str(stripped_path)], "official_conf_import")
        # Capture actual native state after the OFFICIAL parser, not an INI prediction.
        state = h.uapi(socket_path, "get=1\n\n")
        require({line.split("=", 1)[1] for line in state if line.startswith("allowed_ip=")}
                == {"0.0.0.0/0", "::/0"}, "uapi_allowed_ips")
        require(sum(line.startswith("public_key=") for line in state) == 1, "uapi_peer")
        require(f"endpoint=198.18.0.1:{51819 + version}" in state, "uapi_endpoint")
        for family, address in addresses.items():
            network.change("-4" if family == 4 else "-6", "address", "add",
                           address + ("/32" if family == 4 else "/128"), "dev", interface,
                           *(["nodad"] if family == 6 else []))
        network.change("link", "set", "dev", interface, "mtu", "1280", "up")
        # Synthetic external addresses are local aliases: allow their decrypted
        # replies on this TUN, without changing host/all/default sysctls. These
        # per-device settings disappear with the owned device/NET namespace.
        network.guard()
        for setting, value in (("accept_local", "1"), ("rp_filter", "0")):
            Path(f"/proc/sys/net/ipv4/conf/{interface}/{setting}").write_text(value)
        server_path = Path(directory) / "server.json"
        private_write(server_path, json.dumps(config).encode())
        run([str(args.sing_box), "check", "-c", str(server_path)], "server_config_check")
        sing = h.launch(cleanup, [str(args.sing_box), "run", "-c", str(server_path)], env)
        processes = [native_process, sing]
        # Existing renderer API, not an injected inbound/health route. Start
        # before ephemeral echo listeners so none can claim the fixed AWG port.
        h.wait_ready(lambda: h.listener_ready(9090), processes)
        # Loopback public/external/private aliases were installed before this case.
        targets = {"external_v4": services(h, cleanup, "198.18.0.2"),
                   "external_v6": services(h, cleanup, "2001:db8::2"),
                   "node_public": services(h, cleanup, "198.18.0.1"),
                   "private": services(h, cleanup, "192.168.99.1"),
                   "tunnel_own": services(h, cleanup, "127.0.0.1")}
        for service in targets.values():
            direct = pair_probe(h, service, service["address"], None, args.timeout)
            require(all(value == "ok" for value in direct.values()), "direct_service_control")
            with service["lock"]:
                service["counter"].update(tcp=0, udp=0)
        # Local routes normally win before policy routing. Keep the local lookup,
        # but move it after our source-only table (never add/replace a default).
        targets["tunnel_own"]["target"] = f"10.{70 + version}.0.1"
        for family, source in addresses.items():
            flag, prefix, table = ("-4", "/32", "472") if family == 4 else ("-6", "/128", "473")
            network.change(flag, "rule", "add", "pref", "50", "from", source + prefix, "table", table)
            cleanup.callback(network.change, flag, "rule", "del", "pref", "50", "from", source + prefix, "table", table)
            for service in targets.values():
                target = service.get("target", service["address"])
                if (":" in target) != (family == 6):
                    continue
                network.change(flag, "route", "add", "table", table, target + prefix,
                               "dev", interface, "src", source)
                cleanup.callback(network.change, flag, "route", "del", "table", table,
                                 target + prefix, "dev", interface)
                route_proof(network, target, source, interface)
        outer = network.inspect("-4", "route", "get", "198.18.0.1", "ipproto", "udp",
                                "dport", str(51819 + version))
        require(len(outer) == 1 and outer[0].get("dev") == "lo", "outer_endpoint_route")
        emit({"kind": "import", "version": version, "pass": True,
              "parser": "official_awg_setconf", "allowed_ipv4_default": True,
              "allowed_ipv6_default": True, "address_families": [4, 6],
              "exact_host_routes": len(targets), "outer_endpoint_loopback": True,
              "mutation_control": mutation_control, "negative_ipv4_only": True,
              "route_guards_unchanged": not mutation_control,
              "logging_disabled_only": not mutation_control})

        def public_control():
            for name in ("external_v4", "external_v6"):
                service = targets[name]
                address = service["address"]
                outcome = pair_probe(h, service, address, addresses[6 if ":" in address else 4], args.timeout)
                h.alive(processes)
                require(all(value == "ok" for value in outcome.values()), "tunnel_public_control")
            require(h.handshake_seen(socket_path), "native_handshake")

        public_control()
        rows = []
        for name in ("node_public", "tunnel_own", "private"):
            service = targets[name]
            target = service.get("target", service["address"])
            outcome = pair_probe(h, service, target, addresses[4], args.timeout)
            h.alive(processes)
            # A dead/disconnected server may not turn a timeout into a guard pass.
            public_control()
            with service["lock"]:
                counters = dict(service["counter"])
            if mutation_control:
                passed = all(value == "ok" for value in outcome.values()) and all(
                    count > 0 for count in counters.values())
            else:
                passed = all(value in ("timeout", "io_error") for value in outcome.values()) and not any(counters.values())
            rows.append(passed)
            emit({"kind": "mutation_control" if mutation_control else "block",
                  "version": version, "target": name, "pass": passed,
                  "tcp": outcome["tcp"], "udp": outcome["udp"], "requests": counters,
                  "alive": True, "public_controls": True, "negative_ipv4_only": True,
                  "route_guards_unchanged": not mutation_control})
        emit({"kind": "case", "version": version, "pass": all(rows),
              "mutation_control": mutation_control, "negative_ipv4_only": True,
              "ipv4_tcp_udp": True, "ipv6_tcp_udp": True, "native_handshake": True})
        return all(rows)


def self_test():
    """Offline strip/security contract check; no binaries, files or network."""
    text = ("# synthetic\n[Interface]\nPrivateKey = synthetic\n"
            "Address = 10.72.0.2/32, fd72:72::2/128\nDNS = 1.1.1.1\nMTU = 1280\n"
            "Jc = 4\n[Peer]\nPublicKey = synthetic\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.18.0.1:51821\n")
    stripped, addresses = strip_native(text, 2)
    expected = "".join(line for line in text.splitlines(keepends=True)
                       if not line.startswith(("Address =", "DNS =", "MTU =")))
    require(stripped == expected.encode() and set(addresses) == {4, 6}, "self_test_strip")
    hp = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="  # Public RFC vector.
    text3 = text.replace("51821", "51822").replace(
        "Jc = 4", f"HeaderProtectionKey = {hp}\nRandomTrailers = on\nDisableCookies = on")
    stripped3, _ = strip_native(text3, 3)
    require(f"HeaderProtectionKey = {hp}\nRandomTrailers = on\nDisableCookies = on".encode()
            in stripped3, "self_test_encoding")
    for invalid, version in ((text.replace("::/0", "2001:db8::/32"), 2),
                             (text.replace("198.18.0.1", "127.0.0.1"), 2),
                             (text.replace("::2/128", "::2/64"), 2),
                             (text3.replace("RandomTrailers = on", "RandomTrailers = true"), 3)):
        try:
            strip_native(invalid, version)
        except Failure:
            continue
        raise Failure("self_test_rejection")
    emit({"kind": "self_test", "pass": True, "runtime_tested": False})
    return 0


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--sing-box", required=True, type=Path)
    parser.add_argument("--official", required=True, type=Path)
    parser.add_argument("--official-sha256", required=True)
    parser.add_argument("--awg-tool", type=Path)
    parser.add_argument("--awg-tool-sha256")
    parser.add_argument("--version", type=int, choices=(2, 3))
    parser.add_argument("--isolated-netns", action="store_true")
    parser.add_argument("--timeout", type=float, default=12)
    args = parser.parse_args()
    require(3 <= args.timeout <= 30, "arguments")
    require(args.awg_tool is not None and args.awg_tool_sha256 is not None, "official_awg_tool_required")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    helpers = args.helpers.resolve(strict=True)
    require(helpers.name == "awg_official_interop.py", "helpers_path")
    spec = importlib.util.spec_from_file_location("approved_awg_helpers", helpers)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    network = h.Network(args.isolated_netns)
    # No PID namespace: helper compares /proc/self/ns/net to /proc/1/ns/net.
    require(os.stat("/proc/self/ns/pid").st_ino == os.stat("/proc/1/ns/pid").st_ino, "pid_namespace")
    hashes = {}
    for name in ("sing_box", "official", "awg_tool"):
        binary = getattr(args, name).resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "binary_missing")
        setattr(args, name, binary)
        hashes[name + "_sha256"] = h.digest(binary)
    require(hashes["official_sha256"] == args.official_sha256.lower(), "official_digest_mismatch")
    require(hashes["awg_tool_sha256"] == args.awg_tool_sha256.lower(), "awg_tool_digest_mismatch")
    emit({"kind": "provenance", "source_attestation": "caller_supplied_digests",
          "helpers_sha256": h.digest(helpers), **hashes})
    for address in ("198.18.0.1/32", "198.18.0.2/32", "192.168.99.1/32"):
        network.change("-4", "address", "add", address, "dev", "lo")
    network.change("-6", "address", "add", "2001:db8::2/128", "dev", "lo", "nodad")
    for family in ("-4", "-6"):
        # Move, do not remove local delivery; own namespace is discarded by caller.
        rules = network.inspect(family, "rule", "show")
        require(all(rule.get("priority") in (0, 32766, 32767) for rule in rules), "namespace_rules")
        network.change(family, "rule", "add", "pref", "100", "lookup", "local")
        network.change(family, "rule", "del", "pref", "0", "lookup", "local")
    outcomes = []
    for version in ([args.version] if args.version else [2, 3]):
        # Fresh processes/services/TUN for each run. The same target IPs must
        # succeed without guards, then be rejected by the original guarded copy.
        for mutation_control in (True, False):
            try:
                outcomes.append(scenario(args, h, network, version, mutation_control))
            except Failure as error:
                outcomes.append(False)
                emit({"kind": "case", "version": version, "pass": False,
                      "mutation_control": mutation_control, "negative_ipv4_only": True,
                      "failure": str(error)})
            except Exception:
                # Includes helper errors: don't forward external exception text.
                outcomes.append(False)
                emit({"kind": "case", "version": version, "pass": False,
                      "mutation_control": mutation_control, "negative_ipv4_only": True,
                      "failure": "runtime_error"})
    passed = bool(outcomes) and all(outcomes)
    emit({"kind": "summary", "pass": passed, "cases": len(outcomes)})
    return 0 if passed else 1


def interrupted(signum, frame):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise Interrupted()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        code = self_test() if sys.argv[1:] == ["--self-test"] else main()
    except Interrupted:
        emit({"kind": "fatal", "pass": False, "failure": "interrupted"})
        code = 1
    except Failure as error:
        emit({"kind": "fatal", "pass": False, "failure": str(error)})
        code = 1
    except Exception:
        emit({"kind": "fatal", "pass": False, "failure": "internal_error"})
        code = 1
    raise SystemExit(code)
