import gettext
import ipaddress
import os
import subprocess
import sys

from ufw.common import UFWRule
from ufw.frontend import UFWFrontend
from ufw.util import create_lock, hex_encode, release_lock

MARKER = "vpnctl managed ingress"
DNSTT_MARKER = "vpnctl DNSTT"
RULE_TRANSPORTS = ("tcp4", "tcp6", "udp4", "udp6")


def parse_port(value, transports=("tcp", "udp")):
    protocol, port_text = value.split(":")
    port = int(port_text)
    if protocol not in transports or not 1 <= port <= 65535:
        raise ValueError("invalid firewall port")
    return protocol, port


def listening_addresses():
    sockets = subprocess.check_output(["ss", "-H", "-lntu"], text=True)
    listeners = {}
    for fields in map(str.split, sockets.splitlines()):
        host, port_text = fields[4].rsplit(":", 1)
        port = parse_port(f"{fields[0]}:{port_text}")
        host = host.strip("[]").split("%", 1)[0]
        address = None if host == "*" else ipaddress.ip_address(host)
        if address is not None:
            address = getattr(address, "ipv4_mapped", None) or address
        listeners.setdefault(port, []).append(address)
    return listeners


def open_ports(backend, ports, address=None):
    families = (False, True) if address is None and backend.use_ipv6() else (False,)
    additions = []
    for v6 in families:
        for protocol, port in ports:
            rule = UFWRule("allow", protocol, dport=str(port),
                           dst=str(address) if address else "any",
                           comment=hex_encode(MARKER))
            rule.set_v6(v6)
            rule.normalize()
            # UFW's ordinary allow command replaces matching denies or comments.
            # Compare identities under UFW's lock so existing rules keep their owners.
            existing = backend.get_rules_ipv6() if v6 else backend.get_rules_ipv4()
            match = next((current for current in existing if UFWRule.match(current, rule) != 1), None)
            if match is None:
                additions.append(rule)
            elif match.action in ("deny", "reject"):
                family = "IPv6" if v6 else "IPv4"
                raise RuntimeError(f"UFW {match.action} blocks {port}/{protocol} ({family})")

    for rule in additions:
        backend.set_rule(rule)


def cleanup_port(rule):
    if (rule.action != "allow" or rule.direction != "in" or rule.forward
            or rule.logtype or rule.interface_in or rule.interface_out
            or rule.dapp or rule.sapp or rule.sport != "any"
            or rule.protocol not in ("tcp", "udp") or not rule.dport.isdecimal()):
        return None

    port = int(rule.dport)
    anywhere = "::/0" if rule.v6 else "0.0.0.0/0"
    if rule.src != anywhere:
        return None

    comment = rule.get_comment()
    if comment in ("", MARKER) and rule.dst == anywhere:
        return rule.protocol, port

    if (comment in (MARKER, DNSTT_MARKER)
            and not rule.v6 and (rule.protocol, port) == ("udp", 53)
            and ipaddress.IPv4Network(rule.dst, strict=False).prefixlen == 32):
        return rule.protocol, port

    return None


def has_listener(rule, addresses):
    if rule.dst in ("0.0.0.0/0", "::/0"):
        return any(address is None or not address.is_loopback for address in addresses)
    target = ipaddress.IPv4Interface(rule.dst).ip
    return any(
        address is None or address.is_unspecified or address == target
        for address in addresses
    )


def cleanup(backend, protected, previous_idle=None):
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) == 4:
        protected.add(parse_port(f"tcp:{connection[3]}"))

    rules = backend.get_rules()
    candidates = [
        (rule, port)
        for rule in rules
        if (port := cleanup_port(rule)) is not None and port not in protected
    ]
    if not candidates:
        return

    listeners = listening_addresses()
    clear_unmarked = (
        previous_idle is not None
        and backend._get_default_policy() in ("deny", "reject")
    )
    unmarked = set()
    for rule, port in candidates:
        if has_listener(rule, listeners.get(port, ())):
            continue
        transport, number = port
        family = 6 if rule.v6 else 4
        key = (f"{transport}{family}", number)
        if not rule.comment:
            if previous_idle is None:
                unmarked.add(port)
                continue
            if not clear_unmarked:
                continue
            # An empty comment in UFW's delete operation can also match
            # commented rules. Remove only when the whole match is unique.
            if sum(UFWRule.match(other, rule) != 1 for other in rules) != 1:
                continue
            if key not in previous_idle:
                unmarked.add(key)
                continue
        deletion = rule.dup_rule()
        deletion.remove = True
        try:
            backend.set_rule(deletion)
        except Exception:
            if previous_idle is None:
                raise
            print(f"failed {key[0]}:{key[1]}", flush=True)
            break
        if previous_idle is not None:
            print(f"removed {key[0]}:{key[1]}", flush=True)

    if previous_idle is None:
        if unmarked:
            print(" ".join(f"{protocol}:{port}" for protocol, port in sorted(unmarked)))
    else:
        for protocol, port in sorted(unmarked):
            print(f"idle {protocol}:{port}")


def main():
    action, *arguments = sys.argv[1:]
    previous_idle = None
    if action == "sweep":
        boundary = arguments.index("--")
        ports = set(map(parse_port, arguments[:boundary]))
        previous_idle = {
            parse_port(value, RULE_TRANSPORTS) for value in arguments[boundary + 1:]
        }
        address = None
    elif action == "allow-dnstt":
        address, = map(ipaddress.IPv4Address, arguments)
        ports = {("udp", 53)}
    elif action in ("allow", "cleanup"):
        address = None
        ports = set(map(parse_port, arguments))
    else:
        raise ValueError("invalid firewall action")

    gettext.install("ufw")
    lock = create_lock()
    try:
        firewall = UFWFrontend(False)
        status = firewall.get_status().partition("\n")[0]
        if status == "Status: inactive":
            return
        if status != "Status: active":
            raise RuntimeError("could not determine UFW status")
        if action in ("cleanup", "sweep"):
            cleanup(firewall.backend, ports, previous_idle)
        else:
            open_ports(firewall.backend, sorted(ports), address)
    finally:
        release_lock(lock)


if __name__ == "__main__":
    main()
