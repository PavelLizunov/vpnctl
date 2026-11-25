import gettext
import ipaddress
import json
import os
import shutil
import subprocess
import sys

UFWRule = None
UFWFrontend = None
create_lock = None
hex_encode = None
release_lock = None

MARKER = "vpnctl managed ingress"
DNSTT_MARKER = "vpnctl DNSTT"
RULE_TRANSPORTS = ("tcp4", "tcp6", "udp4", "udp6")


def _load_ufw():
    global UFWRule, UFWFrontend, create_lock, hex_encode, release_lock
    from ufw.common import UFWRule as _UFWRule
    from ufw.frontend import UFWFrontend as _UFWFrontend
    from ufw.util import (
        create_lock as _create_lock,
        hex_encode as _hex_encode,
        release_lock as _release_lock,
    )
    UFWRule = _UFWRule
    UFWFrontend = _UFWFrontend
    create_lock = _create_lock
    hex_encode = _hex_encode
    release_lock = _release_lock


def _extract_port_ranges(node, named_sets, table_key):
    if isinstance(node, int) and not isinstance(node, bool):
        return [(node, node)]
    if isinstance(node, str) and node.startswith("@"):
        return list(named_sets.get((table_key[0], table_key[1], node[1:]), ()))
    if isinstance(node, list):
        out = []
        for item in node:
            out.extend(_extract_port_ranges(item, named_sets, table_key))
        return out
    if isinstance(node, dict):
        if "range" in node and isinstance(node["range"], list) and len(node["range"]) == 2:
            lo, hi = node["range"]
            if isinstance(lo, int) and isinstance(hi, int):
                return [(lo, hi)]
        if "set" in node:
            return _extract_port_ranges(node["set"], named_sets, table_key)
        if "elem" in node:
            elem = node["elem"]
            if isinstance(elem, dict) and "val" in elem:
                return _extract_port_ranges(elem["val"], named_sets, table_key)
            return _extract_port_ranges(elem, named_sets, table_key)
    return []


def _extract_l4_protos(node):
    if isinstance(node, str):
        return {node} if node in ("tcp", "udp") else set()
    if isinstance(node, list):
        out = set()
        for item in node:
            out.update(_extract_l4_protos(item))
        return out
    if isinstance(node, dict):
        if "set" in node:
            return _extract_l4_protos(node["set"])
        if "elem" in node:
            elem = node["elem"]
            if isinstance(elem, dict) and "val" in elem:
                return _extract_l4_protos(elem["val"])
            return _extract_l4_protos(elem)
    return set()


def _extract_ct_states(node):
    if isinstance(node, str):
        return {node}
    if isinstance(node, list):
        out = set()
        for item in node:
            out.update(_extract_ct_states(item))
        return out
    if isinstance(node, dict):
        if "set" in node:
            return _extract_ct_states(node["set"])
        if "elem" in node:
            elem = node["elem"]
            if isinstance(elem, dict) and "val" in elem:
                return _extract_ct_states(elem["val"])
            return _extract_ct_states(elem)
    return set()


def find_nft_blocked_ports(ruleset, ports):
    items = ruleset.get("nftables") if isinstance(ruleset, dict) else None
    if not isinstance(items, list):
        return []

    dormant = set()
    named_sets = {}
    drop_chains = set()

    for item in items:
        if not isinstance(item, dict):
            continue
        table = item.get("table")
        if isinstance(table, dict):
            flags = table.get("flags") or []
            if "dormant" in flags:
                dormant.add((table.get("family"), table.get("name")))
        nft_set = item.get("set")
        if isinstance(nft_set, dict):
            key = (nft_set.get("family"), nft_set.get("table"), nft_set.get("name"))
            named_sets[key] = _extract_port_ranges(
                nft_set.get("elem"), {}, (nft_set.get("family"), nft_set.get("table"))
            )

    for item in items:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if not isinstance(chain, dict):
            continue
        family = chain.get("family")
        table_name = chain.get("table")
        if (
            family in ("inet", "ip", "ip6")
            and (family, table_name) not in dormant
            and chain.get("hook") == "input"
            and chain.get("policy") == "drop"
        ):
            drop_chains.add((family, table_name, chain.get("name")))

    if not drop_chains:
        return []

    allowed_by_chain = {chain_key: set() for chain_key in drop_chains}
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        chain_key = (rule.get("family"), rule.get("table"), rule.get("chain"))
        if chain_key not in allowed_by_chain:
            continue
        expr = rule.get("expr")
        if not isinstance(expr, list):
            continue
        if not any(isinstance(step, dict) and "accept" in step for step in expr):
            continue

        skip_rule = False
        l4_protos = set()
        dport_entries = []
        for step in expr:
            if not isinstance(step, dict) or "match" not in step:
                continue
            match = step["match"]
            if not isinstance(match, dict):
                continue
            op = match.get("op")
            if op not in ("==", "in", None):
                skip_rule = True
                break
            left = match.get("left")
            right = match.get("right")
            if not isinstance(left, dict):
                continue
            if "meta" in left and isinstance(left["meta"], dict):
                meta_key = left["meta"].get("key")
                if meta_key in ("iifname", "iif") and right == "lo":
                    skip_rule = True
                    break
                if meta_key == "l4proto":
                    l4_protos.update(_extract_l4_protos(right))
            elif "ct" in left and isinstance(left["ct"], dict):
                if left["ct"].get("key") == "state":
                    states = _extract_ct_states(right)
                    if "new" not in states:
                        skip_rule = True
                        break
            elif "payload" in left and isinstance(left["payload"], dict):
                proto = left["payload"].get("protocol")
                field = left["payload"].get("field")
                if field == "saddr":
                    skip_rule = True
                    break
                if field == "dport" and proto in ("tcp", "udp", "th"):
                    ranges = _extract_port_ranges(
                        right, named_sets, (chain_key[0], chain_key[1])
                    )
                    dport_entries.append((proto, ranges))

        if skip_rule:
            continue

        if dport_entries:
            for proto, ranges in dport_entries:
                target_protos = l4_protos if proto == "th" else {proto}
                for target_proto in target_protos:
                    for port_proto, port_num in ports:
                        if port_proto == target_proto and any(
                            lo <= port_num <= hi for lo, hi in ranges
                        ):
                            allowed_by_chain[chain_key].add((port_proto, port_num))
        elif l4_protos:
            for port_proto, port_num in ports:
                if port_proto in l4_protos:
                    allowed_by_chain[chain_key].add((port_proto, port_num))

    blocked = set()
    for port in ports:
        if any(port not in allowed for allowed in allowed_by_chain.values()):
            blocked.add(port)
    return sorted(blocked)


def check_nftables_drop_policy(ports):
    search_path = os.environ.get("PATH", "")
    search_path = f"{search_path}:/usr/sbin:/sbin" if search_path else "/usr/sbin:/sbin"
    nft = shutil.which("nft", path=search_path)
    if nft is None or not ports:
        return
    try:
        proc = subprocess.run(
            [nft, "-j", "list", "ruleset"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return
    if proc.returncode != 0 or not proc.stdout.strip():
        return
    try:
        ruleset = json.loads(proc.stdout)
    except ValueError:
        return
    blocked = find_nft_blocked_ports(ruleset, ports)
    if blocked:
        print(" ".join(f"nft-blocked:{proto}:{port}" for proto, port in blocked))


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

    # UFW checks the permissions of argv[0], which is "-" for stdin.
    ufw_path = shutil.which("ufw")
    if ufw_path is None:
        if action == "cleanup":
            check_nftables_drop_policy(ports)
            return
        raise RuntimeError("UFW executable not found on PATH")
    _load_ufw()
    sys.argv[0] = os.path.abspath(ufw_path)
    gettext.install("ufw")
    lock = create_lock()
    try:
        firewall = UFWFrontend(False)
        status = firewall.get_status().partition("\n")[0]
        if status == "Status: inactive":
            if action == "cleanup":
                check_nftables_drop_policy(ports)
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
