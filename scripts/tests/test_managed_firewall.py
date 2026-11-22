import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[2] / "crates/kernels/src/firewall/ufw.py"
MARKER = "vpnctl managed ingress"


class Rule:
    def __init__(self, action, protocol, *, dport, dst="any", comment=""):
        self.action, self.protocol, self.dport, self.dst = action, protocol, dport, dst
        self.comment, self.direction, self.sport = comment, "in", "any"
        self.forward = self.remove = self.v6 = False
        self.logtype = self.interface_in = self.interface_out = self.dapp = self.sapp = ""
        self.set_v6(False)

    def set_v6(self, v6):
        self.v6 = v6
        self.src = "::/0" if v6 else "0.0.0.0/0"
        if self.dst in ("any", "0.0.0.0/0", "::/0"):
            self.dst = self.src

    def normalize(self):
        pass

    def get_comment(self):
        return bytes.fromhex(self.comment).decode("utf-8")

    def dup_rule(self):
        return SimpleNamespace(**vars(self))

    @staticmethod
    def match(existing, candidate):
        scope = ("v6", "src", "dst", "protocol", "dport", "sport", "direction")
        if any(getattr(existing, field) != getattr(candidate, field) for field in scope):
            return 1
        if existing.action != candidate.action:
            return -1
        return 0 if existing.comment == candidate.comment else -2


def hex_encode(comment):
    return comment.encode("utf-8").hex()


def fixture():
    modules = {
        "ufw": SimpleNamespace(),
        "ufw.common": SimpleNamespace(UFWRule=Rule),
        "ufw.frontend": SimpleNamespace(UFWFrontend=Mock()),
        "ufw.util": SimpleNamespace(create_lock=Mock(), hex_encode=hex_encode, release_lock=Mock()),
    }
    spec = importlib.util.spec_from_file_location("vpnctl_managed_ufw", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class ManagedFirewallTest(unittest.TestCase):
    def setUp(self):
        self.firewall = fixture()
        self.backend = Mock()

    def test_open_keeps_existing_rule_and_adds_missing_ipv6_half(self):
        manual = Rule("allow", "tcp", dport="8443", comment=hex_encode("manual"))
        self.backend.use_ipv6.return_value = True
        self.backend.get_rules_ipv4.return_value = [manual]
        self.backend.get_rules_ipv6.return_value = []
        self.firewall.open_ports(self.backend, [("tcp", 8443)])
        self.backend.set_rule.assert_called_once()
        new_rule = self.backend.set_rule.call_args.args[0]
        self.assertTrue(new_rule.v6)
        self.assertEqual(new_rule.get_comment(), MARKER)
        self.assertEqual(manual.get_comment(), "manual")

    def test_existing_deny_fails_before_adding_other_ports(self):
        deny = Rule("deny", "tcp", dport="443")
        deny.set_v6(True)
        self.backend.use_ipv6.return_value = True
        self.backend.get_rules_ipv4.return_value = []
        self.backend.get_rules_ipv6.return_value = [deny]

        with self.assertRaisesRegex(RuntimeError, r"UFW deny blocks 443/tcp \(IPv6\)"):
            self.firewall.open_ports(self.backend, [("tcp", 80), ("tcp", 443)])

        self.backend.set_rule.assert_not_called()

    def test_cleanup_removes_owned_stale_ports_and_keeps_all_dependencies(self):
        old = Rule("allow", "tcp", dport="8443", comment=hex_encode(MARKER))
        old.set_v6(True)
        manual = Rule("allow", "tcp", dport="8443", comment=hex_encode("manual"))
        dnstt = Rule("allow", "udp", dport="53", dst="198.51.100.7", comment=hex_encode("vpnctl DNSTT"))
        old_unmarked = Rule("allow", "tcp", dport="6443")
        live = Rule("allow", "tcp", dport="8444", comment=hex_encode(MARKER))
        ssh_open = Rule("allow", "tcp", dport="2200", comment=hex_encode(MARKER))
        ssh_config = Rule("allow", "tcp", dport="2222", comment=hex_encode(MARKER))
        desired = Rule("allow", "udp", dport="8443", comment=hex_encode(MARKER))
        altered_scope = Rule("allow", "tcp", dport="8445", comment=hex_encode(MARKER))
        altered_scope.interface_in = "eth0"
        self.backend.get_rules.return_value = [
            old, dnstt, manual, old_unmarked, live, ssh_open, ssh_config, desired, altered_scope
        ]
        report = io.StringIO()
        with (
            contextlib.redirect_stdout(report),
            patch.object(self.firewall.subprocess, "check_output", return_value=(
                "tcp LISTEN 0 4096 [::]:8444 [::]:*\n"
                "tcp LISTEN 0 4096 [::ffff:127.0.0.1]:8443 [::]:*\n"
                "udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n"
            )),
            patch.dict(self.firewall.os.environ, {"SSH_CONNECTION": "192.0.2.1 51000 198.51.100.7 2200"}),
        ):
            self.firewall.cleanup(self.backend, {("udp", 8443), ("tcp", 2222)})

        deleted = [call.args[0] for call in self.backend.set_rule.call_args_list]
        self.assertEqual(report.getvalue(), "tcp:6443\n")
        self.assertEqual(len(deleted), 2)
        for expected, deletion in zip([old, dnstt], deleted, strict=True):
            self.assertEqual(vars(deletion), {**vars(expected), "remove": True})

    def test_failed_listener_read_aborts_before_rule_changes(self):
        self.backend.get_rules.return_value = [
            Rule("allow", "tcp", dport="8443", comment=hex_encode(MARKER))
        ]
        with patch.object(
            self.firewall.subprocess, "check_output",
            side_effect=subprocess.CalledProcessError(1, "ss"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                self.firewall.cleanup(self.backend, set())
        self.backend.set_rule.assert_not_called()

    def test_inactive_ufw_is_unchanged_and_status_errors_are_reported(self):
        ufw = self.firewall.UFWFrontend.return_value
        ufw.get_status.side_effect = ["Status: inactive", RuntimeError("status failed")]
        with patch.object(sys, "argv", ["ufw.py", "cleanup", "tcp:22"]):
            self.firewall.main()
            with self.assertRaisesRegex(RuntimeError, "status failed"):
                self.firewall.main()
        self.assertEqual(ufw.backend.mock_calls, [])
        self.assertEqual(self.firewall.release_lock.call_count, 2)
