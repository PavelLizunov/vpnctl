import hashlib
import json
import os
import runpy
import stat
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ADAPTER = runpy.run_path(Path(__file__).parents[1] / "dnstt-assurance-on-demand.py")


class DnsttOnDemand(unittest.TestCase):
    def test_selected_address_invokes_the_one_shot_probe_once(self):
        probe = ADAPTER["probe"]
        output = json.dumps({
            "result": "verified", "protocol": "dnstt", "stage": "transfer",
            "https_requests": 1, "elapsed_ms": 1234,
        }).encode()

        def metadata(path):
            kind = stat.S_IFREG if path == ADAPTER["PROBE"] else stat.S_IFDIR
            return SimpleNamespace(st_uid=0, st_mode=kind | 0o755)

        def child(args, *, stdout, **_):
            stdout.write(output)
            return subprocess.CompletedProcess(args, 0)

        with (
            patch.dict(os.environ, {"VPNCTLD_ADMIN_PASSWORD": "fixture-password"}),
            patch("pathlib.Path.lstat", autospec=True, side_effect=metadata),
            patch("subprocess.run", side_effect=child) as run,
        ):
            result = probe(b'{"server":"192.0.2.17","protocol":"dnstt"}')
            name = hashlib.sha256(b"192.0.2.17").hexdigest() + ".dnstt.json"
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], [str(ADAPTER["PROBE"]), name])
            self.assertNotIn("VPNCTLD_ADMIN_PASSWORD", run.call_args.kwargs["env"])
        self.assertEqual(result, {
            "client_kind": "dnstt-on-demand",
            "stage": "transfer", "state": "verified", "failure_code": None, "latency_ms": 1234,
        })

    def test_invalid_request_does_not_invoke_the_probe(self):
        invalid = (b'[]', b'{"server":"192.0.2.17","protocol":"vless"}',
                   b'{"server":"/tmp/config","protocol":"dnstt"}')
        with patch("subprocess.run") as run:
            for request in invalid:
                self.assertEqual(ADAPTER["probe"](request)["failure_code"], "request_invalid")
            run.assert_not_called()

    def test_only_transfer_errors_count_as_degraded(self):
        interpret = ADAPTER["interpret"]
        for reason, state in (
            ("curl_exit_28", "degraded"),
            ("client_config_rejected", "unknown"),
            ("template_permissions_invalid", "unknown"),
            ("sensitive /fixture/path", "unknown"),
        ):
            result = interpret(1, json.dumps({"result": "failed", "reason": reason}).encode())
            self.assertEqual(result["state"], state)
            self.assertNotIn("/fixture/path", json.dumps(result))
        self.assertEqual(interpret(0, b'{"result":"verified"}')["state"], "unknown")
        self.assertEqual(interpret(0, b" " * 4097)["failure_code"], "runner_invalid_result")
