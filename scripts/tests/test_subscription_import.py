#!/usr/bin/env python3
import importlib.util
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "subscription_import", Path(__file__).parents[1] / "import_from_subscription_server.py"
)
IMPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMPORT
SPEC.loader.exec_module(IMPORT)


class SubscriptionImportTest(unittest.TestCase):
    def test_plan_and_apply_redact_current_and_imported_identifiers(self):
        old_uuid = "00000000-0000-0000-0000-000000000001"
        new_uuid = "11111111-1111-1111-1111-111111111111"
        old_device = "22222222222222222222222222222222"
        new_device = "33333333333333333333333333333333"
        grants = [IMPORT.PlanRow("alice", "srv-a", new_uuid, old_uuid, "CHANGE")]
        devices = [IMPORT.DeviceIdPlanRow("alice", new_device, old_device, "SET")]
        for fail in [False, True]:
            output = StringIO()
            result = subprocess.CompletedProcess(
                [], 1 if fail else 0, "", " ".join([old_uuid, new_uuid, old_device, new_device])
            )
            # Each operation's error can contain its own SQL and identifiers.
            with redirect_stdout(output), redirect_stderr(output), mock.patch.object(
                IMPORT, "ssh_base_opts", return_value=["ssh"]
            ), mock.patch.object(IMPORT.subprocess, "run") as run:
                IMPORT.print_plan(grants)
                IMPORT.print_device_id_plan(devices)
                run.return_value = subprocess.CompletedProcess([], result.returncode, "", old_uuid + new_uuid)
                IMPORT.apply_changes("example.test", grants)
                run.return_value = subprocess.CompletedProcess([], result.returncode, "", old_device + new_device)
                IMPORT.apply_device_id_changes("example.test", devices)
            for identifier in [old_uuid, new_uuid, old_device, new_device]:
                self.assertNotIn(identifier, output.getvalue())
                self.assertIn(identifier[:8] + "…", output.getvalue())

    def test_missing_identifier_marker_is_preserved(self):
        self.assertEqual(IMPORT.redact_identifier(None), "(none)")

    def test_validation_errors_redact_malformed_identifiers(self):
        for label, pattern, value in [
            ("client_uuid", IMPORT._RE_UUID, "invalid-uuid-that-must-not-be-printed"),
            ("device_id", IMPORT._RE_DEVICE_ID, "invalid-device-id-that-must-not-be-printed"),
        ]:
            with self.assertRaises(ValueError) as error:
                IMPORT._assert_safe(value, pattern, label)
            self.assertNotIn(value, str(error.exception))
            self.assertIn(value[:8] + "…", str(error.exception))


if __name__ == "__main__":
    unittest.main()
