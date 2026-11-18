"""Spec-only Worker deadline tests; no process or systemd unit is started."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
from worker import Worker  # noqa: E402


class Clocks:
    def __init__(self):
        self.monotonic = 1000.0
        self.boottime = 2000.0

    def advance_boot(self, seconds):
        self.boottime += seconds


class NoSystemdWorker(Worker):
    """Override only the command/property/stop fixture surface in the spec."""

    def __init__(self, config, clocks):
        self.clocks = clocks
        self.commands = []
        self.stop_calls = 0
        self.property_calls = 0
        self.on_command = None
        self.on_properties = None
        self.on_stop = None
        super().__init__(config)

    def command(self, *args, check=True):
        self.commands.append((args, check))
        if self.on_command is not None:
            self.on_command()
        return ""

    def properties(self):
        self.property_calls += 1
        if self.on_properties is not None:
            self.on_properties()
        return {
            "ActiveState": "active",
            "KillMode": "control-group",
            "SendSIGKILL": "yes",
            "Restart": "no",
            "WatchdogUSec": "2s",
            "NotifyAccess": "main",
            "WatchdogSignal": "9",
            "ProtectControlGroups": "yes",
            "NoNewPrivileges": "yes",
            "TimeoutStopUSec": "1s",
            "Conflicts": "sleep.target",
            "Before": "sleep.target",
            "Conflicts": "sleep.target",
            "Before": "sleep.target",
        }

    def stop(self):
        self.stop_calls += 1
        if self.on_stop is not None:
            self.on_stop()


class WorkerDeadlineSpec(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpnctl-spec-deadline-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.clocks = Clocks()
        real_clock_gettime = time.clock_gettime

        def clock_gettime(clock_id):
            if clock_id == time.CLOCK_BOOTTIME:
                return self.clocks.boottime
            return real_clock_gettime(clock_id)

        self.patches = [
            mock.patch.object(time, "monotonic", lambda: self.clocks.monotonic),
            mock.patch.object(time, "clock_gettime", clock_gettime),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        identities = {}
        for name in ("worker_env", "known_hosts", "deploy_key"):
            path = self.root / name
            path.write_text("fixture-bytes\n" if name == "deploy_key" else "")
            identities[name] = str(path)
        self.db = self.root / "inventory.db"
        self.db.touch()
        self.worker = NoSystemdWorker(
            {
                "node_id": "spec-controller",
                "state_dir": str(self.root),
                "runtime_dir": str(self.runtime),
                "stop_budget_ms": 1000,
                "worker": sys.executable,
                "db": str(self.db),
                "worker_addr": "127.0.0.1:0",
                "identities": identities,
            },
            self.clocks,
        )
        self.path = self.runtime / "authority.json"
        self.socket = str(self.runtime / "fixture.sock")

    def authority(self):
        return json.loads(self.path.read_text())

    def prepare(self, boot=2015.0):
        self.worker.prepare(
            1015.0, self.socket, epoch=7, boottime_deadline=boot
        )

    def assert_no_armed_authority(self):
        if self.path.exists():
            self.assertIs(self.authority()["armed"], False)

    def test_happy_prepare_stages_exact_unarmed_grant(self):
        self.prepare()
        record = self.authority()
        self.assertEqual(record["epoch"], 7)
        self.assertEqual(record["deadline"], 1015.0)
        self.assertEqual(record["boottime_deadline"], 2015.0)
        self.assertIs(record["armed"], False)
        self.assertIsInstance(record["boot_id"], str)
        self.assertTrue(record["boot_id"])

    def test_explicit_grant_is_not_reconstructed_after_suspend_before_extend(self):
        self.prepare()
        self.clocks.advance_boot(4)
        self.worker.extend(
            1015.0, token="spec-token", boottime_deadline=2015.0
        )
        record = self.authority()
        self.assertIs(record["armed"], True)
        self.assertEqual(record["arm_token"], "spec-token")
        self.assertEqual(record["deadline"], 1015.0)
        self.assertEqual(record["boottime_deadline"], 2015.0)

    def test_expired_boot_grant_cannot_arm_with_frozen_monotonic(self):
        self.prepare()
        before = self.path.read_bytes()
        self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.worker.extend(
                1015.0, token="spec-token", boottime_deadline=2015.0
            )
        self.assertEqual(self.path.read_bytes(), before)

    def test_slow_property_inspection_cannot_arm_expired_grant(self):
        self.prepare()
        before = self.path.read_bytes()
        self.worker.on_properties = lambda: self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.worker.extend(
                1015.0, token="spec-token", boottime_deadline=2015.0
            )
        self.assertEqual(self.path.read_bytes(), before)

    def test_slow_property_inspection_preserves_original_live_bound(self):
        self.prepare()
        self.worker.on_properties = lambda: self.clocks.advance_boot(4)
        self.worker.extend(
            1015.0, token="spec-token", boottime_deadline=2015.0
        )
        self.assertEqual(self.authority()["boottime_deadline"], 2015.0)

    def test_prepare_rechecks_expiry_after_blocking_property_inspection(self):
        self.worker.on_properties = lambda: self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.prepare()
        self.assert_no_armed_authority()

    def test_prepare_rechecks_expiry_after_blocking_systemd_call(self):
        self.worker.on_command = lambda: self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.prepare()
        self.assert_no_armed_authority()

    def test_prepare_omitted_bound_is_captured_before_blocking_stop(self):
        self.worker.on_stop = lambda: self.clocks.advance_boot(4)
        self.worker.prepare(1015.0, self.socket, epoch=7)
        self.assertEqual(self.authority()["boottime_deadline"], 2015.0)

    def test_prepare_omitted_bound_does_not_restart_after_expired_stop(self):
        self.worker.on_stop = lambda: self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.worker.prepare(1015.0, self.socket, epoch=7)
        self.assert_no_armed_authority()

    def test_explicit_prepare_rejects_grant_already_expired_by_suspend(self):
        self.clocks.advance_boot(16)
        with self.assertRaises(Exception):
            self.prepare()
        self.assert_no_armed_authority()

    def test_publish_keeps_exact_explicit_bound_under_clock_divergence(self):
        self.prepare()
        self.clocks.advance_boot(4)
        self.worker.publish_deadline(
            1015.0, token="spec-published", boottime_deadline=2015.0
        )
        self.assertEqual(self.authority()["deadline"], 1015.0)
        self.assertEqual(self.authority()["boottime_deadline"], 2015.0)
        self.assertEqual(self.authority()["arm_token"], "spec-published")

    def test_publish_requires_strictly_more_than_safety_margin_in_both_clocks(self):
        self.prepare()
        before = self.path.read_bytes()
        for mono, boot in ((1012.0, 2000.0), (1000.0, 2012.0)):
            with self.subTest(monotonic=mono, boottime=boot):
                self.clocks.monotonic = mono
                self.clocks.boottime = boot
                with self.assertRaises(Exception):
                    self.worker.publish_deadline(
                        1015.0, token="spec-token", boottime_deadline=2015.0
                    )
                self.assertEqual(self.path.read_bytes(), before)

    def test_publish_rejects_bound_above_fifteen_seconds(self):
        self.prepare()
        before = self.path.read_bytes()
        for mono_deadline, boot_deadline in ((1015.001, 2015.0), (1015.0, 2015.001)):
            with self.subTest(monotonic=mono_deadline, boottime=boot_deadline):
                with self.assertRaises(Exception):
                    self.worker.publish_deadline(
                        mono_deadline,
                        token="spec-token",
                        boottime_deadline=boot_deadline,
                    )
                self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
