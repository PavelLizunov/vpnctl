"""Suspend regressions: frozen monotonic time must never extend a worker arm."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from controller_ha import Supervisor
from worker import Worker


class Clock:
    def __init__(self):
        self.mono = 100.
        self.boot = 100.

    def suspended(self, seconds=16):
        self.boot += seconds


class SuspendDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch("worker.time.monotonic", lambda: self.clock.mono))
        self.patches.enter_context(patch("worker.time.clock_gettime", lambda _: self.clock.boot))
        self.patches.enter_context(patch("controller_ha.boottime", lambda: self.clock.boot))
        self.config = {"node_id": "fixture-a", "state_dir": self.temp.name, "stop_budget_ms": 1000,
                       "identities": {name: "/fixture/" + name for name in ("worker_env", "known_hosts", "deploy_key")},
                       "worker": "/fixture/worker", "db": "/fixture/inventory.db", "worker_addr": "127.0.0.1:1"}
        self.record = {"holder": "fixture-a", "session": "fixture-session", "epoch": 1, "previous": None}

    def worker(self):
        worker = Worker(self.config)
        worker.epoch = 1
        worker.properties = Mock(return_value={"ActiveState": "active", "WatchdogUSec": "2s", "NotifyAccess": "main",
                                               "Conflicts": "sleep.target", "Before": "sleep.target"})
        return worker

    def supervisor(self):
        app = Supervisor.__new__(Supervisor)
        app.config = self.config
        app.node = self.config["node_id"]
        app.lock, app.worker_lock, app.bulk_lock = threading.RLock(), threading.Lock(), threading.Lock()
        app.active, app.active_epoch, app.activation_epoch = True, 1, 0
        app.deadline, app.boottime_deadline, app.fenced_through = 115., 115., 0
        app.lease, app.session = self.record.copy(), self.record["session"]
        app.worker = Mock()
        app.consul = Mock()
        app.consul.renew.side_effect = lambda _: self.clock.mono + 15
        app.consul.get.return_value = {"record": self.record.copy(), "Session": app.session}
        app.consul.settings.return_value = {"paused": False, "target": None}
        app.last_snapshot, app.replication_error = 0., ""
        app.snapshot = Mock()
        return app

    def test_explicit_absolute_bound_is_written_without_reconstruction(self):
        worker = self.worker()
        self.clock.boot = 108
        worker.extend(115, "reserved", boottime_deadline=115)
        record = json.loads(worker.authority_path.read_text())
        self.assertEqual(record["boottime_deadline"], 115)
        self.assertEqual(record["deadline"], 115)
        self.assertTrue(record["armed"])

    def test_suspend_during_systemd_properties_cannot_write_a_late_arm(self):
        worker = self.worker()
        worker.publish_deadline(115, "old-reservation", boottime_deadline=115)
        old = worker.authority_path.read_bytes()
        properties = worker.properties.return_value
        def delayed_properties():
            self.clock.suspended()
            return properties
        worker.properties.side_effect = delayed_properties
        with self.assertRaisesRegex(RuntimeError, "watchdog stop budget"):
            worker.extend(115, "new-reservation", boottime_deadline=115)
        self.assertEqual(worker.authority_path.read_bytes(), old)

    def test_suspend_during_stop_prevents_prepare_write_and_systemd_start(self):
        worker = self.worker()
        worker.stop = Mock(side_effect=self.clock.suspended)
        worker.command = Mock()
        with self.assertRaisesRegex(RuntimeError, "watchdog stop budget"):
            worker.prepare(115, "/fixture/executor.sock", boottime_deadline=115)
        self.assertFalse(worker.authority_path.exists())
        worker.command.assert_not_called()

    def test_direct_fixture_start_carries_its_entry_bound_through_prepare(self):
        worker = self.worker()
        worker.prepare = Mock(side_effect=lambda *args, **kwargs: self.clock.suspended())
        with self.assertRaisesRegex(RuntimeError, "watchdog stop budget"):
            worker.start(115, "/fixture/executor.sock")
        self.assertEqual(worker.prepare.call_args.kwargs["boottime_deadline"], 115)
        worker.properties.assert_not_called()
        self.assertFalse(worker.authority_path.exists())

    def test_expired_boot_bound_denies_admission_with_monotonic_still_live(self):
        app = self.supervisor()
        app.admit()
        self.clock.suspended()
        with self.assertRaisesRegex(RuntimeError, "no admitted worker"):
            app.admit()
        self.assertEqual(self.clock.mono, 100)

    def test_current_grant_rechecks_boot_bound_after_authority_rpc(self):
        app = self.supervisor()
        app.consul.authority.side_effect = lambda *args: self.clock.suspended()
        with self.assertRaisesRegex(RuntimeError, "insufficient watchdog authority"):
            app.current_grant(self.record)

    def test_suspend_during_witness_reservation_never_extends_or_confirms(self):
        app = self.supervisor()
        def reserve(*args, **kwargs):
            self.clock.suspended()
            return {"token": "fixture-reservation"}
        app.witness_call = Mock(side_effect=reserve)
        with self.assertRaisesRegex(RuntimeError, "insufficient watchdog authority"):
            app.arm_worker(self.record, 115, 115)
        app.worker.extend.assert_not_called()
        self.assertEqual(app.witness_call.call_count, 1)

    def test_renewal_captures_boot_bound_before_the_request_starts(self):
        app = self.supervisor()
        def renew(_):
            self.clock.suspended(6)
            return 115
        app.consul.renew.side_effect = renew
        app.arm_worker = Mock()
        app.bulk = Mock()
        app.step()
        self.assertEqual(app.boottime_deadline, 115)
        self.assertEqual(app.arm_worker.call_args.args, (self.record, 115, 115))

    def test_suspend_inside_renewal_does_not_restore_admission_or_arm(self):
        app = self.supervisor()
        app.consul.renew.side_effect = lambda _: (self.clock.suspended() or 115)
        app.arm_worker = Mock()
        with self.assertRaisesRegex(RuntimeError, "previous local authority deadline"):
            app.step()
        app.arm_worker.assert_not_called()
        with self.assertRaises(RuntimeError):
            app.admit()
        self.assertEqual(app.boottime_deadline, 115)

    def test_late_fresh_renewal_cannot_revive_an_expired_local_bound(self):
        app = self.supervisor()
        app.arm_worker = Mock()
        self.clock.suspended()
        with self.assertRaisesRegex(RuntimeError, "previous local authority deadline"):
            app.step()
        app.consul.renew.assert_not_called()
        app.arm_worker.assert_not_called()
        self.assertEqual(app.boottime_deadline, 115)
        with self.assertRaises(RuntimeError):
            app.admit()

    def test_reaper_fences_by_boot_deadline_while_monotonic_is_frozen(self):
        app = self.supervisor()
        self.clock.suspended()
        app.exit = Mock()
        app.exit.wait.side_effect = [False, True]
        app.stop = Mock()
        app.reap()
        app.stop.assert_called_once_with("authority deadline reached")

    def test_renewal_remains_independent_of_a_bulk_copy_longer_than_ttl(self):
        app = self.supervisor()
        app.arm_worker = Mock()
        started, release = threading.Event(), threading.Event()
        def copy():
            started.set()
            release.wait(5)
        self.assertTrue(app.bulk("copy", copy))
        self.assertTrue(started.wait(1))
        try:
            for _ in range(20):
                self.clock.mono += 1
                self.clock.boot += 1
                app.step()
                app.admit()
            self.assertEqual(app.consul.renew.call_count, 20)
            self.assertTrue(app.bulk_lock.locked())
            self.assertFalse(release.is_set())
        finally:
            release.set()
            with app.bulk_lock:
                pass


if __name__ == "__main__":
    unittest.main()
