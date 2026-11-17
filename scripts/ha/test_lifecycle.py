"""Deterministic boundary tests for durable independent worker evidence."""
from pathlib import Path
import tempfile
import unittest

from lifecycle import Lifecycle


class Authority:
    def __init__(self):
        self.record = {"holder": "a", "epoch": 1, "session": "s1", "previous": None}

    def authority(self, node, epoch, session):
        if (node, epoch, session) != (self.record["holder"], self.record["epoch"], self.record["session"]):
            raise RuntimeError("quorum rejected authority")
        return self.record

    def next(self, node="b"):
        old = self.record
        self.record = {"holder": node, "epoch": old["epoch"] + 1, "session": "s" + str(old["epoch"] + 1),
                       "previous": {"holder": old["holder"], "epoch": old["epoch"]}}


class Executor:
    def __init__(self):
        self.calls = 0
        self.pending = False

    def barrier(self, node, request):
        self.calls += 1
        if self.pending:
            raise RuntimeError("external execution outcome uncertain; jobs: fixture-job")
        return {"successor_epoch": request["epoch"], "external_actions_fenced": True}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 100.
        self.consul, self.executor = Authority(), Executor()
        self.life = Lifecycle(self.temp.name, self.consul, self.executor, clock=lambda: self.now, boot="witness-boot")

    def request(self, armed=False):
        return {**self.consul.record, "proof": {"boot_id": "controller-boot", "unit": "fixture.service",
                "armed": armed, "remaining_ms": 10000, "stop_budget_ms": 1000, "properties": {
                    "ActiveState": "active", "KillMode": "control-group", "SendSIGKILL": "yes", "Restart": "no",
                    "WatchdogUSec": "2s", "NotifyAccess": "main", "WatchdogSignal": "9",
                    "ProtectControlGroups": "yes", "NoNewPrivileges": "yes", "TimeoutStopUSec": "1s",
                    "Conflicts": "sleep.target", "Before": "sleep.target"}}}

    def arm(self):
        request = self.request()
        reservation = self.life.reserve(self.consul.record["holder"], request)
        self.life.confirm(self.consul.record["holder"], {**self.request(True), "token": reservation["token"]})
        return reservation

    def test_failed_candidates_preserve_last_worker_until_independent_expiry(self):
        self.arm()
        old = self.life.status()["worker"].copy()
        for _ in range(2):
            self.consul.next()
            with self.assertRaisesRegex(RuntimeError, "resource arm has not expired"):
                self.life.reserve("b", self.request())
            self.assertEqual(self.life.status()["worker"], old)
        self.now += 15
        self.arm()
        self.assertEqual(self.life.status()["worker"]["epoch"], 3)

    def test_pending_arm_blocks_successor_and_is_durable_across_restart(self):
        self.life.reserve("a", self.request())
        self.life = Lifecycle(self.temp.name, self.consul, self.executor, clock=lambda: self.now, boot="witness-boot")
        self.consul.next()
        with self.assertRaisesRegex(RuntimeError, "resource arm has not expired"):
            self.life.reserve("b", self.request())
        self.now += 15
        self.arm()

    def test_same_grant_renewal_does_not_wait_for_executor_jobs(self):
        self.arm()
        self.executor.pending = True
        count = self.executor.calls
        reservation = self.life.reserve("a", self.request(True))
        self.life.confirm("a", {**self.request(True), "token": reservation["token"]})
        self.assertEqual(self.executor.calls, count)
        self.consul.next()
        self.now += 15
        with self.assertRaisesRegex(RuntimeError, "fixture-job"):
            self.life.reserve("b", self.request())
        self.assertEqual(self.life.status()["worker"]["node"], "a")

    def test_old_authority_cannot_extend_or_confirm_after_successor(self):
        reservation = self.arm()
        old = self.request(True)
        self.consul.next()
        with self.assertRaisesRegex(RuntimeError, "quorum"):
            self.life.confirm("a", {**old, "token": reservation["token"]})
        with self.assertRaisesRegex(RuntimeError, "quorum"):
            self.life.reserve("a", old)

    def test_authenticated_empty_cgroup_shortens_wait_but_old_epoch_stays_closed(self):
        self.arm()
        with self.assertRaises(RuntimeError):
            self.life.empty("b", {"epoch": 1, "boot_id": "controller-boot", "cgroup_empty": True})
        self.life.empty("a", {"epoch": 1, "boot_id": "controller-boot", "cgroup_empty": True})
        with self.assertRaisesRegex(RuntimeError, "fenced"):
            self.life.reserve("a", self.request(True))
        self.consul.next()
        self.arm()

    def test_new_witness_boot_waits_a_full_bound(self):
        self.arm()
        self.now += 100
        self.life = Lifecycle(self.temp.name, self.consul, self.executor, clock=lambda: self.now, boot="new-witness-boot")
        self.assertEqual(self.life.status()["remaining_ms"], 15000)
        self.consul.next()
        with self.assertRaisesRegex(RuntimeError, "resource arm has not expired"):
            self.life.reserve("b", self.request())
        self.now += 15
        self.arm()

    def test_missing_lifecycle_and_bad_watchdog_evidence_fail_closed(self):
        bad = self.request()
        bad["proof"]["properties"]["WatchdogUSec"] = "0"
        with self.assertRaisesRegex(RuntimeError, "not enforced"):
            self.life.reserve("a", bad)
        self.assertIsNone(self.life.status()["worker"])
        self.consul.next()
        with self.assertRaisesRegex(RuntimeError, "lifecycle evidence is missing"):
            self.life.reserve("b", self.request())


if __name__ == "__main__":
    unittest.main()
