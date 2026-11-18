"""Independent black-box lifecycle assertions derived only from controller-ha.md."""

import copy
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from lifecycle import Lifecycle  # noqa: E402


class Clock:
    def __init__(self, seconds=1000.0):
        self.seconds = seconds

    def __call__(self):
        return self.seconds

    def advance_ms(self, milliseconds):
        self.seconds += milliseconds / 1000


class Consul:
    """Only the documented authority interface, with one current grant."""

    def __init__(self):
        self.set_grant("a", 1)

    def set_grant(self, node, epoch):
        self.node = node
        self.epoch = epoch
        self.session_id = f"session-{node}-{epoch}"
        self.record = {
            "holder": node,
            "node_id": node,
            "epoch": epoch,
            "session": self.session_id,
            "previous": None,
        }

    def authority(self, node, epoch, session):
        if (node, epoch, session) != (self.node, self.epoch, self.session_id):
            raise RuntimeError("current authority does not match")
        return copy.deepcopy(self.record)


class Executor:
    """An independently blocked SSH job must block barriers, not renewals."""

    def __init__(self):
        self.closed_through = 0
        self.calls = []
        self.blocked = False

    def barrier(self, identity, request):
        self.calls.append((identity, copy.deepcopy(request)))
        if self.blocked:
            raise RuntimeError("uncertain job spec-pending-job")
        self.closed_through = max(self.closed_through, request["epoch"] - 1)
        return {
            "previous": None,
            "successor_epoch": request["epoch"],
            "external_actions_fenced": True,
        }

    def status(self):
        return {
            "closed_through": self.closed_through,
            "blocked_jobs": ["spec-pending-job"] if self.blocked else [],
            "ready": not self.blocked,
        }


def proof(boot="node-a-boot"):
    return {
        "boot_id": boot,
        "unit": "vpnctl-spec-worker.service",
        "stop_budget_ms": 1000,
        "remaining_ms": 15000,
        "armed": True,
        "properties": {
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
        },
    }


class LifecycleSpec(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpnctl-spec-lifecycle-")
        self.addCleanup(self.directory.cleanup)
        self.clock = Clock()
        self.consul = Consul()
        self.executor = Executor()
        self.lifecycle = Lifecycle(
            self.directory.name,
            self.consul,
            self.executor,
            clock=self.clock,
            boot="witness-boot-1",
        )

    def request(self, *, token=None, worker_proof=None):
        result = {
            "epoch": self.consul.epoch,
            "session": self.consul.session_id,
            "proof": worker_proof or proof(f"node-{self.consul.node}-boot"),
        }
        if token is not None:
            result["token"] = token
        return result

    def reserve(self):
        result = self.lifecycle.reserve(self.consul.node, self.request())
        self.assertIsInstance(result["token"], str)
        self.assertTrue(result["token"])
        return result["token"]

    def arm(self):
        token = self.reserve()
        self.lifecycle.confirm(self.consul.node, self.request(token=token))
        return token

    def assert_blocked(self, call):
        with self.assertRaises(Exception):
            call()

    def expire(self):
        remaining = self.lifecycle.status()["remaining_ms"]
        self.assertIsInstance(remaining, int)
        self.assertGreater(remaining, 0)
        self.clock.advance_ms(remaining + 10)

    def test_reserve_confirm_and_durable_same_boot_restart(self):
        token = self.reserve()
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)
        self.assert_blocked(
            lambda: self.lifecycle.confirm("a", self.request(token="wrong-token"))
        )
        self.lifecycle.confirm("a", self.request(token=token))
        self.clock.advance_ms(4000)
        before = self.lifecycle.status()["remaining_ms"]
        self.lifecycle = Lifecycle(
            self.directory.name,
            self.consul,
            self.executor,
            clock=self.clock,
            boot="witness-boot-1",
        )
        self.assertLessEqual(self.lifecycle.status()["remaining_ms"], before)
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)

    def test_unconfirmed_reservation_blocks_without_early_expiry(self):
        self.reserve()
        remaining = self.lifecycle.status()["remaining_ms"]
        self.consul.set_grant("b", 2)
        self.clock.advance_ms(remaining - 1)
        self.assert_blocked(self.reserve)
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)
        self.clock.advance_ms(11)
        self.reserve()
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 2)

    def test_failed_candidates_do_not_replace_last_worker(self):
        self.arm()
        self.consul.set_grant("b", 2)
        self.assert_blocked(self.reserve)
        self.consul.set_grant("c", 3)
        self.assert_blocked(self.reserve)
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)
        self.expire()
        self.reserve()
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 3)

    def test_expired_same_epoch_cannot_be_revived(self):
        token = self.arm()
        self.expire()
        self.assert_blocked(self.reserve)
        self.assert_blocked(
            lambda: self.lifecycle.confirm("a", self.request(token=token))
        )

    def test_old_authority_cannot_confirm_or_extend(self):
        token = self.arm()
        old_request = self.request(token=token)
        before = self.lifecycle.status()["remaining_ms"]
        self.consul.set_grant("b", 2)
        self.assert_blocked(lambda: self.lifecycle.confirm("a", old_request))
        self.assert_blocked(lambda: self.lifecycle.reserve("a", old_request))
        self.assertLessEqual(self.lifecycle.status()["remaining_ms"], before)
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)

    def test_missing_history_above_bootstrap_epoch_fails_closed(self):
        self.consul.set_grant("b", 2)
        self.assert_blocked(self.reserve)

    def test_witness_reboot_waits_full_fifteen_seconds(self):
        self.arm()
        self.clock = Clock(0)
        self.lifecycle = Lifecycle(
            self.directory.name,
            self.consul,
            self.executor,
            clock=self.clock,
            boot="witness-boot-2",
        )
        self.consul.set_grant("b", 2)
        self.assertGreaterEqual(self.lifecycle.status()["remaining_ms"], 14999)
        self.clock.advance_ms(14999)
        self.assert_blocked(self.reserve)
        self.clock.advance_ms(11)
        self.reserve()

    def test_empty_requires_recorded_identity_epoch_and_boot(self):
        self.arm()
        for identity, epoch, boot in (
            ("b", 1, "node-a-boot"),
            ("a", 2, "node-a-boot"),
            ("a", 1, "different-boot"),
        ):
            with self.subTest(identity=identity, epoch=epoch, boot=boot):
                self.assert_blocked(
                    lambda: self.lifecycle.empty(
                        identity,
                        {"epoch": epoch, "boot_id": boot, "cgroup_empty": True},
                    )
                )
                self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)
        self.lifecycle.empty(
            "a", {"epoch": 1, "boot_id": "node-a-boot", "cgroup_empty": True}
        )
        self.consul.set_grant("b", 2)
        self.reserve()

    def test_malformed_proof_never_creates_reservation(self):
        invalid = []
        for key, value in (
            ("boot_id", ""),
            ("unit", ""),
            ("stop_budget_ms", True),
            ("stop_budget_ms", 99),
            ("stop_budget_ms", 5000),
            ("remaining_ms", 0),
            ("remaining_ms", 15001),
            ("remaining_ms", 1.5),
            ("armed", "yes"),
            ("properties", {}),
        ):
            candidate = proof()
            candidate[key] = value
            invalid.append(candidate)
        candidate = proof()
        candidate["properties"]["KillMode"] = "process"
        invalid.append(candidate)
        candidate = proof()
        candidate["properties"]["TimeoutStopUSec"] = "5s"
        invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(proof=candidate):
                self.assert_blocked(
                    lambda: self.lifecycle.reserve(
                        "a", self.request(worker_proof=candidate)
                    )
                )
                self.assertIsNone(self.lifecycle.status()["worker"])

    def test_same_grant_renewal_does_not_wait_for_executor_barrier(self):
        self.arm()
        calls = len(self.executor.calls)
        self.clock.advance_ms(1000)
        self.executor.blocked = True
        self.arm()
        self.assertEqual(len(self.executor.calls), calls)
        self.assertGreater(self.lifecycle.status()["remaining_ms"], 14000)

    def test_successor_barrier_reports_job_and_preserves_worker_on_failure(self):
        self.arm()
        self.expire()
        self.consul.set_grant("b", 2)
        self.executor.blocked = True
        calls = len(self.executor.calls)
        with self.assertRaisesRegex(Exception, "spec-pending-job"):
            self.reserve()
        self.assertGreater(len(self.executor.calls), calls)
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 1)
        self.executor.blocked = False
        self.reserve()
        self.assertEqual(self.lifecycle.status()["worker"]["epoch"], 2)


if __name__ == "__main__":
    unittest.main()
