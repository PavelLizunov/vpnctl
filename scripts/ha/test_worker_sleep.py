"""Worker sleep ordering; the real fixture starts only its own fake target."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock
import uuid

from lifecycle import Lifecycle
from worker import Worker


class SleepFenceTests(unittest.TestCase):
    def test_both_exact_dependency_memberships_are_required(self):
        for key in ("Conflicts", "Before"):
            for value in (None, "", "not-sleep.target", ["sleep.target"]):
                with self.subTest(key=key, value=value):
                    properties = {"Conflicts": "sleep.target", "Before": "sleep.target"}
                    properties[key] = value
                    with self.assertRaisesRegex(RuntimeError, "sleep fence"):
                        Worker.require_sleep_fence(properties)
        Worker.require_sleep_fence({"Conflicts": "shutdown.target sleep.target", "Before": "sleep.target fixture.target"})

    def test_witness_rejects_missing_sleep_ordering_before_any_worker_arm(self):
        from test_lifecycle import LifecycleTests
        fixture = LifecycleTests(methodName="test_missing_lifecycle_and_bad_watchdog_evidence_fail_closed")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for key in ("Conflicts", "Before"):
            request = fixture.request()
            request["proof"]["properties"].pop(key)
            with self.assertRaisesRegex(RuntimeError, "sleep fence"):
                fixture.life.reserve("a", request)
            self.assertIsNone(fixture.life.status()["worker"])

    def test_worker_proof_and_extension_reject_unenforced_sleep_fence(self):
        with tempfile.TemporaryDirectory() as root:
            worker = Worker({"node_id": "fixture-sleep-proof", "state_dir": root, "stop_budget_ms": 1000})
            worker.properties = Mock(return_value={"ActiveState": "active", "WatchdogUSec": "2s", "NotifyAccess": "main"})
            worker.publish_deadline(time.monotonic() + 14, boottime_deadline=time.clock_gettime(time.CLOCK_BOOTTIME) + 14)
            previous = worker.authority_path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "sleep fence"):
                worker.proof()
            with self.assertRaisesRegex(RuntimeError, "sleep fence"):
                worker.extend(time.monotonic() + 14, "reserved", boottime_deadline=time.clock_gettime(time.CLOCK_BOOTTIME) + 14)
            self.assertEqual(worker.authority_path.read_bytes(), previous)


@unittest.skipUnless(os.environ.get("VPNCTL_HA_SYSTEMD_TESTS") == "1" and os.geteuid() == 0,
                     "requires explicit root real-systemd fixture opt-in")
class RealSleepOrderFixture(unittest.TestCase):
    def test_frozen_staged_guard_is_killed_before_fake_sleep_target_active(self):
        suffix = uuid.uuid4().hex[:12]
        node = "fixture-sleep-" + suffix
        target = "vpnctl-ha-fixture-sleep-" + suffix + ".target"
        probe = "vpnctl-ha-fixture-sleep-probe-" + suffix + ".service"
        unit_root = Path("/run/systemd/system")
        temporary = tempfile.TemporaryDirectory(prefix="vpnctl-ha-sleep-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        marker, evidence = root / "application-started", root / "ordering.json"
        environment = root / "environment"; environment.write_text("")
        helper = root / "fixture-worker.py"
        helper.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nimport time\nPath(" + repr(str(marker)) + ").write_text('started')\ntime.sleep(60)\n")
        helper.chmod(0o755)
        config = {"node_id": node, "state_dir": str(root / "state"), "runtime_dir": str(root / "runtime"),
                  "stop_budget_ms": 1000, "worker": str(helper), "db": str(root / "fixture.db"),
                  "worker_addr": "127.0.0.1:1", "identities": {"worker_env": str(environment),
                  "known_hosts": str(root / "fixture-known-hosts"), "deploy_key": str(root / "fixture-key")}}
        fixture_target = target
        class FixtureWorker(Worker):
            def command(self, *args, check=True):
                if args[0] == "systemd-run":
                    args = tuple(value + " " + fixture_target if value.startswith(("--property=Conflicts=", "--property=Before=")) else value for value in args)
                return super().command(*args, check=check)
        worker = FixtureWorker(config)
        self.addCleanup(worker.stop)
        target_path, probe_path = unit_root / target, unit_root / probe
        self.assertFalse(target_path.exists()); self.assertFalse(probe_path.exists())
        def cleanup_units():
            subprocess.run(["systemctl", "stop", target, probe], check=False, capture_output=True, timeout=10)
            target_path.unlink(missing_ok=True); probe_path.unlink(missing_ok=True)
            subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, timeout=10)
        self.addCleanup(cleanup_units)
        script = root / "probe.py"
        script.write_text("import sys,json,time,subprocess\nfrom pathlib import Path\nsys.path.insert(0," + repr(str(Path(__file__).resolve().parent)) + ")\nfrom worker import Worker\nconfig=" + repr(config) + "\nempty=Worker(config).stopped()\nstate=subprocess.run(['systemctl','is-active'," + repr(target) + "],capture_output=True,text=True).stdout.strip()\nPath(" + repr(str(evidence)) + ").write_text(json.dumps({'cgroup_empty_before_target':empty,'target_state_when_empty':state,'observed_monotonic_ns':time.monotonic_ns(),'observed_boottime_ns':time.clock_gettime_ns(time.CLOCK_BOOTTIME)}))\nraise SystemExit(0 if empty and state in ('inactive','activating') else 1)\n")
        target_path.write_text("[Unit]\nDescription=vpnctl isolated fake sleep target\nDefaultDependencies=no\nRequires=" + probe + "\nAfter=" + probe + "\n")
        probe_path.write_text("[Unit]\nDescription=vpnctl isolated pre-target empty-cgroup proof\nDefaultDependencies=no\nAfter=" + worker.unit + "\nBefore=" + target + "\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 " + str(script) + "\nTimeoutStartSec=5\nRestart=no\n")
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, timeout=10)
        deadline, boot_deadline = time.monotonic() + 14, time.clock_gettime(time.CLOCK_BOOTTIME) + 14
        worker.prepare(deadline, root / "executor.sock", boottime_deadline=boot_deadline)
        proof = worker.proof()
        self.assertIn("sleep.target", proof["properties"]["Conflicts"].split())
        self.assertIn("sleep.target", proof["properties"]["Before"].split())
        self.assertIn(target, proof["properties"]["Conflicts"].split())
        self.assertIn(target, proof["properties"]["Before"].split())
        guard_pid = int(proof["properties"]["MainPID"])
        os.kill(guard_pid, signal.SIGSTOP)
        worker.extend(deadline, "fixture-reserved-arm", boottime_deadline=boot_deadline)
        self.assertFalse(marker.exists())
        subprocess.run(["systemctl", "start", target], check=True, capture_output=True, timeout=8)
        self.assertEqual(subprocess.check_output(["systemctl", "is-active", target], text=True).strip(), "active")
        self.assertTrue(json.loads(evidence.read_text())["cgroup_empty_before_target"])
        self.assertIn(json.loads(evidence.read_text())["target_state_when_empty"], ("inactive", "activating"))
        self.assertTrue(worker.stopped())
        self.assertFalse(Path("/proc/" + str(guard_pid)).exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(guard_pid, signal.SIGCONT)
        self.assertFalse(marker.exists())
        entered = int(subprocess.check_output(["systemctl", "show", target, "--property=ActiveEnterTimestampMonotonic", "--value"], text=True).strip())
        observed = json.loads(evidence.read_text())["observed_boottime_ns"]
        observed_mono = json.loads(evidence.read_text())["observed_monotonic_ns"]
        self.assertLessEqual(observed_mono // 1000, entered)
        print("real fake-sleep ordering evidence: " + json.dumps({"fixture_target": target,
              "guard_pid_reaped": guard_pid, "cgroup_empty_before_target": True,
              "application_start_count": 0, "target_active_monotonic_usec": entered,
              "empty_cgroup_proof_boottime_ns": observed, "empty_cgroup_proof_monotonic_ns": observed_mono,
              "target_state_when_empty": json.loads(evidence.read_text())["target_state_when_empty"], "restart": "no"}), flush=True)


if __name__ == "__main__":
    unittest.main()
