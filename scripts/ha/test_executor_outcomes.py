"""Structured helper outcomes are terminal only with complete dispatch evidence."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from executor import Executor, MAX_COMPLETED_JOBS


HELPER = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(__file__).parent
json.load(sys.stdin)
with (root / "dispatches").open("a") as out:
    out.write("once\\n")
record = json.loads((root / "response.json").read_text())
print(record["raw"] if "raw" in record else json.dumps(record["response"]), flush=True)
os._exit(record.get("returncode", 0))
'''


class Authority:
    def __init__(self):
        self.epoch = 1

    def authority(self, node, epoch, session):
        if (node, epoch, session) != ("fixture-controller", self.epoch, "fixture-session"):
            raise RuntimeError("fixture authority rejected")
        return {"epoch": epoch, "session": session,
                "previous": None if epoch == 1 else {"epoch": epoch - 1}}


class ExecutorOutcomeContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vpnctl-executor-outcomes-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.executors = []
        self.addCleanup(self.close_executors)
        self.number = 0
        self.fresh()

    def close_executors(self):
        for executor in self.executors:
            executor.instance_lock.close()

    def fresh(self):
        self.number += 1
        self.root = self.base / str(self.number)
        self.root.mkdir()
        self.helper = self.root / "helper"
        self.helper.write_text(HELPER)
        self.helper.chmod(0o700)
        self.authority = Authority()
        self.executor = self.open_executor()

    def open_executor(self):
        executor = Executor(self.root / "state", self.authority, self.helper,
                            self.root / "fixture-key", "fixture-build")
        self.executors.append(executor)
        return executor

    def restart(self):
        self.executor.instance_lock.close()
        self.executor = self.open_executor()

    def configure(self, response=None, **record):
        if response is not None:
            record["response"] = response
        (self.root / "response.json").write_text(json.dumps(record))

    def execute(self):
        return self.executor.execute("fixture-controller", {
            "epoch": self.authority.epoch, "session": "fixture-session", "build": "fixture-build",
            "transport": {"timeout_ms": 10, "operation": "exec", "host": "fixture.invalid",
                          "user": "root", "port": 22, "remote_cmd": "fixture-command"}})

    def dispatches(self):
        path = self.root / "dispatches"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def test_completed_failures_and_rejections_survive_restart_without_blocking_next_jobs(self):
        for response in [
            {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": 1},
            {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": 254},
            {"ok": False, "stdout_b64": "", "outcome": "rejected"},
        ]:
            with self.subTest(response=response):
                self.fresh()
                self.configure({**response, "error": "fixture-private-material"})
                result = self.execute()
                self.assertFalse(result["ok"])
                self.assertEqual(result["outcome"], response["outcome"])
                self.assertNotIn("fixture-private-material", json.dumps(result))
                self.assertEqual(self.dispatches(), 1)
                self.restart()
                self.assertTrue(self.executor.status()["ready"])
                self.assertEqual(self.dispatches(), 1, "restart replayed a terminal failure")
                self.authority.epoch = 2
                barrier = self.executor.barrier("fixture-controller", {"epoch": 2, "session": "fixture-session"})
                self.assertTrue(barrier["external_actions_fenced"])
                self.configure({"ok": True, "stdout_b64": "", "outcome": "completed", "exit_code": 0})
                self.assertTrue(self.execute()["ok"])
                self.assertEqual(self.dispatches(), 2)
                self.assertNotIn("fixture-private-material", (self.root / "state/executor.json").read_text())

    def test_missing_or_malformed_completion_evidence_remains_uncertain_after_restart(self):
        records = [
            {"response": {"ok": False, "stdout_b64": ""}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "uncertain"}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": 255}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": True}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": 1.0}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "completed"}},
            {"response": {"ok": True, "stdout_b64": "", "outcome": "completed", "exit_code": 1}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "completed", "exit_code": 0}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "rejected", "exit_code": 1}},
            {"response": {"ok": False, "stdout_b64": "", "outcome": "unknown"}},
            {"response": {"ok": True, "stdout_b64": "", "outcome": None}},
            {"response": {"ok": True, "stdout_b64": "!!!", "outcome": "completed", "exit_code": 0}},
            {"response": {"ok": True, "stdout_b64": "", "known_hosts_b64": "!!!"}},
            {"response": {"ok": True, "stdout_b64": "", "error": "contradiction"}},
            {"response": {"ok": True, "stdout_b64": "", "unexpected": "field"}},
            {"response": {"ok": True, "stdout_b64": ""}, "returncode": 23},
            {"response": []},
            {"raw": "not-json"},
        ]
        for record in records:
            with self.subTest(record=record):
                self.fresh()
                self.configure(**record)
                self.assertEqual(self.execute()["outcome"], "uncertain")
                status = self.executor.status()
                self.assertFalse(status["ready"])
                self.restart()
                self.assertEqual(self.executor.status(), status)
                with self.assertRaisesRegex(RuntimeError, "uncertain earlier operation"):
                    self.execute()
                self.authority.epoch = 2
                with self.assertRaisesRegex(RuntimeError, "outcome uncertain; jobs:"):
                    self.executor.barrier("fixture-controller", {"epoch": 2, "session": "fixture-session"})
                self.assertEqual(self.dispatches(), 1, "uncertain action was dispatched twice")

    def test_helper_timeout_and_unfinished_intent_are_durable_without_replay(self):
        with mock.patch("executor.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture-helper", 1)):
            self.assertEqual(self.execute()["outcome"], "uncertain")
        self.restart()
        self.assertFalse(self.executor.status()["ready"])
        with self.assertRaisesRegex(RuntimeError, "uncertain earlier operation"):
            self.execute()
        self.assertEqual(self.dispatches(), 0)
        self.fresh()
        self.executor.state["jobs"]["unfinished-fixture"] = {"state": "running", "epoch": 1}
        self.executor.save()
        self.restart()
        self.assertEqual(self.executor.status()["blocked_jobs"],
                         [{"id": "unfinished-fixture", "epoch": 1, "state": "uncertain"}])
        self.assertEqual(self.dispatches(), 0)

    def test_legacy_success_remains_completed(self):
        self.configure({"ok": True, "stdout_b64": "bGVnYWN5"})
        self.assertEqual(self.execute(), {"ok": True, "stdout_b64": "bGVnYWN5"})
        self.restart()
        self.assertTrue(self.executor.status()["ready"])
        self.assertEqual(self.dispatches(), 1)

    def test_completed_ledger_is_bounded_while_count_and_all_unfinished_intents_survive(self):
        process = subprocess.CompletedProcess([], 0, stdout=b'{"ok":true,"stdout_b64":""}')
        total = MAX_COMPLETED_JOBS + 7
        with mock.patch("executor.subprocess.run", return_value=process) as dispatch:
            for _ in range(total):
                self.assertTrue(self.execute()["ok"])
            self.assertEqual(dispatch.call_count, total)
        self.restart()
        state = self.executor.state
        self.assertEqual(state["completed_count"], total)
        self.assertEqual(len(state["jobs"]), MAX_COMPLETED_JOBS)
        self.assertEqual(sorted(job["completion_index"] for job in state["jobs"].values()),
                         list(range(8, total + 1)))
        state["jobs"].update({"uncertain-fixture": {"state": "uncertain", "epoch": 1},
                              "running-fixture": {"state": "running", "epoch": 1}})
        self.executor.save()
        self.restart()
        self.assertEqual(self.executor.state["completed_count"], total)
        self.assertEqual(len(self.executor.state["jobs"]), MAX_COMPLETED_JOBS + 2)
        self.assertEqual({job["id"] for job in self.executor.status()["blocked_jobs"]},
                         {"uncertain-fixture", "running-fixture"})
        self.assertTrue(all(job["state"] == "uncertain" for job in self.executor.status()["blocked_jobs"]))


if __name__ == "__main__":
    unittest.main()
