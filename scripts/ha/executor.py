"""Independent, durable single-dispatch SSH executor and snapshot witness."""
from __future__ import annotations

import base64
import fcntl
import os
from pathlib import Path
import subprocess
import threading
import uuid

from common import atomic_json, now_ms, read_json


class Executor:
    def __init__(self, root, consul, helper, deploy_key, build):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.instance_lock = (self.root / "executor.lock").open("a+b")
        fcntl.flock(self.instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.consul = consul
        self.helper = str(helper)
        self.deploy_key = str(deploy_key)
        self.build = build
        self.lock = threading.Lock()
        self.state_file = self.root / "executor.json"
        self.state = read_json(self.state_file, {"closed_through": 0, "jobs": {}})
        # An intent is committed before dispatch. Never dispatch it again.
        for job in self.state["jobs"].values():
            if job["state"] == "running":
                job["state"] = "uncertain"
        self.save()

    def save(self):
        atomic_json(self.state_file, self.state)

    def status(self):
        state = read_json(self.state_file)
        uncertain = [{"id": ident, "epoch": job["epoch"], "state": job["state"]}
                     for ident, job in state["jobs"].items() if job["state"] != "completed"]
        return {"closed_through": state["closed_through"],
                "blocked_jobs": uncertain, "ready": not uncertain}

    def barrier(self, identity, request):
        # Check authority inside the serialization lock, so no dispatch can race
        # between the epoch fence and examination of all prior intents.
        with self.lock:
            record = self.consul.authority(identity, request["epoch"], request["session"])
            previous = record["previous"]
            previous_epoch = previous["epoch"] if previous else 0
            greatest = self.state.get("greatest_grant")
            if greatest and (record["epoch"] < greatest["epoch"] or
                             (record["epoch"] == greatest["epoch"] and record != greatest) or
                             (record["epoch"] > greatest["epoch"] and previous_epoch < greatest["epoch"])):
                raise RuntimeError("quorum epoch history moved backwards; all workers require recovery")
            self.state["closed_through"] = max(self.state["closed_through"], previous_epoch)
            self.save()
            pending = [ident for ident, job in self.state["jobs"].items()
                       if job["state"] != "completed"]
            if pending:
                raise RuntimeError("external execution outcome uncertain; jobs: " + ",".join(pending))
            self.state["greatest_grant"] = record
            self.save()
            return {"previous": previous, "successor_epoch": record["epoch"],
                    "external_actions_fenced": True}

    def execute(self, identity, request):
        with self.lock:
            record = self.consul.authority(identity, request["epoch"], request["session"])
            greatest = self.state.get("greatest_grant")
            if greatest and (record["epoch"] < greatest["epoch"] or
                             (record["epoch"] == greatest["epoch"] and record != greatest)):
                raise RuntimeError("executor rejected regressed quorum authority")
            if request["epoch"] <= self.state["closed_through"]:
                raise RuntimeError("executor epoch is fenced")
            if request["build"] != self.build:
                raise RuntimeError("executor build mismatch")
            if any(job["state"] != "completed" for job in self.state["jobs"].values()):
                raise RuntimeError("executor blocked by uncertain earlier operation")
            job_id = uuid.uuid4().hex
            self.state["jobs"][job_id] = {"epoch": request["epoch"], "state": "running", "created_at_ms": now_ms()}
            self.save()
            # The transport request (including a bootstrap password) is kept only
            # in the pipe. The durable ledger contains attribution, never secrets.
            environment = {k: v for k, v in os.environ.items() if not k.startswith("VPNCTLD_HA_")}
            environment["VPNCTLD_DEPLOY_KEY"] = self.deploy_key
            try:
                transport = request["transport"]
                deadline = 2 * transport["timeout_ms"] / 1000 + 60
                from common import canonical
                process = subprocess.run([self.helper, "--ha-execute"], input=canonical(transport),
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         timeout=deadline, env=environment, check=False)
                import json
                response = json.loads(process.stdout)
                safe = (process.returncode == 0 and response.get("ok") is True
                        and isinstance(response.get("stdout_b64"), str))
                if safe:
                    base64.b64decode(response["stdout_b64"], validate=True)
                    self.state["jobs"][job_id]["state"] = "completed"
                else:
                    self.state["jobs"][job_id]["state"] = "uncertain"
                self.save()
                if not safe:
                    # Avoid broadcasting a remote error that can contain a
                    # command, bootstrap password or returned private material.
                    return {"ok": False, "stdout_b64": "", "error": "remote outcome uncertain; executor job " + job_id}
                return response
            except Exception:
                self.state["jobs"][job_id]["state"] = "uncertain"
                self.save()
                return {"ok": False, "stdout_b64": "", "error": "remote outcome uncertain; executor job " + job_id}
