"""Durable independent evidence bounding every possibly running worker.

The authenticated controller is trusted to enforce the inspected systemd
properties.  Consul grants alone do not prove resource fencing: a durable arm
reservation covers the gap before a controller may extend its local watchdog.
"""
from __future__ import annotations

from pathlib import Path
import re
import threading
import time
import uuid

from common import atomic_json, read_json


ARM_SECONDS = 15


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


class Lifecycle:
    def __init__(self, root, consul, executor, clock=boottime, boot=None):
        self.path = Path(root) / "lifecycle.json"
        self.consul = consul
        self.executor = executor
        self.clock = clock
        self.boot = boot or boot_id()
        self.lock = threading.Lock()
        self.state = read_json(self.path, {"version": 1, "seen_epoch": 0, "closed_through": 0, "worker": None})
        worker = self.state["worker"]
        if worker and worker["witness_boot"] != self.boot and not worker.get("empty"):
            # A restarted witness never interprets an older boot's clock.  All
            # reservations issued before its restart expire within this bound.
            worker.update(witness_boot=self.boot, expires=self.clock() + ARM_SECONDS)
            self.save()

    def save(self):
        atomic_json(self.path, self.state)

    def status(self):
        with self.lock:
            worker = self.state["worker"]
            remaining = max(0, worker["expires"] - self.clock()) if worker and not worker.get("empty") else 0
            return {"worker": worker.copy() if worker else None, "remaining_ms": int(remaining * 1000),
                    "ready": remaining == 0, "closed_through": self.state["closed_through"]}

    @staticmethod
    def validate_proof(proof, armed=False):
        expected = {"ActiveState": "active", "KillMode": "control-group", "SendSIGKILL": "yes",
                    "Restart": "no", "WatchdogUSec": "2s", "NotifyAccess": "main",
                    "WatchdogSignal": "9", "ProtectControlGroups": "yes", "NoNewPrivileges": "yes"}
        if (not isinstance(proof, dict) or not isinstance(proof.get("boot_id"), str)
                or not proof["boot_id"] or not isinstance(proof.get("unit"), str) or not proof["unit"]
                or type(proof.get("armed")) is not bool
                or not isinstance(proof.get("properties"), dict)):
            raise RuntimeError("authenticated local watchdog evidence is missing")
        if any(proof.get("properties", {}).get(key) != value for key, value in expected.items()):
            raise RuntimeError("independent cgroup watchdog properties are not enforced")
        if any(not isinstance(proof["properties"].get(name), str)
               or "sleep.target" not in proof["properties"][name].split()
               for name in ("Conflicts", "Before")):
            raise RuntimeError("independent cgroup sleep fence is not enforced")
        timeout = proof["properties"].get("TimeoutStopUSec", "")
        parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(us|ms|s|min|h)", timeout)
        compact = timeout.replace(" ", "")
        if "".join(number + unit for number, unit in parts) != compact or not parts:
            raise RuntimeError("independent cgroup stop timeout is unbounded")
        units = {"us": .001, "ms": 1, "s": 1000, "min": 60000, "h": 3600000}
        milliseconds = sum(float(number) * units[unit] for number, unit in parts)
        budget = proof.get("stop_budget_ms")
        if type(budget) is not int or not 100 <= budget < 5000 or not 0 < milliseconds <= budget:
            raise RuntimeError("independent cgroup stop timeout exceeds its budget")
        remaining = proof.get("remaining_ms")
        if isinstance(remaining, bool) or not isinstance(remaining, int) or not 0 < remaining <= ARM_SECONDS * 1000:
            raise RuntimeError("local watchdog deadline is not bounded")
        if armed and proof.get("armed") is not True:
            raise RuntimeError("local watchdog was not successfully armed")

    def reserve(self, identity, request):
        # Executor serializes and durably closes all older epochs.  Its pending
        # outcomes must be resolved before even a pending new arm is permitted.
        with self.lock:
            current = self.state["worker"]
            renewal = current and (current["node"], current["epoch"], current["session"]) == (
                identity, request["epoch"], request["session"])
        if not renewal:
            barrier = self.executor.barrier(identity, request)
            if barrier.get("external_actions_fenced") is not True or barrier.get("successor_epoch") != request["epoch"]:
                raise RuntimeError("external executor epoch barrier was not proven")
        self.validate_proof(request.get("proof"))
        with self.lock:
            record = self.consul.authority(identity, request["epoch"], request["session"])
            epoch = record["epoch"]
            if epoch <= self.state["closed_through"] or epoch < self.state["seen_epoch"]:
                raise RuntimeError("worker lifecycle epoch is fenced")
            current = self.state["worker"]
            same = current and (current["node"], current["epoch"], current["session"], current["boot_id"]) == (
                identity, epoch, request["session"], request["proof"]["boot_id"])
            if same and (current.get("empty") or current["expires"] <= self.clock() or not current.get("armed")):
                raise RuntimeError("expired or unconfirmed worker arm cannot be revived")
            if current and not same and not current.get("empty") and self.clock() < current["expires"]:
                raise RuntimeError("previous worker resource arm has not expired: " + current["node"] + " epoch " + str(current["epoch"]))
            if not current and epoch > 1 and self.state["seen_epoch"] == 0:
                raise RuntimeError("previous worker lifecycle evidence is missing")
            if same:
                # The renewal proof attests the old arm; the pending reservation
                # must be durable before the local deadline is allowed to grow.
                self.validate_proof(request["proof"], armed=True)
            self.state["seen_epoch"] = max(epoch, self.state["seen_epoch"])
            self.state["closed_through"] = max(epoch - 1, self.state["closed_through"])
            worker = {"node": identity, "epoch": epoch, "session": request["session"],
                      "boot_id": request["proof"]["boot_id"], "unit": request["proof"]["unit"],
                      "properties": request["proof"]["properties"], "witness_boot": self.boot,
                      "expires": self.clock() + ARM_SECONDS, "token": uuid.uuid4().hex,
                      "armed": False, "empty": False}
            self.state["worker"] = worker
            self.save()
            return {"token": worker["token"], "epoch": epoch, "resource_access_bounded": True}

    def confirm(self, identity, request):
        self.validate_proof(request.get("proof"), armed=True)
        with self.lock:
            self.consul.authority(identity, request["epoch"], request["session"])
            worker = self.state["worker"]
            if not worker or (worker["node"], worker["epoch"], worker["session"], worker["token"], worker["boot_id"]) != (
                    identity, request["epoch"], request["session"], request["token"], request["proof"]["boot_id"]):
                raise RuntimeError("worker watchdog confirmation does not match reservation")
            if worker["expires"] <= self.clock() or worker.get("empty"):
                raise RuntimeError("worker watchdog reservation expired")
            worker["armed"] = True
            self.save()
            return {"epoch": worker["epoch"], "resource_access_bounded": True}

    def empty(self, identity, request):
        with self.lock:
            worker = self.state["worker"]
            if not worker or worker["node"] != identity or worker["epoch"] != request["epoch"] or worker["boot_id"] != request["boot_id"]:
                raise RuntimeError("empty-cgroup evidence does not match recorded worker")
            if request.get("cgroup_empty") is not True:
                raise RuntimeError("worker cgroup is not proven empty")
            worker["empty"] = True
            self.state["closed_through"] = max(worker["epoch"], self.state["closed_through"])
            self.save()
            return {"epoch": worker["epoch"], "resource_access_fenced": True}
