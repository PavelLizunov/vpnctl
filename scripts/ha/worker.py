"""Systemd cgroup lifecycle; never signal only the parent daemon process."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import time


class Worker:
    def __init__(self, config):
        self.config = config
        node = config["node_id"]
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", node):
            raise ValueError("invalid node ID")
        self.unit = "vpnctl-ha-worker-" + node + ".service"
        self.authority_path = Path(config.get("runtime_dir", Path(config["state_dir"]) / "runtime")) / "authority.json"
        self.epoch = 0
        self.stop_budget = config.get("stop_budget_ms", 2000) / 1000

    def command(self, *args, check=True):
        if self.config.get("systemd_user"):
            args = (args[0], "--user", *args[1:])
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=check, timeout=self.stop_budget + 3).stdout.decode().strip()

    def properties(self):
        result = self.command("systemctl", "show", self.unit, "--no-pager",
                              "--property=ActiveState,SubState,ControlGroup,MainPID,ActiveEnterTimestampMonotonic,KillMode,SendSIGKILL,Restart,WatchdogUSec,NotifyAccess,WatchdogSignal,ProtectControlGroups,NoNewPrivileges,TimeoutStopUSec,Conflicts,Before", check=False)
        return dict(line.split("=", 1) for line in result.splitlines() if "=" in line)

    def stopped(self):
        prop = self.properties()
        # A missing unit is not evidence until systemd itself has answered.
        self.command("systemctl", "show", "--property=Version", "--value")
        if prop.get("ActiveState") not in ("inactive", "failed") or prop.get("MainPID") != "0":
            return False
        group = prop.get("ControlGroup")
        if group:
            if not group.startswith("/") or ".." in group.split("/"):
                raise RuntimeError("invalid systemd control group")
            events = Path("/sys/fs/cgroup" + group) / "cgroup.events"
            try:
                if "populated 0" not in events.read_text().splitlines():
                    return False
            except FileNotFoundError:
                # systemd removed this empty cgroup. The unit is already inactive.
                pass
        return True

    def stop(self):
        # SIGKILL reaches SIGSTOPped descendants and SSH's distinct process groups.
        self.command("systemctl", "kill", "--kill-whom=all", "--signal=SIGKILL", self.unit, check=False)
        self.command("systemctl", "stop", self.unit, check=False)
        if not self.stopped():
            raise RuntimeError("worker cgroup did not become empty")

    def deadline_bound(self, deadline, boottime_deadline=None):
        if boottime_deadline is None:
            # Direct fixture compatibility only. Sample boot time first, so a
            # suspend between samples can only shorten this captured bound.
            boottime_deadline = time.clock_gettime(time.CLOCK_BOOTTIME) + (deadline - time.monotonic())
        remaining = deadline - time.monotonic()
        boot_remaining = boottime_deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
        if not (self.stop_budget + 2 < remaining <= 15
                and self.stop_budget + 2 < boot_remaining <= 15):
            raise RuntimeError("authority cannot cover independent watchdog stop budget")
        return boottime_deadline

    def prepare(self, deadline, socket_path, epoch=1, boottime_deadline=None):
        boottime_deadline = self.deadline_bound(deadline, boottime_deadline)
        self.stop()
        self.epoch = epoch
        self.publish_deadline(deadline, boottime_deadline=boottime_deadline)
        remaining = deadline - time.monotonic() - self.stop_budget
        if remaining <= self.stop_budget:
            raise RuntimeError("insufficient authority remaining to start worker")
        args = ["systemd-run", "--quiet", "--collect", "--unit=" + self.unit,
                "--property=Type=notify", "--property=NotifyAccess=main", "--property=WatchdogSec=2",
                "--property=WatchdogSignal=SIGKILL", "--property=TimeoutStartSec=3", "--property=Restart=no", "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes", "--property=NoNewPrivileges=yes",
                "--property=Conflicts=sleep.target", "--property=Before=sleep.target",
                "--property=ProtectControlGroups=yes", "--property=TimeoutStopSec=" + str(self.stop_budget),
                "--property=EnvironmentFile=" + self.config["identities"]["worker_env"]]
        if self.config.get("worker_user"):
            args.append("--property=User=" + self.config["worker_user"])
        args += ["/usr/bin/python3", str(Path(__file__).resolve().with_name("worker_guard.py")),
                 "--authority", str(self.authority_path), "--epoch", str(epoch),
                 "--stop-budget", str(self.stop_budget),
                 "--executor-socket", str(socket_path),
                 "--known-hosts", self.config["identities"]["known_hosts"],
                 "--deploy-key", self.config["identities"]["deploy_key"],
                 self.config["worker"], "--db", self.config["db"], "--addr", self.config["worker_addr"]]
        self.deadline_bound(deadline, boottime_deadline)
        self.command(*args)
        properties = self.properties()
        if properties.get("KillMode") != "control-group" or properties.get("SendSIGKILL") != "yes" or properties.get("Restart") != "no":
            self.stop()
            raise RuntimeError("worker cgroup lifecycle properties not enforced")
        self.require_sleep_fence(properties)
        self.deadline_bound(deadline, boottime_deadline)
        return self.proof()

    def start(self, deadline, socket_path, epoch=1, boottime_deadline=None):
        # Compatibility for the standalone lifecycle fixture.  The supervisor
        # always reserves a witness arm between prepare() and extend().
        boottime_deadline = self.deadline_bound(deadline, boottime_deadline)
        self.prepare(deadline, socket_path, epoch, boottime_deadline=boottime_deadline)
        self.extend(deadline, "direct-lifecycle-fixture", boottime_deadline=boottime_deadline)

    @staticmethod
    def require_sleep_fence(properties):
        if any(not isinstance(properties.get(name), str) or "sleep.target" not in properties[name].split()
               for name in ("Conflicts", "Before")):
            raise RuntimeError("independent cgroup sleep fence is not enforced")

    def proof(self):
        from common import read_json
        record = read_json(self.authority_path, {})
        remaining = record.get("boottime_deadline", 0) - time.clock_gettime(time.CLOCK_BOOTTIME)
        properties = self.properties()
        self.require_sleep_fence(properties)
        return {"unit": self.unit, "boot_id": record.get("boot_id"),
                "properties": properties, "remaining_ms": max(0, int(remaining * 1000)),
                "armed": record.get("armed") is True, "stop_budget_ms": int(self.stop_budget * 1000)}

    def health(self):
        import http.client
        host, port = self.config["worker_addr"].rsplit(":", 1)
        connection = http.client.HTTPConnection(host.strip("[]"), int(port), timeout=1)
        try:
            connection.request("GET", "/api/v1/health")
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("worker health is not HTTP 200")
            response.read(65536)
        finally:
            connection.close()

    def publish_deadline(self, deadline, token=None, boottime_deadline=None):
        from common import atomic_json
        boottime_deadline = self.deadline_bound(deadline, boottime_deadline)
        atomic_json(self.authority_path, {
            "epoch": self.epoch, "deadline": deadline,
            "boottime_deadline": boottime_deadline,
            "armed": token is not None, "arm_token": token,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }, mode=0o644)

    def extend(self, deadline, token="direct-lifecycle-fixture", boottime_deadline=None):
        boottime_deadline = self.deadline_bound(deadline, boottime_deadline)
        properties = self.properties()
        if properties.get("ActiveState") != "active":
            raise RuntimeError("worker is not active")
        if properties.get("WatchdogUSec") != "2s" or properties.get("NotifyAccess") != "main":
            raise RuntimeError("independent systemd worker watchdog is not enforced")
        self.require_sleep_fence(properties)
        self.publish_deadline(deadline, token, boottime_deadline=boottime_deadline)
