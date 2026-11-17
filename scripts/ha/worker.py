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
                              "--property=ActiveState,SubState,ControlGroup,MainPID,ActiveEnterTimestampMonotonic,KillMode,SendSIGKILL,Restart,WatchdogUSec,NotifyAccess", check=False)
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

    def start(self, deadline, socket_path, epoch=1):
        self.stop()
        self.epoch = epoch
        self.publish_deadline(deadline)
        remaining = deadline - time.monotonic() - self.stop_budget
        if remaining <= self.stop_budget:
            raise RuntimeError("insufficient authority remaining to start worker")
        args = ["systemd-run", "--quiet", "--collect", "--unit=" + self.unit,
                "--property=Type=notify", "--property=NotifyAccess=main", "--property=WatchdogSec=2",
                "--property=WatchdogSignal=SIGKILL", "--property=TimeoutStartSec=3", "--property=Restart=no", "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes", "--property=NoNewPrivileges=yes",
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
        self.command(*args)
        properties = self.properties()
        if properties.get("KillMode") != "control-group" or properties.get("SendSIGKILL") != "yes" or properties.get("Restart") != "no":
            self.stop()
            raise RuntimeError("worker cgroup lifecycle properties not enforced")
        self.extend(deadline)

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

    def publish_deadline(self, deadline):
        from common import atomic_json
        remaining = deadline - time.monotonic()
        if not self.stop_budget + 2 < remaining <= 15:
            raise RuntimeError("authority cannot cover independent watchdog stop budget")
        atomic_json(self.authority_path, {
            "epoch": self.epoch, "deadline": deadline,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }, mode=0o644)

    def extend(self, deadline):
        properties = self.properties()
        if properties.get("ActiveState") != "active":
            raise RuntimeError("worker is not active")
        if properties.get("WatchdogUSec") != "2s" or properties.get("NotifyAccess") != "main":
            raise RuntimeError("independent systemd worker watchdog is not enforced")
        self.publish_deadline(deadline)
