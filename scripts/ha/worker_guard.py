#!/usr/bin/env python3
"""Worker cgroup main process; systemd owns its independent fixed watchdog."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def notify(value):
    address = os.environ["NOTIFY_SOCKET"]
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
        stream.connect(address)
        stream.sendall(value.encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--stop-budget", required=True, type=float)
    parser.add_argument("--executor-socket", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--deploy-key", required=True)
    parser.add_argument("worker", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    watchdog = int(os.environ["WATCHDOG_USEC"]) / 1_000_000
    def authorized():
        record = json.loads(Path(args.authority).read_bytes())
        remaining = record["boottime_deadline"] - time.clock_gettime(time.CLOCK_BOOTTIME)
        if not (record["boot_id"] == boot and record["epoch"] == args.epoch
                and watchdog + args.stop_budget < remaining <= 15):
            raise RuntimeError("worker watchdog authority expired")
        return record.get("armed") is True and bool(record.get("arm_token"))
    authorized()
    environment = dict(os.environ)
    for key in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"):
        environment.pop(key, None)
    environment["VPNCTLD_HA_EXECUTOR_SOCKET"] = args.executor_socket
    environment["VPNCTLD_HA_KNOWN_HOSTS"] = args.known_hosts
    environment["VPNCTLD_DEPLOY_KEY"] = args.deploy_key
    environment["VPNCTLD_TRUSTED_PROXIES"] = "127.0.0.1,::1"
    # Stage an inspected live watchdog without starting the application.  Only
    # a durable witness reservation permits the manager to publish an arm.
    notify("READY=1\nWATCHDOG=1")
    while not authorized():
        notify("WATCHDOG=1")
        time.sleep(min(.05, watchdog / 4))
    child = subprocess.Popen(args.worker, env=environment)
    while child.poll() is None:
        if not authorized():
            return 1  # Main exits; KillMode=control-group reaps every descendant.
        notify("WATCHDOG=1")
        time.sleep(min(.25, watchdog / 4))
    return child.returncode or 1


if __name__ == "__main__":
    sys.exit(main())
