#!/usr/bin/env python3
"""Opt-in cooperating-controller service. Standalone vpnctld is unchanged."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import fcntl
import json
import os
from pathlib import Path
import signal
import socketserver
import ssl
import subprocess
import threading
import time

from common import Consul, MAX_FRAME, atomic_json, canonical, now_ms, read_json, request, tls_context
from executor import Executor
from gateway import Server
from replica import SnapshotStore, SnapshotError
from worker import Worker


def address(value):
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


class Supervisor:
    def __init__(self, config):
        self.config = config
        self.node = config["node_id"]
        self.witness = config.get("role") == "witness"
        self.root = Path(config["state_dir"])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.instance_lock = (self.root / "supervisor.lock").open("a+b")
        fcntl.flock(self.instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.context = tls_context(config["tls"])
        consul_tls = tls_context(config["consul"]["tls"]) if config["consul"].get("tls") else None
        self.consul = Consul(config["consul"], consul_tls)
        self.store = SnapshotStore(self.root / "generations", config["build"], config["schema"])
        self.lock = threading.RLock()
        self.worker_lock = threading.Lock()
        self.witness_lock = threading.Lock()
        self.active = False
        self.active_epoch = 0
        self.deadline = 0.0
        self.lease = None
        self.session = None
        self.blocked = "startup readiness has not completed"
        self.quorum = False
        self.replica = None
        self.replica_observed = 0.0
        self.executor_state = None
        self.exit = threading.Event()
        self.last_snapshot = 0.0
        self.fences_file = self.root / "fences.json"
        self.fenced_through = read_json(self.fences_file, {"epoch": 0})["epoch"]
        self.metadata_file = self.root / "snapshots.json"
        self.metadata = read_json(self.metadata_file, {"counter": 0, "latest": None, "allocations": {}})
        self.runtime = Path(config.get("runtime_dir", self.root / "runtime"))
        self.runtime.mkdir(mode=0o711, parents=True, exist_ok=True)
        if self.runtime.is_symlink() or self.runtime.stat().st_uid != os.geteuid():
            raise RuntimeError("runtime directory must belong to the supervisor account")
        self.runtime.chmod(0o711)  # mkdir mode alone is reduced by service UMask.
        self.socket_path = self.runtime / "executor.sock"
        self.worker = None if self.witness else Worker(config)
        self.executor = Executor(self.root / "executor", self.consul, config["worker"],
                                 config["deploy_key"], config["build"]) if self.witness else None
        self.verify_artifact()
        if self.worker:
            self.worker.stop()  # Orphaned old workers are never adopted.

    def verify_artifact(self):
        binary = Path(self.config["worker"])
        actual = hashlib.sha256(binary.read_bytes()).hexdigest()
        if actual != self.config["build"]:
            raise RuntimeError("worker executable hash differs from configured build")
        result = subprocess.run([str(binary), "--ha-artifact"], check=True, capture_output=True, timeout=10)
        self.artifact = json.loads(result.stdout)
        if self.artifact["executable_sha256"] != actual:
            raise RuntimeError("worker executable changed during readiness verification")
        if self.artifact["schema"] != self.config["schema"]:
            raise RuntimeError("configured schema differs from worker embedded migrations")

    def remote(self, node, path, value=None, method="POST", timeout=3):
        try:
            return request(self.config["peers"][node], method, path, value, self.context, timeout=timeout)
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise RuntimeError("HA control peer " + node + " unavailable or invalid (" + type(error).__name__ + ")") from error

    def witness_call(self, path, value=None, method="POST"):
        return self.remote(self.config["witness"], path, value, method)

    def credentials(self):
        with self.lock:
            if not self.lease or not self.session:
                raise RuntimeError("no local grant")
            return {"epoch": self.lease["epoch"], "session": self.session, "build": self.config["build"]}

    def admit(self):
        with self.lock:
            if not self.active or time.monotonic() >= self.deadline - self.config.get("stop_budget_ms", 2000) / 1000:
                raise RuntimeError("controller has no admitted worker")

    def local_upstream(self):
        self.admit()
        return "http://" + self.config["worker_addr"]

    def upstream(self):
        item = self.consul.get("lease")  # Consistent quorum read, never cached discovery.
        if not item or not item.get("Session"):
            raise RuntimeError("no quorum-backed leader is available")
        node = item["record"]["holder"]
        if node == self.node:
            return self.local_upstream(), None
        if node not in self.config["peers"] or node == self.config["witness"]:
            raise RuntimeError("leader is not a configured controller")
        return self.config["peers"][node], self.context

    def record_fence(self, epoch):
        self.fenced_through = max(self.fenced_through, epoch)
        atomic_json(self.fences_file, {"epoch": self.fenced_through})

    def stop(self, reason):
        with self.lock:
            self.active = False  # Close admission before any blocking systemd call.
            self.blocked = reason
            if self.active_epoch:
                self.record_fence(self.active_epoch)
                self.active_epoch = 0
        if self.worker:
            with self.worker_lock:
                self.worker.stop()

    def control(self, identity, method, path, value):
        if identity == self.config.get("witness"):
            raise PermissionError("witness does not operate controllers")
        if method == "GET" and path == "/_ha/status":
            return self.status()
        if self.witness:
            if method == "GET" and path == "/_ha/snapshot-status":
                with self.witness_lock:
                    return {"manifest": self.metadata["latest"], "witness_now_ms": now_ms()}
            if method == "GET" and path == "/_ha/executor-status":
                return self.executor.status()
            if method == "GET" and path.startswith("/_ha/snapshot/"):
                generation = int(path.removeprefix("/_ha/snapshot/"))
                with self.witness_lock:
                    if not self.metadata["latest"] or generation != self.metadata["latest"]["generation"]:
                        raise RuntimeError("requested generation is not latest")
                    return {"snapshot": self.store.export(generation), "witness_now_ms": now_ms()}
            if method == "POST" and path == "/_ha/execute":
                return self.executor.execute(identity, value)
            if method == "POST" and path == "/_ha/barrier":
                return self.executor.barrier(identity, value)
            if method == "POST" and path in ("/_ha/allocate", "/_ha/publish"):
                with self.witness_lock:
                    seed = value.get("seed") is True
                    if seed:
                        if identity != self.config["seed_node"] or self.consul.get("lease") is not None or self.metadata["latest"]:
                            raise RuntimeError("cluster seed is already fixed or seed identity rejected")
                    else:
                        self.consul.authority(identity, value["epoch"], value["session"])
                    if path == "/_ha/allocate":
                        self.metadata["counter"] += 1
                        generation = self.metadata["counter"]
                        stamp = now_ms()
                        self.metadata["allocations"][str(generation)] = {"node": identity, "created_at_ms": stamp,
                                                                       "epoch": value.get("epoch", 0)}
                        atomic_json(self.metadata_file, self.metadata)
                        return {"generation": generation, "created_at_ms": stamp}
                    manifest = value["snapshot"]["manifest"]
                    allocation = self.metadata["allocations"].get(str(manifest["generation"]))
                    if allocation != {"node": identity, "created_at_ms": manifest["created_at_ms"], "epoch": value.get("epoch", 0)}:
                        raise RuntimeError("generation allocation does not match publication")
                    latest = self.metadata["latest"]
                    if latest and manifest["generation"] <= latest["generation"]:
                        raise RuntimeError("generation cannot move backwards")
                    verified = self.store.import_snapshot(value["snapshot"], now_ms(), self.config["max_replica_age_ms"])
                    if verified["files"].get("deploy_key", {}).get("sha256") != hashlib.sha256(Path(self.config["deploy_key"]).read_bytes()).hexdigest():
                        raise RuntimeError("snapshot deploy identity differs from executor key")
                    if verified["migration_sha256"] != self.artifact["migrations_sha256"]:
                        raise RuntimeError("snapshot migration checksums differ from witness build")
                    if not seed:
                        self.consul.authority(identity, value["epoch"], value["session"])
                    elif self.consul.get("lease") is not None:
                        raise RuntimeError("cluster was initialized concurrently")
                    self.metadata["latest"] = verified
                    atomic_json(self.metadata_file, self.metadata)
                    return {"manifest": verified, "witness_now_ms": now_ms()}
        elif method == "POST" and path == "/_ha/fence":
            record = self.consul.authority(identity, value["epoch"], value["session"])
            previous = record["previous"]
            if not previous or previous["holder"] != self.node:
                raise RuntimeError("fence request does not name this previous controller")
            self.stop("fenced by successor epoch " + str(record["epoch"]))
            self.record_fence(previous["epoch"])
            return {"node": self.node, "fenced_through": self.fenced_through, "cgroup_empty": self.worker.stopped(),
                    "successor_epoch": record["epoch"]}
        raise RuntimeError("unsupported HA control operation")

    def snapshot(self, seed=False):
        if not seed:
            self.admit()
        values = {"seed": True} if seed else self.credentials()
        allocation = self.witness_call("/_ha/allocate", values)
        manifest = self.store.create(self.config["db"], self.config["identities"], allocation["generation"], allocation["created_at_ms"])
        if manifest["migration_sha256"] != self.artifact["migrations_sha256"]:
            raise RuntimeError("source database migrations differ from worker build")
        result = self.witness_call("/_ha/publish", {**values, "snapshot": self.store.export(manifest["generation"])})
        self.observe_replica(result)
        self.last_snapshot = time.monotonic()

    def observe_replica(self, result):
        with self.lock:
            self.replica = result
            self.replica_observed = time.monotonic()

    def fetch(self):
        result = self.witness_call("/_ha/snapshot-status", method="GET")
        self.observe_replica(result)
        manifest = result["manifest"]
        if not manifest:
            raise RuntimeError("no verified generation has been published")
        stamp = result["witness_now_ms"]
        age = stamp - manifest["created_at_ms"]
        if age < 0 or age > self.config["max_replica_age_ms"]:
            raise RuntimeError("latest generation is future-dated or too old for promotion")
        generation = manifest["generation"]
        try:
            local = self.store.verify(generation, stamp, self.config["max_replica_age_ms"])
        except ValueError:
            download = self.witness_call("/_ha/snapshot/" + str(generation), method="GET")
            local = self.store.import_snapshot(download["snapshot"], download["witness_now_ms"], self.config["max_replica_age_ms"])
            result["witness_now_ms"] = download["witness_now_ms"]
        if local["migration_sha256"] != self.artifact["migrations_sha256"]:
            raise RuntimeError("snapshot migrations differ from worker build")
        if local != manifest:
            raise RuntimeError("local immutable generation differs from witness pointer")
        return manifest, result["witness_now_ms"]

    def activate(self, record, deadline):
        previous = record["previous"]
        if record["epoch"] <= self.fenced_through:
            raise RuntimeError("this local epoch was already fenced")
        if previous:
            if previous["holder"] == self.node:
                with self.worker_lock:
                    self.worker.stop()
                    self.record_fence(previous["epoch"])
                proof = {"node": self.node, "fenced_through": self.fenced_through,
                         "successor_epoch": record["epoch"], "cgroup_empty": self.worker.stopped()}
            else:
                proof = self.remote(previous["holder"], "/_ha/fence", self.credentials())
            if (proof.get("node") != previous["holder"] or proof.get("fenced_through", 0) < previous["epoch"]
                    or proof.get("successor_epoch") != record["epoch"] or proof.get("cgroup_empty") is not True):
                raise RuntimeError("previous controller cgroup fence was not proven")
        barrier = self.witness_call("/_ha/barrier", self.credentials())
        if barrier.get("previous") != previous or barrier.get("successor_epoch") != record["epoch"] or barrier.get("external_actions_fenced") is not True:
            raise RuntimeError("external action barrier was not proven")
        manifest, stamp = self.fetch()
        with self.worker_lock:
            if not self.worker.stopped():
                raise RuntimeError("local worker is not stopped before replica install")
            self.store.install(manifest["generation"], self.config["db"], self.config["identities"], stamp, self.config["max_replica_age_ms"])
            if self.config.get("worker_user"):
                import pwd
                owner = pwd.getpwnam(self.config["worker_user"])
                for target in [self.config["db"], *(path for name, path in self.config["identities"].items() if name != "worker_env")]:
                    os.chown(target, owner.pw_uid, owner.pw_gid)
            self.verify_artifact()
            latest = self.witness_call("/_ha/snapshot-status", method="GET")
            if latest["manifest"] != manifest or not 0 <= latest["witness_now_ms"] - manifest["created_at_ms"] <= self.config["max_replica_age_ms"]:
                raise RuntimeError("generation became stale or changed during installation")
            deadline = self.consul.renew(self.session)
            self.consul.authority(self.node, record["epoch"], self.session)
            if record["epoch"] <= self.fenced_through:
                raise RuntimeError("epoch fenced during activation")
            self.worker.start(deadline, self.socket_path, record["epoch"])
            while True:
                try:
                    self.worker.health()
                    break
                except Exception:
                    if time.monotonic() >= deadline - 2 * self.config.get("stop_budget_ms", 2000) / 1000:
                        raise RuntimeError("worker did not become healthy within authority grant")
                    self.exit.wait(0.1)
            # cgroup enforcement is independent of this Python process.
            with self.lock:
                self.deadline = deadline
                self.active_epoch = record["epoch"]
                self.active = True
                self.blocked = ""
            settings = self.consul.settings()
            if settings.get("target") == self.node:
                settings["target"] = None
                self.consul.set_settings(settings)

    def readiness(self):
        self.verify_artifact()
        settings = self.consul.settings()
        self.consul.verify_voters()
        self.quorum = True
        self.fetch()
        self.executor_state = self.witness_call("/_ha/executor-status", method="GET")
        if not self.executor_state["ready"]:
            raise RuntimeError("external executor has unresolved jobs: " + ",".join(j["id"] for j in self.executor_state["blocked_jobs"]))
        return settings

    def action(self, action, target):
        if self.witness:
            raise RuntimeError("operator controls run on controller frontends")
        if action == "readiness":
            try:
                self.readiness()
                self.blocked = ""
            except Exception as error:
                self.blocked = str(error) if isinstance(error, (RuntimeError, SnapshotError)) else "readiness validation failed (" + type(error).__name__ + ")"
            return
        if action == "initialize":
            if not self.worker.stopped() or self.consul.get("lease") is not None:
                raise RuntimeError("initialization requires a stopped seed and no lease history")
            self.snapshot(seed=True)
            settings = self.consul.settings()
            settings.update({"paused": True, "target": self.node})
            self.consul.set_settings(settings)
            return
        settings = self.consul.settings()
        if action == "pause":
            settings["paused"] = True
        elif action == "resume":
            self.readiness()
            settings["paused"] = False
        elif action == "handover":
            self.admit()
            if target not in self.config["peers"] or target in (self.node, self.config["witness"]):
                raise RuntimeError("select a different configured controller")
            self.snapshot()
            settings.update({"paused": False, "target": target})
            self.consul.set_settings(settings)
            self.stop("planned handover to " + target)
            self.consul.release(self.session)
            self.session = None
            return
        else:
            raise RuntimeError("unknown operator action")
        self.consul.set_settings(settings)

    def status(self):
        if not self.witness:
            try:
                self.executor_state = self.witness_call("/_ha/executor-status", method="GET")
            except Exception:
                self.executor_state = {"ready": False, "blocked_reason": "executor unreachable"}
        with self.lock:
            manifest = self.replica["manifest"] if self.replica else None
            age = None if manifest is None else max(0, self.replica["witness_now_ms"] - manifest["created_at_ms"] + int((time.monotonic() - self.replica_observed) * 1000))
            return {"node": self.node, "role": "witness" if self.witness else "leader" if self.active else "follower" if self.lease and self.lease["holder"] != self.node else "isolated",
                    "leader": self.lease["holder"] if self.lease else None, "quorum": self.quorum,
                    "generation": manifest["generation"] if manifest else None, "snapshot_age_ms": age,
                    "replication_interval_ms": self.config.get("replication_interval_ms", 5000),
                    "maximum_promotion_age_ms": self.config["max_replica_age_ms"],
                    "rpo": "asynchronous; promotion may lose acknowledged changes up to the displayed snapshot age",
                    "fenced_through": self.fenced_through, "worker_admitted": self.active, "executor": self.executor_state,
                    "automatic_failover": getattr(self, "settings", {"paused": True}),
                    "blocked_reason": self.blocked}

    def step(self):
        self.quorum = False
        if self.session is None:
            self.session = self.consul.session(self.node)
        deadline = self.consul.renew(self.session)
        item = self.consul.get("lease")
        self.settings = self.consul.settings()
        self.consul.verify_voters()
        self.quorum = True
        record = item["record"] if item else None
        with self.lock:
            self.lease = record
        if item and item.get("Session") == self.session:
            self.consul.authority(self.node, record["epoch"], self.session)
            if self.active:
                with self.worker_lock:
                    self.worker.extend(deadline)
                    self.worker.health()
                    with self.lock:
                        self.deadline = deadline
                if time.monotonic() - self.last_snapshot >= self.config.get("replication_interval_ms", 5000) / 1000:
                    self.snapshot()
            else:
                self.activate(record, deadline)
        else:
            if self.active:
                self.stop("authority belongs to another session")
            self.fetch()
            if not item or not item.get("Session"):
                target = self.settings.get("target")
                if self.settings.get("paused", True):
                    self.blocked = "automatic failover is paused"
                elif target is not None and target != self.node:
                    self.blocked = "planned handover targets another controller"
                else:
                    acquired = self.consul.acquire(self.node, self.session)
                    if acquired:
                        self.lease = acquired
                        self.activate(acquired, deadline)
            else:
                self.blocked = ""

    def run(self):
        while not self.exit.is_set():
            try:
                self.step()
            except Exception as error:
                reason = str(error) if isinstance(error, (RuntimeError, SnapshotError)) else "HA dependency unavailable (" + type(error).__name__ + ")"
                try:
                    self.stop(reason)
                except Exception:
                    self.blocked = reason + "; worker cgroup fence could not be confirmed"
                if self.session:
                    try:
                        self.consul.release(self.session)
                    except Exception:
                        pass
                    self.session = None
            self.exit.wait(1)

    def reap(self):
        while not self.exit.wait(0.1):
            if self.active and time.monotonic() >= self.deadline - self.config.get("stop_budget_ms", 2000) / 1000:
                try:
                    self.stop("authority deadline reached")
                except Exception:
                    self.blocked = "authority expired and cgroup stop could not be confirmed"


class Broker(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(7320)
        try:
            raw = self.rfile.readline(64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024 or not raw.endswith(b"\n"):
                raise ValueError("broker frame invalid")
            app = self.server.app
            app.admit()
            transport = json.loads(raw)
            response = app.remote(app.config["witness"], "/_ha/execute",
                                  {**app.credentials(), "transport": transport},
                                  timeout=2 * transport["timeout_ms"] / 1000 + 70)
        except Exception:
            response = {"ok": False, "stdout_b64": "", "error": "HA executor unavailable; operation not replayed"}
        self.wfile.write(canonical(response) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    config = json.loads(Path(parser.parse_args().config).read_bytes())
    if config.get("replication_interval_ms", 5000) <= 0 or config["max_replica_age_ms"] <= 0:
        raise ValueError("replication intervals must be positive")
    budget = config.get("stop_budget_ms", 2000)
    if not 100 <= budget < 5000:
        raise ValueError("stop budget must be 100..4999ms")
    if config.get("role") != "witness":
        if config.get("worker_user") and not config.get("runtime_dir"):
            raise ValueError("a separate worker account requires an explicit searchable runtime_dir")
        required = {"deploy_key", "deploy_public", "known_hosts", "worker_env"}
        if set(config.get("identities", {})) != required:
            raise ValueError("HA identities require exactly deploy_key, deploy_public, known_hosts and worker_env")
        if not config["worker_addr"].startswith(("127.0.0.1:", "[::1]:")):
            raise ValueError("HA worker must listen only on loopback")
        if config.get("worker_env"):
            raise ValueError("HA application configuration belongs in replicated worker_env file")
    controllers = set(config["peers"]) - {config["witness"]}
    if len(controllers) != 2 or config["node_id"] not in config["peers"]:
        raise ValueError("HA requires exactly two controllers and one executor/storage witness")
    app = Supervisor(config)
    servers = []
    control = Server(address(config["control_addr"]), app, control=True, context=tls_context(config["tls"], server=True))
    servers.append(control)
    if not app.witness:
        public_context = None
        if config.get("public_tls"):
            public_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            public_context.minimum_version = ssl.TLSVersion.TLSv1_3
            public_context.load_cert_chain(config["public_tls"]["cert"], config["public_tls"]["key"])
        public_address = address(config["public_addr"])
        if not public_context and not __import__("ipaddress").ip_address(public_address[0]).is_loopback:
            raise ValueError("public HA listener requires TLS or a loopback reverse proxy")
        servers.append(Server(public_address, app, context=public_context))
        if app.socket_path.exists():
            app.socket_path.unlink()
        broker = Broker(str(app.socket_path), BrokerHandler)
        broker.app = app
        os.chmod(app.socket_path, 0o600)
        if config.get("worker_user"):
            import pwd
            os.chown(app.socket_path, pwd.getpwnam(config["worker_user"]).pw_uid, -1)
        servers.append(broker)
        for task in (app.run, app.reap):
            threading.Thread(target=task, daemon=True).start()
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    def shutdown(*_):
        app.exit.set()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    app.exit.wait()
    if app.worker:
        app.stop("supervisor shutdown")
    for server in servers:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
