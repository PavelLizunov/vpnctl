"""Opt-in fault tests with three real Consul voters and real systemd cgroups.

Run with VPNCTL_HA_CONSUL_BINARY=/path/to/consul VPNCTL_HA_SYSTEMD_TESTS=1.
Only disposable fixture workers, keys, SQLite files and transient units are used.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from common import Consul, canonical, request, tls_context

ROOT = Path(__file__).resolve().parent
CONSUL = os.environ.get("VPNCTL_HA_CONSUL_BINARY")
SYSTEMD = os.environ.get("VPNCTL_HA_SYSTEMD_TESTS") == "1"
FIXTURE_BYTES = int(os.environ.get("VPNCTL_HA_FIXTURE_BYTES", "0"))
FIXTURE_ADDRESS_SPACE_BYTES = 1536 * 1024 * 1024
USED_PORTS = set()


def port():
    # A bind-to-zero reservation is released before subprocess startup. Avoid
    # ephemeral ports so the fixture's own outgoing RPCs cannot steal listeners.
    low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
    below = max(0, low - 1024)
    above = max(1024, high + 1)
    count = below + max(0, 65536 - above)
    if not count:
        raise RuntimeError("fixture needs unprivileged ports outside the ephemeral range")
    for _ in range(2048):
        index = int.from_bytes(os.urandom(4), "big") % count
        value = 1024 + index if index < below else above + index - below
        if value in USED_PORTS:
            continue
        try:
            with socket.socket() as stream, socket.socket(type=socket.SOCK_DGRAM) as datagram:
                stream.bind(("127.0.0.1", value))
                datagram.bind(("127.0.0.1", value))
        except OSError:
            continue
        USED_PORTS.add(value)
        return value
    raise RuntimeError("fixture could not reserve available service ports")


def eventually(action, timeout=40):
    if FIXTURE_BYTES:
        timeout = max(timeout, 240)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = action()
            if value:
                return value
        except Exception as error:
            last = error
        time.sleep(.15)
    raise AssertionError("fixture condition did not become true: " + repr(last))


FIXTURE_WORKER = r'''#!/usr/bin/env python3
import base64,contextlib,hashlib,http.server,json,os,pathlib,socket,sqlite3,subprocess,sys,time,urllib.parse
SELF=pathlib.Path(__file__).resolve()
MIGRATION="1:" + "01"*48 + "\n"
if "--ha-artifact" in sys.argv:
 print(json.dumps({"schema":1,"executable_sha256":hashlib.sha256(SELF.read_bytes()).hexdigest(),"migrations_sha256":hashlib.sha256(MIGRATION.encode()).hexdigest()}));sys.exit()
if "--ha-execute" in sys.argv:
 req=json.load(sys.stdin); kind,path,delay,outcome=req["remote_cmd"].split("|")
 with open(path,"ab",buffering=0) as f: f.write(b"dispatched\n");os.fsync(f.fileno())
 time.sleep(float(delay))
 if outcome=="crash": os._exit(3)
 print(json.dumps({"ok":True,"stdout_b64":base64.b64encode(b"completed").decode()}));sys.exit()
ASSET=pathlib.Path("assets/admin.js").read_bytes()
db=pathlib.Path(sys.argv[sys.argv.index("--db")+1]);addr=sys.argv[sys.argv.index("--addr")+1];host,p=addr.rsplit(":",1)
db.with_suffix(".pid").write_text(str(os.getpid()))
child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(3600)"],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
db.with_suffix(".childpid").write_text(str(child.pid))
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  url=urllib.parse.urlsplit(self.path)
  if url.path=="/api/v1/health":body=b"ok"
  elif url.path=="/admin/assets/admin.js":body=ASSET
  elif url.path=="/write":
   with contextlib.closing(sqlite3.connect(db)) as c,c:c.execute("update fixture set count=count+1");body=str(c.execute("select count from fixture").fetchone()[0]).encode()
  else:
   with contextlib.closing(sqlite3.connect(db)) as c:body=c.execute("select artifact from fixture").fetchone()[0].encode()
  self.send_response(200);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
http.server.ThreadingHTTPServer((host,int(p)),Handler).serve_forever()
'''


@unittest.skipUnless(CONSUL and SYSTEMD, "requires explicit real Consul/systemd fixture opt-in")
class ClusterFaultTests(unittest.TestCase):
    def test_slow_pinned_follower_download_survives_multiple_publications(self):
        from common import decode_chunk
        from replica import SnapshotStore
        follower = self.controllers["fixture-b"]
        os.kill(follower.pid, signal.SIGSTOP)
        self.addCleanup(os.kill, follower.pid, signal.SIGCONT)
        witness = self.configs["fixture-witness"]["peers"]["fixture-witness"]
        context = self.contexts["fixture-b"]
        latest = request(witness, "GET", "/_ha/snapshot-status", context=context)["manifest"]
        generation = latest["generation"]
        transfer = request(witness, "GET", "/_ha/snapshot/" + str(generation), context=context, timeout=30)
        reads = 0
        try:
            sink = SnapshotStore(self.root / "slow-follower-transfer", self.configs["fixture-b"]["build"], 1)
            def reader(name, index, entry):
                nonlocal reads
                chunk = request(witness, "POST", "/_ha/chunk", {"pin": transfer["pin"], "generation": generation,
                                "name": name, "index": index}, context=context)
                reads += 1
                if reads == 1:
                    eventually(lambda: request(witness, "GET", "/_ha/snapshot-status", context=context)["manifest"]["generation"] >= generation + 3)
                    self.assertFalse((self.root / "fixture-witness/state/generations" / str(generation)).exists())
                return decode_chunk(chunk, entry)
            installed = sink.receive(transfer["description"], reader, transfer["witness_now_ms"], 120000)
            self.assertEqual(installed, latest)
            self.assertGreater(reads, 1)
            self.assertEqual(sink.verify(generation, transfer["witness_now_ms"], 120000), latest)
            self.assertTrue(self.status("fixture-a")["worker_admitted"])
        finally:
            request(witness, "POST", "/_ha/snapshot-release", {"pin": transfer["pin"]}, context=context)
            os.kill(follower.pid, signal.SIGCONT)

    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.temporary = tempfile.TemporaryDirectory(prefix="vpnctl-ha-fixture-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o711)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o755)
        self.bundle.chmod(0o755)
        for source in ROOT.glob("*.py"):
            if not source.name.startswith("test_"):
                shutil.copyfile(source, self.bundle / source.name)
                (self.bundle / source.name).chmod(0o644)
        self.processes = []
        self.logs = []
        self.controllers = {}
        self.addCleanup(self.cleanup)
        self.names = ["fixture-a", "fixture-b", "fixture-witness"]
        self.public = {node: port() for node in self.names[:2]}
        self.controls = {node: port() for node in self.names}
        self.consul_ports = [{"http": port(), "server": port(), "serf_lan": port(), "serf_wan": port(),
                              "dns": -1, "grpc": -1, "grpc_tls": -1, "https": -1} for _ in range(3)]
        self.consul_commands = []
        for index in range(3):
            directory = self.root / ("consul" + str(index));directory.mkdir()
            settings = {"server": True, "bootstrap_expect": 3, "node_name": "fixture-voter-" + str(index),
                        "data_dir": str(directory), "bind_addr": "127.0.0.1", "client_addr": "127.0.0.1",
                        "ports": self.consul_ports[index], "log_level": "ERROR",
                        "retry_join": ["127.0.0.1:" + str(self.consul_ports[0]["serf_lan"])],
                        "disable_update_check": True}
            path = self.root / ("consul" + str(index) + ".json");path.write_bytes(canonical(settings))
            command = [CONSUL, "agent", "-config-file=" + str(path)]
            self.consul_commands.append(command)
            self.processes.append(self.spawn(command, "consul-" + str(index)))
        self.consul = Consul({"url": "http://127.0.0.1:" + str(self.consul_ports[0]["http"])})
        eventually(lambda: self.consul.get("settings") is None and len(self.consul.call("GET", "operator/raft/configuration")["Servers"]) == 3)
        self.make_certificates()
        self.helper = self.root / "fixture-worker.py";self.helper.write_text(FIXTURE_WORKER);self.helper.chmod(0o755)
        assets = self.root / "assets";assets.mkdir(mode=0o755);assets.chmod(0o755)
        (assets / "admin.js").write_bytes(b"fixture-installed-admin-asset")
        (assets / "admin.js").chmod(0o644)
        build = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.configs = {}
        self.token = "fixture-management-token-not-live"
        (self.root / "retained-fixture-identities").mkdir(mode=0o700)
        for node in self.names:
            directory = self.root / node;directory.mkdir(mode=0o711);directory.chmod(0o711)
            data_dir = directory / "data";data_dir.mkdir(mode=0o700)
            worker_user = None
            if os.geteuid() == 0 and node != "fixture-witness":
                import pwd
                owner = pwd.getpwnam("nobody")
                os.chown(data_dir, owner.pw_uid, owner.pw_gid)
                worker_user = "nobody"
            token = directory / "admin-token";token.write_text(self.token)
            identities = {}
            for name, value in {"deploy_key": "fixture-deploy-identity-not-a-key", "deploy_public": "fixture-public-identity", "known_hosts": "", "worker_env": ""}.items():
                path = (directory if name == "worker_env" else data_dir) / name
                path.write_text(value);identities[name] = str(path)
            database = data_dir / "inventory.db"
            with closing(sqlite3.connect(database)) as db, db:
                db.executescript("create table _sqlx_migrations(version bigint primary key,description text,installed_on text,success boolean,checksum blob,execution_time bigint);create table fixture(artifact text,count int);")
                db.execute("insert into _sqlx_migrations values(1,'fixture','2026-01-01',1,?,0)", (bytes([1])*48,))
                db.execute("insert into fixture values('fixture-subscription-byte-contract',0)")
                if FIXTURE_BYTES:
                    # Generated fixture telemetry, never a production DB copy.
                    db.execute("create table server_metrics(id integer primary key, sample blob)")
                    for _ in range((FIXTURE_BYTES + 1024 * 1024 - 1) // (1024 * 1024)):
                        db.execute("insert into server_metrics(sample) values(zeroblob(1048576))")
            config = {"node_id": node, "role": "witness" if node == "fixture-witness" else "controller", "state_dir": str(directory / "state"), "runtime_dir": str(directory / "runtime"),
                      "worker": str(self.helper), "build": build, "schema": 1,
                      "tls": {"ca": str(self.root / "ca.crt"), "cert": str(self.root / (node + ".crt")), "key": str(self.root / (node + ".key"))},
                      "consul": {"url": self.consul.url}, "peers": {name: "https://localhost:" + str(self.controls[name]) for name in self.names},
                      "witness": "fixture-witness", "seed_node": "fixture-a", "control_addr": "127.0.0.1:" + str(self.controls[node]),
                      "public_addr": "127.0.0.1:" + str(self.public.get(node, 0)), "admin_token_file": str(token), "db": str(database),
                      "identities": identities, "deploy_key": identities["deploy_key"], "worker_addr": "127.0.0.1:" + str(port()),
                      "systemd_user": os.geteuid() != 0, "stop_budget_ms": 1000, "replication_interval_ms": 1000, "max_replica_age_ms": 600000 if FIXTURE_BYTES else 120000,
                      "credential_root": str(self.root / "retained-fixture-identities" / node)}
            if worker_user:
                config["worker_user"] = worker_user
            path = directory / "config.json";path.write_bytes(canonical(config));self.configs[node] = config
            self.controllers[node] = self.spawn([sys.executable, str(self.bundle / "controller_ha.py"), "--config", str(path)], node)
        self.contexts = {node: tls_context(config["tls"]) for node, config in self.configs.items()}
        eventually(lambda: all(self.status(node)["node"] == node for node in self.names))
        self.manage("fixture-a", "pause")  # Existing settings are not lease history.
        self.manage("fixture-a", "initialize")
        self.manage("fixture-a", "resume")
        eventually(lambda: self.status("fixture-a")["worker_admitted"] and self.consul.settings().get("target") is None)
        def follower_ready():
            code, body = self.get("fixture-b", "/sub/fixture-token")
            if code == 200 and body == b"fixture-subscription-byte-contract":
                return True
            raise RuntimeError("follower HTTP " + str(code) + ": " + repr(body[:1024]) + "; leader=" + json.dumps(self.status("fixture-a")) + "; follower=" + json.dumps(self.status("fixture-b")))
        eventually(follower_ready)

    def spawn(self, command, name):
        log = (self.root / (name + ".log")).open("ab");self.logs.append(log)
        limiter = None
        if FIXTURE_BYTES and any(str(value).endswith("/controller_ha.py") for value in command):
            def limiter():
                import resource
                resource.setrlimit(resource.RLIMIT_AS, (FIXTURE_ADDRESS_SPACE_BYTES, FIXTURE_ADDRESS_SPACE_BYTES))
        environment = dict(os.environ)
        if limiter:
            # Bound glibc's virtual malloc arenas as well as live buffers while
            # measuring a constrained fixture; this does not affect the host.
            environment["MALLOC_ARENA_MAX"] = "2"
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                preexec_fn=limiter, env=environment)

    def memory_high_water(self):
        result = {}
        for node, process in self.controllers.items():
            try:
                fields = Path("/proc/" + str(process.pid) + "/status").read_text().splitlines()
                result[node] = next(line.split(":", 1)[1].strip() for line in fields if line.startswith("VmHWM:"))
            except (FileNotFoundError, StopIteration):
                pass
        return result

    def make_certificates(self):
        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=HA-fixture-CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(self.root / "ca.key"), "-out", str(self.root / "ca.crt"))
        extension = self.root / "ext";extension.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n")
        for node in self.names:
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + node, "-keyout", str(self.root / (node + ".key")), "-out", str(self.root / (node + ".csr")))
            openssl("x509", "-req", "-in", str(self.root / (node + ".csr")), "-CA", str(self.root / "ca.crt"), "-CAkey", str(self.root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(extension), "-out", str(self.root / (node + ".crt")))

    def status(self, node):
        result = request(self.configs[node]["peers"][node], "GET", "/_ha/status", context=self.contexts["fixture-b"])
        self.last_status = result
        return result

    def get(self, node, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.public[node], timeout=4)
        try:
            conn.request("GET", path);response=conn.getresponse();return response.status,response.read()
        finally:conn.close()

    def manage(self, node, action, target="fixture-b"):
        conn = http.client.HTTPConnection("127.0.0.1", self.public[node], timeout=600 if FIXTURE_BYTES else 10)
        headers={"Authorization":"Basic "+base64.b64encode(("ha:"+self.token).encode()).decode()}
        try:
            conn.request("GET","/admin/ha",headers=headers);response=conn.getresponse();body=response.read().decode()
            self.assertEqual(response.status,200)
            csrf=re.search('name="csrf" value="([^"]+)"',body)[1]
            import urllib.parse
            data=urllib.parse.urlencode({"csrf":csrf,"action":action,"target":target})
            headers["Content-Type"]="application/x-www-form-urlencoded"
            conn.request("POST","/admin/ha",body=data,headers=headers);response=conn.getresponse();body=response.read()
            self.assertEqual(response.status,303,body)
        finally:conn.close()

    def cleanup(self):
        if getattr(self, "last_status", {}).get("blocked_reason"):
            print("last fixture status:", json.dumps(self.last_status), flush=True)
        for process in getattr(self,"controllers",{}).values():
            if process.poll() is None:
                process.send_signal(signal.SIGCONT);process.terminate()
        for process in getattr(self,"processes",[]):
            if process.poll() is None:process.terminate()
        for process in [*getattr(self,"controllers",{}).values(),*getattr(self,"processes",[])]:
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for node in ("fixture-a","fixture-b"):
            command=["systemctl"]+(["--user"] if os.geteuid()!=0 else [])+["stop","vpnctl-ha-worker-"+node+".service"]
            subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        for log in getattr(self,"logs",[]):log.close()
        for path in self.root.glob("*.log"):
            if not path.name.startswith("consul-") and path.stat().st_size:
                print("fixture process log " + path.name + ": " + path.read_text()[-6000:], flush=True)
        if hasattr(self,"temporary"):self.temporary.cleanup()

    def test_crash_sigstop_handover_and_byte_compatible_forwarding(self):
        for node in ("fixture-a", "fixture-b"):
            self.assertEqual(self.get(node, "/admin/assets/admin.js"), (200, b"fixture-installed-admin-asset"))
        # Application paths cannot become control RPCs at the private hop.
        self.assertEqual(self.get("fixture-b", "/_ha/status"), (200, b"fixture-subscription-byte-contract"))
        # Both frontend URLs handle GET mutations through the same writable worker.
        self.assertEqual(self.get("fixture-a","/write"),(200,b"1"))
        self.assertEqual(self.get("fixture-b","/write"),(200,b"2"))
        eventually(lambda: self.status("fixture-b")["generation"] == self.status("fixture-a")["generation"])
        self.manage("fixture-a","handover")
        eventually(lambda:self.status("fixture-b")["worker_admitted"])
        self.assertEqual(self.get("fixture-a", "/admin/assets/admin.js"), (200, b"fixture-installed-admin-asset"))
        self.assertEqual(self.get("fixture-a","/sub/fixture-token"),self.get("fixture-b","/sub/fixture-token"))
        age=self.status("fixture-b")["snapshot_age_ms"];self.assertGreaterEqual(age,0);self.assertLess(age,120000)
        print("verified snapshot age observed after planned handover: " + str(age) + "ms (fixture RPO upper bound)", flush=True)
        db=Path(self.configs["fixture-b"]["db"])
        old_pid=int(db.with_suffix(".pid").read_text());old_child=int(db.with_suffix(".childpid").read_text())
        os.kill(old_pid,signal.SIGSTOP)
        eventually(lambda:self.status("fixture-a")["worker_admitted"],timeout=60)
        self.assertFalse(Path("/proc/"+str(old_pid)).exists())
        eventually(lambda: not Path("/proc/"+str(old_child)).exists() or Path("/proc/"+str(old_child)+"/stat").read_text().split()[2]=="Z")
        self.assertEqual(self.get("fixture-b","/sub/fixture-token"),(200,b"fixture-subscription-byte-contract"))
        # A hard worker crash follows the same verified fence path.
        pid=int(Path(self.configs["fixture-a"]["db"]).with_suffix(".pid").read_text())
        os.kill(pid,signal.SIGKILL)
        eventually(lambda:self.status("fixture-b")["worker_admitted"],timeout=60)
        self.assertEqual(self.get("fixture-a","/sub/fixture-token"),(200,b"fixture-subscription-byte-contract"))

    def test_quorum_loss_and_suspended_old_supervisor_fail_closed(self):
        old=self.controllers["fixture-a"];os.kill(old.pid,signal.SIGSTOP)
        # Even a frozen supervisor cannot extend the independent systemd deadline.
        pid=int(Path(self.configs["fixture-a"]["db"]).with_suffix(".pid").read_text())
        eventually(lambda:not Path("/proc/"+str(pid)).exists(),timeout=25)
        # No RPC response from the suspended manager is required: the durable
        # witness arm and independent systemd watchdog prove bounded resource
        # access, while the executor barrier closes its old SSH epoch.
        eventually(lambda:self.status("fixture-b")["worker_admitted"],timeout=60)
        os.kill(old.pid,signal.SIGCONT)
        eventually(lambda:not self.status("fixture-a")["worker_admitted"])
        self.assertEqual(self.get("fixture-a", "/sub/fixture-token"), (200, b"fixture-subscription-byte-contract"))
        for process in self.processes[1:]:process.terminate();process.wait(timeout=8)
        eventually(lambda:not self.status("fixture-b")["worker_admitted"],timeout=25)
        self.assertNotEqual(self.get("fixture-b","/sub/fixture-token")[0],200)

    def test_killed_unreachable_manager_promotes_after_independent_arm(self):
        old = self.controllers["fixture-a"]
        pid = int(Path(self.configs["fixture-a"]["db"]).with_suffix(".pid").read_text())
        old_grant = self.consul.get("lease")["record"]
        peak_before = self.memory_high_water()
        started = time.monotonic()
        old.kill(); old.wait()
        eventually(lambda: self.status("fixture-b")["worker_admitted"], timeout=60)
        self.assertFalse(Path("/proc/" + str(pid)).exists())
        self.assertEqual(self.get("fixture-b", "/sub/fixture-token"), (200, b"fixture-subscription-byte-contract"))
        stale_effect = self.root / "stale-external-effect"
        with self.assertRaises(RuntimeError):
            request(self.configs["fixture-a"]["peers"]["fixture-witness"], "POST", "/_ha/execute",
                    {**old_grant, "build": self.configs["fixture-a"]["build"],
                     "transport": {"timeout_ms": 1000, "remote_cmd": "append|" + str(stale_effect) + "|0|ok"}},
                    context=self.contexts["fixture-a"])
        self.assertFalse(stale_effect.exists())
        if FIXTURE_BYTES:
            manifest = json.loads((self.root / "fixture-witness/state/snapshots.json").read_text())["latest"]
            print("current-size isolated evidence: " + json.dumps({
                "fixture_requested_bytes": FIXTURE_BYTES,
                "snapshot_database_bytes": manifest["files"]["inv_db"]["size_bytes"],
                "snapshot_total_bytes": sum(entry["size_bytes"] for entry in manifest["files"].values()),
                "supervisor_address_space_limit_bytes": FIXTURE_ADDRESS_SPACE_BYTES,
                "fixture_malloc_arena_max": 2,
                "peak_rss_before_crash": peak_before, "peak_rss_after_promotion": self.memory_high_water(),
                "failover_to_usable_seconds": round(time.monotonic() - started, 3),
                "old_worker_reaped": True, "subscription_bytes_preserved": True, "stale_external_dispatch_count": 0,
            }), flush=True)
        # Restarting the old manager fences any leftover worker and rejoins as
        # a proxy; its divergent inventory cannot regain authority.
        path = self.root / "fixture-a" / "config.json"
        self.controllers["fixture-a"] = self.spawn([sys.executable, str(self.bundle / "controller_ha.py"), "--config", str(path)], "old-manager-restart")
        eventually(lambda: self.get("fixture-a", "/sub/fixture-token") == (200, b"fixture-subscription-byte-contract"))
        self.assertFalse(self.status("fixture-a")["worker_admitted"])

    def test_failed_candidate_preserves_unreachable_predecessor_evidence(self):
        old = self.controllers["fixture-a"]
        os.kill(old.pid, signal.SIGSTOP)
        original = self.consul.get("lease")["record"]
        self.consul.release(original["session"])
        candidate = eventually(lambda: (item["record"] if (item := self.consul.get("lease")) and item.get("Session")
                                         and item["record"]["epoch"] > original["epoch"] else None))
        self.assertEqual(candidate["holder"], "fixture-b")
        # Fail a candidate before it can arm a worker, then let a later lease
        # recover.  Consul's immediate previous lease now names the candidate,
        # while the independent lifecycle must still name the actual worker.
        self.consul.release(candidate["session"])
        url = self.configs["fixture-b"]["peers"]["fixture-witness"]
        evidence = request(url, "GET", "/_ha/lifecycle-status", context=self.contexts["fixture-b"])
        self.assertEqual(evidence["worker"]["node"], "fixture-a")
        self.assertEqual(evidence["worker"]["epoch"], original["epoch"])
        self.assertFalse(evidence["ready"])
        eventually(lambda: self.status("fixture-b")["worker_admitted"], timeout=60)
        current = self.consul.get("lease")["record"]
        self.assertGreater(current["epoch"], candidate["epoch"])
        os.kill(old.pid, signal.SIGCONT)
        eventually(lambda: not self.status("fixture-a")["worker_admitted"])
        self.assertEqual(self.get("fixture-a", "/sub/fixture-token"), (200, b"fixture-subscription-byte-contract"))

    def test_stalled_replication_does_not_block_renewal_or_quorum_loss_stop(self):
        # Instrument only the disposable copied module, then restart the
        # witness-independent follower and the leader supervisor cleanly.
        source = self.bundle / "replica.py"
        source.write_text(source.read_text() + """\n
_fixture_create = SnapshotStore.create
def _fixture_stall(self, *args, **kwargs):
    marker = Path(""" + repr(str(self.root / "stall-copy")) + """)
    if marker.exists():
        marker.with_suffix('.started').touch()
        import time
        time.sleep(40)
    return _fixture_create(self, *args, **kwargs)
SnapshotStore.create = _fixture_stall
""")
        old = self.controllers["fixture-a"]
        old.terminate(); old.wait(timeout=8)
        path = self.root / "fixture-a" / "config.json"
        self.controllers["fixture-a"] = self.spawn([sys.executable, str(self.bundle / "controller_ha.py"), "--config", str(path)], "stalled-copy-manager")
        eventually(lambda: self.status("fixture-a")["worker_admitted"] or self.status("fixture-b")["worker_admitted"], timeout=60)
        if self.status("fixture-b")["worker_admitted"]:
            self.manage("fixture-b", "handover", target="fixture-a")
            eventually(lambda: self.status("fixture-a")["worker_admitted"], timeout=60)
        (self.root / "stall-copy").touch()
        eventually(lambda: (self.root / "stall-copy.started").exists())
        epoch = self.consul.get("lease")["record"]["epoch"]
        time.sleep(17)  # A snapshot spans more than the 15-second grant bound.
        self.assertTrue(self.status("fixture-a")["worker_admitted"])
        self.assertEqual(self.consul.get("lease")["record"]["epoch"], epoch)
        self.assertEqual(self.get("fixture-a", "/sub/fixture-token"), (200, b"fixture-subscription-byte-contract"))
        started = time.monotonic()
        for process in self.processes[1:]:
            process.terminate(); process.wait(timeout=8)
        eventually(lambda: not self.status("fixture-a")["worker_admitted"], timeout=20)
        self.assertLess(time.monotonic() - started, 20)
        self.assertNotEqual(self.get("fixture-a", "/sub/fixture-token")[0], 200)
        self.assertTrue((self.root / "stall-copy.started").exists())

    def test_stale_and_mismatched_generation_block_automatic_promotion(self):
        self.manage("fixture-a", "pause")
        pid = int(Path(self.configs["fixture-a"]["db"]).with_suffix(".pid").read_text())
        os.kill(pid, signal.SIGKILL)
        eventually(lambda: not self.status("fixture-a")["worker_admitted"])
        metadata_path = self.root / "fixture-witness" / "state" / "snapshots.json"
        original = json.loads(metadata_path.read_bytes())
        for field, value, reason in [("created_at_ms", 1, "too old"),
                                     ("build", "mismatched-fixture-build", "differs")]:
            settings = self.consul.settings(); settings.update({"paused": True, "target": "fixture-b"})
            self.consul.set_settings(settings)
            witness = self.controllers["fixture-witness"]; witness.terminate(); witness.wait(timeout=8)
            changed = json.loads(json.dumps(original)); changed["latest"][field] = value
            metadata_path.write_bytes(canonical(changed))
            path = self.root / "fixture-witness" / "config.json"
            self.controllers["fixture-witness"] = self.spawn([sys.executable, str(self.bundle / "controller_ha.py"), "--config", str(path)], "witness-restart")
            eventually(lambda: request(self.configs["fixture-a"]["peers"]["fixture-witness"], "GET", "/_ha/snapshot-status", context=self.contexts["fixture-a"]))
            settings = self.consul.settings(); settings["paused"] = False; self.consul.set_settings(settings)
            eventually(lambda: reason in self.status("fixture-b")["blocked_reason"])
            self.assertFalse(self.status("fixture-b")["worker_admitted"])
            self.assertNotEqual(self.get("fixture-b", "/sub/fixture-token")[0], 200)

    def test_uncertain_remote_operation_survives_witness_restart_and_blocks_promotion(self):
        lease=self.consul.get("lease")["record"]
        marker=self.root/"remote-effect"
        transport={"timeout_ms":1000,"remote_cmd":"append|"+str(marker)+"|0|crash"}
        response=request(self.configs["fixture-witness"]["peers"]["fixture-witness"],"POST","/_ha/execute",{**lease,"build":self.configs["fixture-a"]["build"],"transport":transport},self.contexts["fixture-a"])
        self.assertFalse(response["ok"])
        self.assertEqual(marker.read_bytes(),b"dispatched\n")
        witness=self.controllers["fixture-witness"];witness.kill();witness.wait()
        path=self.root/"fixture-witness"/"config.json"
        self.controllers["fixture-witness"]=self.spawn([sys.executable,str(self.bundle/"controller_ha.py"),"--config",str(path)],"witness-restart")
        url=self.configs["fixture-a"]["peers"]["fixture-witness"]
        result=eventually(lambda:request(url,"GET","/_ha/executor-status",context=self.contexts["fixture-a"]))
        self.assertFalse(result["ready"]);self.assertEqual(len(result["blocked_jobs"]),1)
        from worker import Worker
        previous = Worker(self.configs["fixture-a"])
        previous.stop()
        self.assertTrue(previous.stopped())
        eventually(lambda:self.status("fixture-b")["blocked_reason"].startswith("control request rejected"),timeout=45)
        self.assertFalse(self.status("fixture-b")["worker_admitted"])
        self.assertEqual(marker.read_bytes(),b"dispatched\n")


if __name__=="__main__":unittest.main()
