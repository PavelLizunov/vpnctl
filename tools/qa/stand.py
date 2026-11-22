"""Ephemeral, loopback-only vpnctl and OpenSSH fixtures on Linux."""
import contextlib
import os
from pathlib import Path
import signal
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import NamedTuple
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


class Stand(NamedTuple):
    origin: str
    namespace_pid: int


@contextlib.contextmanager
def stand(port=0):
    bundle_setting = os.environ.get("VPNCTL_QA_BUNDLE")
    if not bundle_setting:
        raise ValueError("Set VPNCTL_QA_BUNDLE to an unpacked vpnctl CI candidate")
    bundle = Path(bundle_setting).resolve()
    for name in ("bin/vpnctl", "bin/vpnctld", "assets/admin.js"):
        if not (bundle / name).is_file():
            raise ValueError(f"Missing {name} in VPNCTL_QA_BUNDLE")

    with tempfile.TemporaryDirectory(prefix="vpnctl-qa-", dir="/tmp") as directory:
        root = Path(directory)
        for name in ("node-etc", "controller", "relay"):
            (root / name).mkdir(mode=0o700)
        for key in ("node-etc/host_key", "controller/id_ed25519"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", root / key],
                           check=True, stdout=subprocess.DEVNULL)
        (root / "authorized_keys").write_bytes((root / "controller/id_ed25519.pub").read_bytes())
        passwd = ("root:x:0:0:QA root:/root:/bin/sh\n"
                  "nobody:x:65534:65534:nobody:/tmp:/bin/false\n"
                  "sshd:x:74:74:sshd:/var/empty:/bin/false\n")
        (root / "passwd").write_text(passwd)
        (root / "node-etc/passwd").write_text(passwd)
        (root / "node-etc/group").write_text("root:x:0:\nnobody:x:65534:\nsshd:x:74:\n")
        (root / "node-etc/shadow").write_text("root:*:19000:0:99999:7:::\n")
        (root / "node-etc/sshd_config").write_text(
            "Port 2222\nListenAddress 127.0.0.1\nHostKey /etc/host_key\n"
            "PermitRootLogin prohibit-password\nPasswordAuthentication no\nUsePAM no\n"
            "KbdInteractiveAuthentication no\nDisableForwarding yes\n"
        )
        class Relay(socketserver.BaseRequestHandler):
            def handle(self):
                subprocess.run(["socat", "STDIO", f"UNIX-CONNECT:{root}/relay/http.sock"],
                               stdin=self.request, stdout=self.request, stderr=subprocess.DEVNULL)

        class RelayServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        with RelayServer(("127.0.0.1", port), Relay) as listener:
            origin = f"http://127.0.0.1:{listener.server_address[1]}"
            with (root / "startup.log").open("wb") as log:
                proc = subprocess.Popen(
                    ["unshare", "--user", "--map-auto", "--map-root-user", "--net", "--pid",
                     "--fork", "--kill-child=KILL", "--", "bash", Path(__file__).with_name("namespace.sh"),
                     root, bundle], stdin=subprocess.PIPE, stdout=log, stderr=log, start_new_session=True,
                    env={"PATH": os.defpath + ":/usr/sbin:/sbin", "LC_ALL": "C"},
                )
                thread = threading.Thread(target=listener.serve_forever, daemon=True)
                thread.start()
                try:
                    http = build_opener(ProxyHandler({}))
                    for _ in range(120):
                        if proc.poll() is not None:
                            raise RuntimeError("QA namespace stopped. Check userns, subuid/subgid, bwrap, socat and sshd.")
                        if (root / "relay/http.sock").exists():
                            try:
                                with http.open(origin + "/api/v1/health", timeout=1) as response:
                                    if response.status == 200:
                                        break
                            except (OSError, URLError):
                                pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("QA daemon did not become healthy")
                    yield Stand(origin, proc.pid)
                finally:
                    if proc.poll() is None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    proc.stdin.close()
                    listener.shutdown()
                    thread.join()
