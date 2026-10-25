#!/usr/bin/env python3
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock
from pathlib import Path

RUNNER = Path(__file__).parents[1] / "protocol-assurance-runner.py"
SPEC = importlib.util.spec_from_file_location("assurance_runner", RUNNER)
RUNNER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER_MODULE)


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.configs = self.root / "configs"
        self.configs.mkdir(mode=0o700)
        self.engine = self.root / "fake-engine"
        self.engine.write_text(
            "#!/usr/bin/env python3\n"
            "import json,socket,sys,time\n"
            "config=json.load(open(sys.argv[-1]))\n"
            "s=socket.socket();s.bind(('127.0.0.1',int(config['port'])));s.listen();time.sleep(5)\n"
        )
        self.engine.chmod(0o755)
        self.curl = self.root / "curl"
        self.curl.write_text(
            "#!/bin/bash\n"
            "args=\" $* \"\n"
            "case \"$args\" in *' --socks5-hostname '*) ;; *) exit 90;; esac\n"
            "case \"$args\" in *' --noproxy '*) exit 91;; esac\n"
            "[ -z \"${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}${NO_PROXY:-}\" ] || exit 92\n"
            "printf \"${FAKE_HTTP_CODE:-204}\"\nexit \"${FAKE_CURL_EXIT:-0}\"\n"
        )
        self.curl.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_runner(self, request, template=None, mode=0o600, extra_env=None):
        server = request["server"]
        protocol = request["protocol"]
        name = __import__("hashlib").sha256(server.encode()).hexdigest() + "." + protocol + ".json"
        if template is not None:
            path = self.configs / name
            path.write_text(json.dumps(template))
            path.chmod(mode)
        env = os.environ.copy()
        env.update(
            VPNCTL_ASSURANCE_CONFIG_DIR=str(self.configs),
            VPNCTL_ASSURANCE_SING_BOX=str(self.engine),
            VPNCTL_ASSURANCE_XRAY=str(self.engine),
        )
        extra_env = extra_env or {}
        env.update(extra_env)
        if "FAKE_HTTP_CODE" in extra_env or "FAKE_CURL_EXIT" in extra_env:
            self.curl.write_text(
                "#!/bin/bash\n"
                "args=\" $* \"\n"
                "case \"$args\" in *' --socks5-hostname '*) ;; *) exit 90;; esac\n"
                "case \"$args\" in *' --noproxy '*) exit 91;; esac\n"
                "[ -z \"${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}${NO_PROXY:-}\" ] || exit 92\n"
                f"printf {extra_env.get('FAKE_HTTP_CODE', '204')}\nexit {extra_env.get('FAKE_CURL_EXIT', '0')}\n"
            )
            self.curl.chmod(0o755)
        copy = self.root / "runner"
        copy.write_text(RUNNER.read_text().replace('"/usr/bin/curl"', repr(str(self.curl))))
        copy.chmod(0o755)
        result = subprocess.run(
            [str(copy)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
        return json.loads(result.stdout)

    def test_missing_config_is_blocked(self):
        result = self.run_runner({"server": "192.0.2.1", "protocol": "hysteria2", "ports": [["udp", 8444]]})
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["failure_code"], "probe_config_missing")

    def test_unsafe_config_permissions_are_blocked(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": [["udp", 8444]]},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
            0o644,
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["stage"], "client_import")
        self.assertEqual(result["failure_code"], "probe_config_unsafe")

    def test_successful_transfer_returns_verified(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": [["udp", 8444]]},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["stage"], "transfer")
        self.assertEqual(result["client_kind"], "sing-box")

    def test_non_204_is_transfer_failed(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": [["udp", 8444]]},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
            extra_env={"FAKE_HTTP_CODE": "503"},
        )
        self.assertEqual(result["stage"], "transfer")
        self.assertEqual(result["failure_code"], "transfer_failed")

    def test_curl_failure_is_handshake_timeout(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": [["udp", 8444]]},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
            extra_env={"FAKE_CURL_EXIT": "7"},
        )
        self.assertEqual(result["stage"], "handshake")
        self.assertEqual(result["failure_code"], "handshake_timeout")

    def test_xray_engine_is_supported(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "vless+xhttp", "ports": [["tcp", 9443]]},
            {"engine": "xray", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["client_kind"], "xray")

    def test_unsafe_config_directory_is_blocked(self):
        self.configs.chmod(0o755)
        result = self.run_runner({"server": "192.0.2.1", "protocol": "hysteria2", "ports": []})
        self.assertEqual(result["failure_code"], "probe_config_unsafe")

    def test_ambient_proxy_variables_are_not_forwarded(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
            extra_env={"ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "*"},
        )
        self.assertEqual(result["state"], "verified")

    def test_invalid_engine_is_blocked(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "other", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["failure_code"], "probe_engine_invalid")

    def test_engine_crash_is_blocked(self):
        self.engine.write_text("#!/bin/bash\nexit 1\n")
        self.engine.chmod(0o755)
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["failure_code"], "client_start_failed")

    def test_engine_without_listener_times_out(self):
        self.engine.write_text("#!/bin/bash\nexec sleep 5\n")
        self.engine.chmod(0o755)
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["failure_code"], "client_start_timeout")

    def test_writable_engine_is_blocked(self):
        self.engine.chmod(0o777)
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
        )
        self.assertEqual(result["failure_code"], "probe_engine_unsafe")

    def test_owner_mismatch_is_rejected_by_trust_checks(self):
        template = self.configs / "template"
        template.write_text("{}")
        template.chmod(0o600)
        with mock.patch.object(RUNNER_MODULE.os, "geteuid", return_value=os.geteuid() + 1):
            with redirect_stdout(StringIO()), self.assertRaises(SystemExit):
                RUNNER_MODULE.trusted_file(template)

    def test_missing_engine_is_blocked(self):
        result = self.run_runner(
            {"server": "192.0.2.1", "protocol": "hysteria2", "ports": []},
            {"engine": "sing-box", "config": {"port": "__PORT__"}},
            extra_env={"VPNCTL_ASSURANCE_SING_BOX": str(self.root / "missing")},
        )
        self.assertEqual(result["failure_code"], "probe_engine_missing")

    def test_outer_timeout_kills_engine_in_runner_group(self):
        try:
            with socket.socket():
                pass
        except PermissionError:
            self.skipTest("sandbox prohibits sockets required by the real runner")
        record = self.root / "engine.json"
        self.engine.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,signal,socket,sys,time\n"
            "config_path=sys.argv[-1]\n"
            "config=json.load(open(config_path))\n"
            "s=socket.socket();s.bind(('127.0.0.1',config['port']));s.listen()\n"
            "with open(config['record'],'w') as f:\n"
            " json.dump({'pid':os.getpid(),'group':os.getpgrp(),'config':config_path},f)\n"
            "os.kill(os.getppid(),signal.SIGSTOP)\n"
            "time.sleep(60)\n"
        )
        request = {"server": "192.0.2.1", "protocol": "hysteria2"}
        name = __import__("hashlib").sha256(request["server"].encode()).hexdigest() + ".hysteria2.json"
        template = self.configs / name
        template.write_text(json.dumps({"engine": "sing-box", "config": {"port": "__PORT__", "record": str(record)}}))
        template.chmod(0o600)
        env = dict(os.environ, VPNCTL_ASSURANCE_CONFIG_DIR=str(self.configs),
                   VPNCTL_ASSURANCE_SING_BOX=str(self.engine), TMPDIR=str(self.root))
        runner = subprocess.Popen([sys.executable, str(RUNNER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, start_new_session=True)
        engine = None
        try:
            runner.stdin.write(json.dumps(request).encode())
            runner.stdin.close()
            runner.stdin = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = Path(f"/proc/{runner.pid}/stat").read_text().rsplit(") ", 1)[1]
                if record.exists() and status.startswith("T"):
                    break
                time.sleep(0.01)
            engine = json.loads(record.read_text())
            self.assertTrue(Path(engine["config"]).exists())
            os.killpg(runner.pid, signal.SIGKILL)
            runner.communicate(timeout=5)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    state = Path(f"/proc/{engine['pid']}/stat").read_text().rsplit(") ", 1)[1]
                except (FileNotFoundError, ProcessLookupError):
                    break  # the process vanished between checks
                if state.startswith("Z"):
                    break
                time.sleep(0.01)
            else:
                self.fail("engine survived the outer runner timeout")
            self.assertEqual(engine["group"], runner.pid)
        finally:
            if runner.poll() is None:
                os.killpg(runner.pid, signal.SIGKILL)
                runner.communicate(timeout=5)
            if engine is not None:
                try:
                    os.kill(engine["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_stop_process_reaps_engine_in_inherited_group(self):
        process = subprocess.Popen(["bash", "-c", "exec sleep 60"])
        try:
            self.assertEqual(os.getpgid(process.pid), os.getpgrp())
            RUNNER_MODULE.stop_process(process)
            self.assertEqual(process.poll(), -signal.SIGTERM)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)

    def test_stop_process_escalates_after_termination_timeout(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("engine", 2), None]
        RUNNER_MODULE.stop_process(process)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
