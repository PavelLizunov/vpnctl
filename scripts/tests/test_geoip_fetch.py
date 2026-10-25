#!/usr/bin/env python3
import gzip
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "vpnctl-geoip-fetch-via-node.sh"


@unittest.skipUnless(shutil.which("sqlite3") and shutil.which("bash"), "requires sqlite3 and bash")
class GeoipFetchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(self.root / "inv.db")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=0")
        self.db.execute("CREATE TABLE servers (id TEXT, ssh_user TEXT, address TEXT, ssh_port INTEGER, jump_via TEXT)")
        self.db.commit()
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.execute("INSERT INTO servers VALUES ('node', 'root', '203.0.113.10', 22, NULL)")
        self.db.commit()
        self.mmdb = b"x" * 1_100_000 + b"MaxMind.com"
        (self.root / "fixture.gz").write_bytes(gzip.compress(self.mmdb))
        (self.root / "ready").mkdir()
        ssh = self.root / "ssh"
        ssh.write_text(
            '#!/bin/bash\nset -eu\n'
            'echo "$*" >> "$TEST_ROOT/ssh.log"\n'
            'if [ "${TEST_BLOCK:-0}" = 1 ]; then\n'
            '  touch "$TEST_ROOT/ready/$PPID"\n'
            '  for ((i=0; i<500; i++)); do\n'
            '    [ ! -e "$TEST_ROOT/release" ] || break\n'
            '    sleep 0.01\n'
            '  done\n'
            '  [ -e "$TEST_ROOT/release" ] || exit 1\n'
            'fi\n'
            'cat "$TEST_ROOT/fixture.gz"\n'
        )
        ssh.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        TEST_ROOT=str(self.root), VPNCTLD_INV_DB=str(self.root / "inv.db"),
                        VPNCTLD_GEOIP_DIR=str(self.root / "geoip"))

    def test_live_wal_server_is_visible_to_node_selection(self):
        result = subprocess.run(["bash", str(SCRIPT)], env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("root@203.0.113.10", (self.root / "ssh.log").read_text())
        self.assertEqual((self.root / "geoip/GeoLite2-City.mmdb").read_bytes(), self.mmdb)

    def test_concurrent_updaters_use_distinct_partial_files(self):
        env = dict(self.env, TEST_BLOCK="1")
        children = [subprocess.Popen(["bash", str(SCRIPT)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            deadline = time.monotonic() + 5
            while len(list((self.root / "ready").iterdir())) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(list((self.root / "ready").iterdir())), 2)
            self.assertEqual(len(list((self.root / "geoip").glob("*.partial.gz"))), 2)
        finally:
            (self.root / "release").touch()
            results = [child.communicate(timeout=15) for child in children]
        for child, (_, stderr) in zip(children, results):
            self.assertEqual(child.returncode, 0, stderr.decode())
        for name in ["GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"]:
            self.assertEqual((self.root / "geoip" / name).read_bytes(), self.mmdb)
        self.assertFalse(list((self.root / "geoip").glob("*.partial*")))


if __name__ == "__main__":
    unittest.main()
