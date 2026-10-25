#!/usr/bin/env python3
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "vpnctl-restore.sh"


@unittest.skipUnless(shutil.which("sqlite3") and shutil.which("bash"), "requires sqlite3 and bash")
class RestoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in {
            "date": "printf '2026-10-25T00-00-00Z\\n'\n",
            "age": 'cp -- "$6" "$5"\n',
            "zstd": 'cp -- "$5" "$4"\n',
        }.items():
            path = self.bin / name
            path.write_text("#!/bin/bash\nset -eu\n" + body)
            path.chmod(0o755)
        self.key = self.root / "key"
        self.key.touch()
        self.archive = self.root / "archive.tar"
        self.database = self.root / "source.db"
        with sqlite3.connect(self.database) as db:
            for name in ["users", "servers", "grants", "sub_access_log", "_sqlx_migrations"]:
                db.execute(f"CREATE TABLE {name} (id INTEGER)")
        self.env = dict(os.environ, TMPDIR=str(self.root),
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"])

    def make_archive(self, path="vpnctl-snap/inv.db", symlink=False):
        with tarfile.open(self.archive, "w") as archive:
            if symlink:
                entry = tarfile.TarInfo(path)
                entry.type = tarfile.SYMTYPE
                entry.linkname = str(self.database)
                archive.addfile(entry)
            else:
                archive.add(self.database, arcname=path)

    def run_restore(self, archive=None, key=None, cwd=None):
        return subprocess.run(["bash", str(SCRIPT), str(archive or self.archive), str(key or self.key)],
                              env=self.env, capture_output=True, text=True, timeout=10, cwd=cwd)

    def test_restore_uses_new_private_directory_and_expected_inventory(self):
        self.make_archive()
        attacker = self.root / "vpnctl-restore-2026-10-25T00-00-00Z"
        attacker.mkdir(mode=0o777)
        attacker.chmod(0o777)
        result = self.run_restore()
        self.assertEqual(result.returncode, 0, result.stderr)
        scratch = next(line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
                       if line.strip().startswith("scratch:"))
        work = Path(scratch)
        self.assertNotEqual(work, attacker)
        self.assertEqual(work.stat().st_mode & 0o777, 0o700)
        self.assertTrue((work / "vpnctl-snap/inv.db").is_file())
        self.assertEqual(list(attacker.iterdir()), [])

    def test_restore_accepts_relative_archive_and_key_paths(self):
        self.make_archive()
        result = self.run_restore(self.archive.name, self.key.name, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_restore_rejects_inventory_at_an_unexpected_path(self):
        self.make_archive("decoy/inv.db")
        result = self.run_restore()
        self.assertEqual(result.returncode, 67, result.stderr)

    def test_restore_rejects_symlinked_inventory(self):
        self.make_archive(symlink=True)
        result = self.run_restore()
        self.assertEqual(result.returncode, 67, result.stderr)


if __name__ == "__main__":
    unittest.main()
