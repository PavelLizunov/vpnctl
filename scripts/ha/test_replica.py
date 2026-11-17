"""Isolated replica tests; all keys/config bytes are synthetic fixtures."""

import base64
from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

import replica


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.db"
        self.database = sqlite3.connect(self.source)
        self.addCleanup(self.database.close)
        self.database.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE _sqlx_migrations (
                version INTEGER PRIMARY KEY, success BOOLEAN NOT NULL,
                checksum BLOB NOT NULL
            );
            CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (id INTEGER REFERENCES parent(id));
            INSERT INTO parent VALUES (1);
            INSERT INTO child VALUES (1);
        """)
        self.database.execute("INSERT INTO _sqlx_migrations VALUES (1, 1, ?)",
                              (bytes(range(48)),))
        self.database.commit()
        self.identities = {}
        for name, content in {"deploy_key": b"fixture-key\x00\n", "known_hosts": b"fixture-host\n",
                              "environment": b"TEST_ONLY=fixture\n"}.items():
            path = self.root / name
            path.write_bytes(content)
            self.identities[name] = path
        self.store = replica.SnapshotStore(self.root / "store", "fixture-build", 1)

    def create(self, generation=1):
        return self.store.create(self.source, self.identities, generation, 100)

    def rewrite_manifest(self, name, data):
        directory = self.store.root / "1"
        (directory / name).write_bytes(data)
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][name] = {"size_bytes": len(data),
                                   "sha256": hashlib.sha256(data).hexdigest()}
        manifest["identity_sha256"] = hashlib.sha256(replica._json_bytes(
            manifest["files"])).hexdigest()
        manifest_path.write_bytes(replica._json_bytes(manifest))

    def test_online_backup_includes_committed_wal_and_remains_immutable(self):
        self.database.execute("INSERT INTO parent VALUES (2)")
        self.database.commit()
        manifest = self.create()
        migration_bytes = f"1:{bytes(range(48)).hex()}\n".encode("ascii")
        self.assertEqual(manifest["migration_sha256"],
                         hashlib.sha256(migration_bytes).hexdigest())
        self.database.execute("INSERT INTO parent VALUES (3)")
        self.database.commit()
        with closing(sqlite3.connect(self.store.root / "1" / "inv_db")) as database:
            self.assertEqual(database.execute("SELECT id FROM parent ORDER BY id").fetchall(),
                             [(1,), (2,)])
        self.assertEqual(self.store.verify(1, 200, 100), manifest)
        self.assertEqual(manifest["created_at_ms"], 100)
        self.assertEqual(stat.S_IMODE(self.store.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.store.root / "1").stat().st_mode), 0o700)
        for file in (self.store.root / "1").iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    def test_age_boundary_and_future_creation_rejected(self):
        self.create()
        self.store.verify(1, 200, 100)
        for now, age in [(201, 100), (99, 100), (100, -1), (True, 100)]:
            with self.subTest(now=now, age=age), self.assertRaises(replica.SnapshotError):
                self.store.verify(1, now, age)

    def test_all_identity_and_database_bytes_contribute_to_digest(self):
        original = self.create()
        self.identities["environment"].write_bytes(b"TEST_ONLY=different\n")
        changed_identity = self.create(2)
        self.database.execute("INSERT INTO parent VALUES (2)")
        self.database.commit()
        changed_database = self.create(3)
        self.assertNotEqual(original["identity_sha256"], changed_identity["identity_sha256"])
        self.assertNotEqual(changed_identity["identity_sha256"],
                            changed_database["identity_sha256"])

    def test_generation_is_positive_integer_and_cannot_be_overwritten(self):
        original = self.create()
        with self.assertRaises(replica.SnapshotError):
            self.create()
        self.assertEqual(self.store.verify(1, 100, 0), original)
        for value in [0, -1, True, "../outside"]:
            with self.subTest(value=value), self.assertRaises(replica.SnapshotError):
                self.create(value)

    def test_tampering_and_extra_files_fail_verification(self):
        self.create()
        directory = self.store.root / "1"
        extra = directory / "extra"
        extra.write_bytes(b"unadvertised")
        with self.assertRaises(replica.SnapshotError):
            self.store.verify(1, 100, 0)
        extra.unlink()
        (directory / "environment").write_bytes(b"tampered")
        with self.assertRaises(replica.SnapshotError):
            self.store.verify(1, 100, 0)

    def test_roundtrip_import_verifies_and_never_refreshes_time(self):
        manifest = self.create()
        record = self.store.export(1)
        imported = replica.SnapshotStore(self.root / "imported", "fixture-build", 1)
        self.assertEqual(imported.import_snapshot(record, 150, 100), manifest)
        self.assertEqual(imported.export(1), record)
        with self.assertRaises(replica.SnapshotError):
            imported.import_snapshot(record, 150, 100)
        with self.assertRaises(replica.SnapshotError):
            imported.verify(1, 201, 100)

    def test_import_rejects_path_names_extra_files_hash_and_build_mismatch(self):
        self.create()
        record = self.store.export(1)
        for mutation in ["extra", "path", "hash", "build", "schema", "future", "nonascii"]:
            candidate = copy.deepcopy(record)
            if mutation == "extra":
                candidate["files"]["extra"] = ""
            elif mutation == "path":
                candidate["manifest"]["files"]["../escape"] = candidate["manifest"]["files"].pop(
                    "environment")
            elif mutation == "hash":
                candidate["files"]["environment"] = base64.b64encode(b"X" * len(
                    self.identities["environment"].read_bytes())).decode("ascii")
            elif mutation == "build":
                candidate["manifest"]["build"] = "other-build"
            elif mutation == "schema":
                candidate["manifest"]["schema_version"] = 2
            elif mutation == "future":
                candidate["manifest"]["created_at_ms"] = 101
            else:
                candidate["files"]["environment"] = "\u00e9" * len(candidate["files"]["environment"])
            destination = replica.SnapshotStore(self.root / mutation, "fixture-build", 1)
            with self.subTest(mutation=mutation), self.assertRaises(replica.SnapshotError):
                destination.import_snapshot(candidate, 100, 0)
            self.assertFalse((destination.root / "1").exists())

    def test_bounded_create_import_and_export_reject_before_large_decode(self):
        with mock.patch.object(replica, "MAX_SNAPSHOT_BYTES", 128):
            with self.assertRaises(replica.SnapshotError):
                self.create()
        self.assertFalse((self.store.root / "1").exists())
        self.create()
        record = self.store.export(1)
        destination = replica.SnapshotStore(self.root / "imported", "fixture-build", 1)
        with mock.patch.object(replica, "MAX_SNAPSHOT_BYTES", 128), mock.patch.object(
                replica.base64, "b64decode", side_effect=AssertionError("must not decode")):
            with self.assertRaises(replica.SnapshotError):
                destination.import_snapshot(record, 100, 0)
            with self.assertRaises(replica.SnapshotError):
                self.store.export(1)

    def test_database_integrity_and_foreign_keys_are_independently_checked(self):
        self.create()
        snapshot = self.store.root / "1" / "inv_db"
        with closing(sqlite3.connect(snapshot)) as database:
            database.execute("INSERT INTO child VALUES (99)")
            database.commit()
        self.rewrite_manifest("inv_db", snapshot.read_bytes())
        with self.assertRaisesRegex(replica.SnapshotError, "foreign key"):
            self.store.verify(1, 100, 0)
        self.rewrite_manifest("inv_db", b"not a database")
        with self.assertRaises(replica.SnapshotError):
            self.store.verify(1, 100, 0)

    def test_failed_missing_and_wrong_migrations_are_rejected(self):
        for statement in ["UPDATE _sqlx_migrations SET success=0",
                          "DELETE FROM _sqlx_migrations",
                          "UPDATE _sqlx_migrations SET version=2",
                          "UPDATE _sqlx_migrations SET checksum=x'00'"]:
            with self.subTest(statement=statement):
                self.database.execute("DELETE FROM _sqlx_migrations")
                self.database.execute("INSERT INTO _sqlx_migrations VALUES (1, 1, ?)",
                                      (bytes(range(48)),))
                self.database.execute(statement)
                self.database.commit()
                with self.assertRaises(replica.SnapshotError):
                    self.create()
                self.assertFalse((self.store.root / "1").exists())

    def test_reserved_names_source_and_generation_symlinks_are_rejected(self):
        for name in ["../escape", "inv_db", "manifest", "a/b", "Upper", "manifest.json"]:
            with self.subTest(name=name), self.assertRaises(replica.SnapshotError):
                self.store.create(self.source, {name: self.source}, 1, 100)
        link = self.root / "link"
        link.symlink_to(self.identities["environment"])
        with self.assertRaises(replica.SnapshotError):
            self.store.create(self.source, {"environment": link}, 1, 100)
        link.unlink()
        link.symlink_to(self.source)
        with self.assertRaises(replica.SnapshotError):
            self.store.create(link, {}, 1, 100)
        self.create()
        (self.store.root / "2").symlink_to(self.store.root / "1", target_is_directory=True)
        with self.assertRaises(replica.SnapshotError):
            self.store.verify(2, 100, 0)

    def test_install_stages_exact_files_removes_stale_wal_and_fsyncs(self):
        expected = self.create()
        target = self.root / "installed" / "inv.db"
        targets = {name: target.parent / name for name in self.identities}
        target.parent.mkdir()
        target.write_bytes(b"old-database")
        for suffix in ["-wal", "-shm", "-journal"]:
            Path(str(target) + suffix).write_bytes(b"stale")
        with mock.patch.object(replica.os, "fsync", wraps=os.fsync) as fsync:
            self.assertEqual(self.store.install(1, target, targets, 150, 100), expected)
            self.assertGreaterEqual(fsync.call_count, 8)
        with closing(sqlite3.connect(target)) as database:
            self.assertEqual(database.execute("PRAGMA integrity_check").fetchone(), ("ok",))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        for name, destination in targets.items():
            self.assertEqual(destination.read_bytes(), self.identities[name].read_bytes())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        for suffix in ["-wal", "-shm", "-journal"]:
            self.assertFalse(Path(str(target) + suffix).exists())

    def test_install_refuses_missing_aliasing_and_symlink_targets(self):
        self.create()
        target = self.root / "installed.db"
        targets = {name: self.root / ("installed-" + name) for name in self.identities}
        with self.assertRaises(replica.SnapshotError):
            self.store.install(1, target, {}, 100, 0)
        targets["environment"] = target
        with self.assertRaises(replica.SnapshotError):
            self.store.install(1, target, targets, 100, 0)
        targets["environment"] = self.root / "installed-environment"
        target.symlink_to(self.source)
        with self.assertRaises(replica.SnapshotError):
            self.store.install(1, target, targets, 100, 0)
        target.unlink()
        with self.assertRaises(replica.SnapshotError):
            self.store.install(1, self.store.root / "1" / "inv_db", targets, 100, 0)
        self.assertFalse(any(self.root.glob(".vpnctl-ha-*")))

    def test_install_copy_failure_changes_no_destination(self):
        self.create()
        target = self.root / "installed.db"
        target.write_bytes(b"original-db")
        targets = {name: self.root / ("installed-" + name) for name in self.identities}
        for file in targets.values():
            file.write_bytes(b"original-identity")
        original_copy = replica._copy_new
        calls = 0

        def failing_copy(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic copy failure")
            return original_copy(*args, **kwargs)

        with mock.patch.object(replica, "_copy_new", side_effect=failing_copy):
            with self.assertRaises(replica.SnapshotError):
                self.store.install(1, target, targets, 100, 0)
        self.assertEqual(target.read_bytes(), b"original-db")
        for file in targets.values():
            self.assertEqual(file.read_bytes(), b"original-identity")
        self.assertFalse(any(self.root.glob(".vpnctl-ha-*")))


if __name__ == "__main__":
    unittest.main()
