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

    def test_interrupted_retirement_preserves_latest_and_recovers_on_restart(self):
        for generation in range(1, 5):
            self.create(generation)
        old_versions = set((self.store.credential_root / "versions").iterdir())
        with mock.patch.object(replica.shutil, "rmtree", side_effect=OSError("fixture interrupted prune")):
            with self.assertRaises(replica.SnapshotError):
                self.store.prune(4)
        self.store.verify(4, 100, 0)
        self.store.verify(3, 100, 0)
        restarted = replica.SnapshotStore(self.store.root, "fixture-build", 1)
        restarted.prune(4)
        self.assertEqual({p.name for p in restarted.root.iterdir() if p.name.isdecimal()}, {"3", "4"})
        self.assertTrue(old_versions.issubset(set((restarted.credential_root / "versions").iterdir())))

    def test_prune_does_not_remove_a_newer_generation_awaiting_publication(self):
        for generation in range(1, 5):
            self.create(generation)
        self.store.prune(3)
        self.store.verify(4, 100, 0)
        self.store.prune(4)
        self.assertEqual({p.name for p in self.store.root.iterdir() if p.name.isdecimal()}, {"3", "4"})

    def test_failed_unpublished_cycles_remain_bounded_after_credential_retention(self):
        self.create()
        for generation in range(2, 12):
            self.store._retire_unpublished(1)
            self.create(generation)
            self.assertEqual(len([p for p in self.store.root.iterdir() if p.name.isdecimal()]), 2)
        self.store._retire_unpublished(1)
        self.store.verify(1, 100, 0)
        self.assertEqual(len(list((self.store.credential_root / "versions").iterdir())), 1)

    def test_install_retains_divergent_database_credentials_and_full_identity(self):
        self.create()
        self.database.execute("CREATE TABLE future_credentials(token TEXT,private_key BLOB)")
        self.database.execute("INSERT INTO future_credentials VALUES(?,?)",
                              ("fixture-divergent-token", b"fixture-divergent-private-key"))
        self.database.commit()
        self.identities["environment"].write_bytes(b"FIXTURE_DIVERGENT_ENV=retained\n")
        self.database.close()
        self.store.install(1, self.source, self.identities, 100, 0)
        recovered = []
        environments = []
        for version in (self.store.credential_root / "versions").iterdir():
            environments.append((version / "environment").read_bytes())
            with closing(sqlite3.connect(":memory:")) as restored:
                restored.executescript((version / "database.sql").read_text())
                if restored.execute("SELECT 1 FROM sqlite_schema WHERE name='future_credentials'").fetchone():
                    recovered.extend(restored.execute("SELECT token,private_key FROM future_credentials"))
        self.assertIn(("fixture-divergent-token", b"fixture-divergent-private-key"), recovered)
        self.assertIn(b"FIXTURE_DIVERGENT_ENV=retained\n", environments)

    def test_install_retains_generated_credentials_and_sqlite_sequence(self):
        self.create()
        self.database.executescript("CREATE TABLE generated_credentials(base TEXT,token TEXT GENERATED ALWAYS AS (base || '-derived-token') STORED);"
                                    "INSERT INTO generated_credentials(base) VALUES('fixture');"
                                    "CREATE TABLE credential_sequence(id INTEGER PRIMARY KEY AUTOINCREMENT,secret TEXT);"
                                    "INSERT INTO credential_sequence(id,secret) VALUES(9000,'fixture-removed-secret');"
                                    "DELETE FROM credential_sequence;")
        self.database.commit()
        self.database.close()
        self.store.install(1, self.source, self.identities, 100, 0)
        recovered = []
        for version in (self.store.credential_root / "versions").iterdir():
            with closing(sqlite3.connect(":memory:")) as restored:
                restored.executescript((version / "database.sql").read_text())
                if restored.execute("SELECT 1 FROM sqlite_schema WHERE name='generated_credentials'").fetchone():
                    recovered.extend(restored.execute("SELECT token FROM generated_credentials"))
                    self.assertEqual(restored.execute("SELECT seq FROM sqlite_sequence WHERE name='credential_sequence'").fetchone(), (9000,))
        self.assertIn(("fixture-derived-token",), recovered)

    def test_install_checks_capacity_on_the_destination_filesystem(self):
        self.create()
        with tempfile.TemporaryDirectory(prefix="vpnctl-ha-destination-", dir="/dev/shm") as destination:
            target = Path(destination) / "database.db"
            target.write_bytes(b"fixture-old-destination")
            targets = {name: Path(destination) / name for name in self.identities}
            usage = replica.shutil.disk_usage(self.store.root)
            def capacity(path):
                if Path(path).is_relative_to(Path(destination)):
                    return usage._replace(free=self.store.reserve_bytes)
                return usage
            with mock.patch.object(replica.shutil, "disk_usage", side_effect=capacity):
                with self.assertRaisesRegex(replica.SnapshotError, "reserve"):
                    self.store.install(1, target, targets, 100, 0)
            self.assertEqual(target.read_bytes(), b"fixture-old-destination")
            self.assertFalse(any(Path(destination).glob(".vpnctl-ha-*")))

    def test_failed_backup_retains_complete_raw_wal_recovery_set(self):
        self.create()
        self.database.execute("CREATE TABLE wal_credentials(token TEXT)")
        self.database.execute("INSERT INTO wal_credentials VALUES('fixture-wal-only-token')")
        self.database.commit()
        self.assertTrue(Path(str(self.source) + "-wal").exists())
        with mock.patch.object(self.store, "_backup", side_effect=sqlite3.OperationalError("fixture backup failure")):
            self.store.install(1, self.source, self.identities, 100, 0)
        recovered = []
        recovery = self.root / "raw-recovery"
        recovery.mkdir()
        for version in (self.store.credential_root / "versions").iterdir():
            if not (version / "database.raw").exists():
                continue
            shutil = replica.shutil
            target = recovery / "restored.db"
            shutil.copyfile(version / "database.raw", target)
            for logical, suffix in (("db_wal", "-wal"), ("db_shm", "-shm"), ("db_journal", "-journal")):
                if (version / logical).exists():
                    shutil.copyfile(version / logical, Path(str(target) + suffix))
            with closing(sqlite3.connect(target)) as restored:
                recovered.extend(restored.execute("SELECT token FROM wal_credentials"))
        self.assertIn(("fixture-wal-only-token",), recovered)

    def test_corrupt_destination_data_pages_are_retained_before_recovery(self):
        self.create()
        self.database.execute("CREATE TABLE corrupt_credentials(secret TEXT)")
        self.database.execute("INSERT INTO corrupt_credentials VALUES('fixture-corrupt-page-secret')")
        self.database.commit()
        page = self.database.execute("SELECT rootpage FROM sqlite_schema WHERE name='corrupt_credentials'").fetchone()[0]
        page_size = self.database.execute("PRAGMA page_size").fetchone()[0]
        self.database.close()
        with self.source.open("r+b") as source:
            source.seek((page - 1) * page_size)
            source.write(b"\0" * 16)
        original = self.source.read_bytes()
        self.assertIn(b"fixture-corrupt-page-secret", original)
        self.store.install(1, self.source, self.identities, 100, 0)
        retained = [(version / "database.raw").read_bytes()
                    for version in (self.store.credential_root / "versions").iterdir()
                    if (version / "database.raw").exists()]
        self.assertIn(original, retained)

    def test_receive_preserves_reserve_when_capacity_changes_during_transfer(self):
        self.create()
        receiver = replica.SnapshotStore(self.root / "receiver", "fixture-build", 1)
        description = self.store.describe(1)
        receiver.receive(description, lambda name,index,entry:self.store.read_chunk(1,name,index), 100, 0)
        self.identities["environment"].write_bytes(b"FIXTURE_CHANGED_CONFIG=yes\n")
        self.create(2)
        changed = self.store.describe(2)
        consumed = False
        usage = replica.shutil.disk_usage(receiver.root)
        def capacity(path):
            if consumed and Path(path).is_relative_to(receiver.root):
                return usage._replace(free=receiver.reserve_bytes)
            return usage
        def reader(name,index,entry):
            nonlocal consumed
            consumed = True
            return self.store.read_chunk(2,name,index)
        with mock.patch.object(replica.shutil, "disk_usage", side_effect=capacity):
            with self.assertRaisesRegex(replica.SnapshotError, "reserve"):
                receiver.receive(changed, reader, 100, 0)
        self.assertTrue(consumed)
        receiver.verify(1, 100, 0)
        self.assertFalse((receiver.root / "2").exists())

    def test_wal_writer_during_bulk_backup_does_not_restart_its_read_snapshot(self):
        self.database.execute("CREATE TABLE server_metrics(value BLOB)")
        self.database.execute("INSERT INTO server_metrics VALUES(zeroblob(4194304))")
        self.database.commit()
        connect = sqlite3.connect
        changed = False
        source_path = self.source
        class TrackedConnection(sqlite3.Connection):
            def backup(self, target, *, pages, progress, sleep):
                def concurrent_write(status, remaining, total):
                    nonlocal changed
                    if not changed:
                        with closing(connect(source_path)) as writer:
                            writer.execute("INSERT INTO parent VALUES(99)"); writer.commit()
                        changed = True
                    progress(status, remaining, total)
                return super().backup(target, pages=pages, progress=concurrent_write, sleep=sleep)
        def connection(path, **kwargs):
            if str(path).startswith(source_path.as_uri()):
                kwargs["factory"] = TrackedConnection
            return connect(path, **kwargs)
        with mock.patch.object(replica.sqlite3, "connect", side_effect=connection):
            self.create()
        self.assertTrue(changed)
        with closing(connect(self.store.root / "1/inv_db")) as backed_up:
            self.assertEqual(backed_up.execute("SELECT id FROM parent").fetchall(), [(1,)])
        self.assertEqual(self.database.execute("SELECT id FROM parent ORDER BY id").fetchall(), [(1,), (99,)])

    def test_archive_staging_is_included_in_capacity_reserve(self):
        self.create()
        self.database.execute("CREATE TABLE unknown_credentials(private_key BLOB)")
        self.database.execute("INSERT INTO unknown_credentials VALUES(?)", (b"fixture" * 20000,))
        self.database.commit()
        baseline = self.source.stat().st_size + Path(str(self.source) + "-wal").stat().st_size
        usage = replica.shutil.disk_usage(self.store.root)
        def capacity(path):
            if Path(path).is_relative_to(self.store.credential_root):
                return usage._replace(free=self.store.reserve_bytes + baseline)
            return usage
        with mock.patch.object(replica.shutil, "disk_usage", side_effect=capacity):
            with self.assertRaisesRegex(replica.SnapshotError, "reserve"):
                self.create(2)
        self.store.verify(1, 100, 0)
        self.assertFalse((self.store.root / "2").exists())

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
