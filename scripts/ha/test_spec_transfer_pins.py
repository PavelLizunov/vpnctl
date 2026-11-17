"""Independent transfer-pin tests using only the documented public APIs."""

import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
from replica import SnapshotStore  # noqa: E402
from transfer_pins import TransferPins  # noqa: E402


class Clock:
    def __init__(self):
        self.seconds = 1000.0

    def __call__(self):
        return self.seconds


class TransferPinsSpec(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpnctl-spec-pins-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store_root = self.root / "snapshots"
        self.pin_root = self.store_root / ".transfers"
        self.archive = self.root / "credentials"
        self.clock = Clock()
        self.store = SnapshotStore(
            self.store_root,
            "spec-build",
            1,
            credential_root=self.archive,
            reserve_bytes=0,
            keep_generations=2,
        )
        source = self.root / "source.db"
        with closing(sqlite3.connect(source)) as db, db:
            db.execute(
                "CREATE TABLE _sqlx_migrations("
                "version INTEGER PRIMARY KEY,success INTEGER,checksum BLOB)"
            )
            db.execute(
                "INSERT INTO _sqlx_migrations VALUES(1,1,?)", (bytes(range(48)),)
            )
            db.execute("CREATE TABLE fixture_data(value TEXT)")
            db.execute("INSERT INTO fixture_data VALUES('generation-1')")
        identities = {}
        for name in ("deploy_key", "known_hosts", "worker_env"):
            path = self.root / name
            path.write_text(f"fixture-{name}\n")
            identities[name] = path
        for generation in (1, 2, 3):
            with closing(sqlite3.connect(source)) as db, db:
                db.execute(
                    "UPDATE fixture_data SET value=?", (f"generation-{generation}",)
                )
            self.store.create(source, identities, generation, 1000000)
        self.pins = self.new_pins()

    def new_pins(self, **overrides):
        options = {"ttl_seconds": 10, "clock": self.clock}
        options.update(overrides)
        return TransferPins(
            self.pin_root,
            self.store,
            ["controller-a", "controller-b"],
            **options,
        )

    def acquire(self, holder="controller-a", generation=1):
        result = self.pins.acquire(holder, generation)
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result["pin"], str)
        self.assertTrue(result["pin"])
        self.assertIsInstance(result["description"], dict)
        return result

    def first_chunk(self, result):
        for name, entries in result["description"]["chunks"].items():
            if entries:
                return name, 0, entries[0]
        self.fail("a verified SQLite generation must have at least one chunk")

    def chunk(self, result, holder="controller-a", generation=1):
        name, index, entry = self.first_chunk(result)
        raw = self.pins.chunk(holder, result["pin"], generation, name, index)
        self.assertIsInstance(raw, bytes)
        self.assertEqual(len(raw), entry["size_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
        return raw

    def assert_rejected_chunk(self, result, holder="controller-a", generation=1):
        with self.assertRaises(Exception):
            self.chunk(result, holder, generation)

    @staticmethod
    def file_bytes(root):
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    @staticmethod
    def inodes(root):
        return {
            (path.stat().st_dev, path.stat().st_ino)
            for path in root.rglob("*")
            if path.is_file()
        }

    def test_old_generation_chunks_survive_numeric_prune(self):
        result = self.acquire()
        self.assertEqual(result["description"], self.store.describe(1))
        expected = {}
        for name, entries in result["description"]["chunks"].items():
            for index, entry in enumerate(entries):
                expected[name, index] = self.store.read_chunk(1, name, index)
                self.assertLessEqual(entry["size_bytes"], 1048576)
        self.store.prune(3)
        self.assertFalse((self.store_root / "1").exists())
        self.assertTrue((self.store_root / "2").is_dir())
        self.assertTrue((self.store_root / "3").is_dir())
        for (name, index), raw in expected.items():
            self.assertEqual(
                self.pins.chunk("controller-a", result["pin"], 1, name, index),
                raw,
            )
        self.assertEqual(result["description"]["manifest"]["created_at_ms"], 1000000)

    def test_replacement_has_one_live_token_and_releases_old_links(self):
        old = self.acquire()
        first_inodes = self.inodes(self.store_root / "1")
        second_inodes = self.inodes(self.store_root / "2")
        old_unique = first_inodes - second_inodes
        self.assertTrue(old_unique)
        self.assertTrue(self.inodes(self.pin_root) & old_unique)
        replacement = self.acquire(generation=2)
        self.assertNotEqual(old["pin"], replacement["pin"])
        self.assert_rejected_chunk(old)
        self.chunk(replacement, generation=2)
        self.assertFalse(self.inodes(self.pin_root) & old_unique)
        self.pins.release("controller-a", old["pin"])
        self.chunk(replacement, generation=2)

    def test_other_holder_survives_independent_replacement(self):
        first = self.acquire("controller-a", 1)
        other = self.acquire("controller-b", 1)
        self.assertNotEqual(first["pin"], other["pin"])
        self.acquire("controller-a", 3)
        self.assert_rejected_chunk(first)
        self.chunk(other, "controller-b", 1)

    def test_cross_holder_token_cannot_read_or_release(self):
        result = self.acquire()
        self.assert_rejected_chunk(result, "controller-b")
        self.assert_rejected_chunk(result, "unconfigured")
        try:
            self.pins.release("controller-b", result["pin"])
        except Exception:
            pass
        self.chunk(result)
        with self.assertRaises(Exception):
            self.pins.acquire("unconfigured", 1)

    def test_wrong_generation_unknown_token_and_paths_fail_closed(self):
        result = self.acquire()
        name, index, _ = self.first_chunk(result)
        invalid = (
            (result["pin"], 2, name, index),
            ("unknown-token", 1, name, index),
            (result["pin"], "../1", name, index),
            (result["pin"], 1, "../inv_db", index),
            (result["pin"], 1, "/etc/passwd", index),
            (result["pin"], 1, name, -1),
            (result["pin"], 1, name, 999999),
        )
        for token, generation, logical_name, chunk_index in invalid:
            with self.subTest(
                token=token,
                generation=generation,
                logical_name=logical_name,
                chunk_index=chunk_index,
            ):
                with self.assertRaises(Exception):
                    self.pins.chunk(
                        "controller-a", token, generation, logical_name, chunk_index
                    )
        self.chunk(result)

    def test_exact_expiry_rejects_chunks_without_renewal_by_reads(self):
        result = self.acquire()
        self.clock.seconds = 1009.999
        self.chunk(result)
        self.clock.seconds = 1010.0
        self.assert_rejected_chunk(result)
        self.pins.reap()
        self.assert_rejected_chunk(result)

    def test_reap_and_idempotent_release_preserve_credential_archive(self):
        result = self.acquire()
        generation_inodes = self.inodes(self.store_root / "1")
        self.store.prune(3)
        archive = self.file_bytes(self.archive)
        self.assertTrue(archive)
        self.clock.seconds = 1010.0
        self.pins.reap()
        self.pins.reap()
        self.pins.release("controller-a", result["pin"])
        self.pins.release("controller-a", result["pin"])
        self.assertFalse(self.inodes(self.pin_root) & generation_inodes)
        self.assertEqual(self.file_bytes(self.archive), archive)

    def test_live_release_removes_pin_without_removing_archived_credentials(self):
        result = self.acquire()
        generation_inodes = self.inodes(self.store_root / "1")
        self.store.prune(3)
        archive = self.file_bytes(self.archive)
        self.pins.release("controller-a", result["pin"])
        self.pins.release("controller-a", result["pin"])
        self.assert_rejected_chunk(result)
        self.assertFalse(self.inodes(self.pin_root) & generation_inodes)
        self.assertEqual(self.file_bytes(self.archive), archive)

    def test_restart_invalidates_tokens_and_removes_duplicate_links(self):
        result = self.acquire()
        self.store.prune(3)
        archive = self.file_bytes(self.archive)
        pinned_inodes = self.inodes(self.pin_root)
        self.assertTrue(pinned_inodes)
        self.pins = self.new_pins()
        self.assert_rejected_chunk(result)
        self.assertFalse(self.inodes(self.pin_root) & pinned_inodes)
        self.assertEqual(self.file_bytes(self.archive), archive)
        fresh = self.acquire(generation=3)
        self.chunk(fresh, generation=3)

    def test_interrupted_hardlink_creation_returns_no_token(self):
        real_link = os.link
        linked = 0

        def interrupted_link(*args, **kwargs):
            nonlocal linked
            linked += 1
            if linked == 2:
                raise OSError("spec interrupted pin creation")
            return real_link(*args, **kwargs)

        with mock.patch.object(os, "link", interrupted_link):
            with self.assertRaises(Exception):
                self.pins.acquire("controller-a", 1)
        self.assertGreaterEqual(linked, 2)
        self.pins.reap()
        result = self.acquire()
        self.chunk(result)

    def test_rejects_unbounded_ttl_and_unsafe_holders(self):
        for ttl in (0, -1, 3600.001, float("inf"), float("-inf"), float("nan")):
            with self.subTest(ttl=ttl):
                with self.assertRaises(Exception):
                    self.new_pins(ttl_seconds=ttl)
        for holders in ([], ["../controller-a"], ["/controller-a"], ["."], ["a/b"]):
            with self.subTest(holders=holders):
                with self.assertRaises(Exception):
                    TransferPins(
                        self.pin_root,
                        self.store,
                        holders,
                        ttl_seconds=10,
                        clock=self.clock,
                    )

    def test_unsafe_roots_fail_before_deleting_existing_data(self):
        result = self.acquire()
        archive = self.file_bytes(self.archive)
        generation = self.file_bytes(self.store_root / "1")
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("keep")
        for root in (self.store_root, self.store_root / "1", self.archive, outside):
            with self.subTest(root=root):
                with self.assertRaises(Exception):
                    TransferPins(
                        root,
                        self.store,
                        ["controller-a", "controller-b"],
                        ttl_seconds=10,
                        clock=self.clock,
                    )
        self.assertEqual(self.file_bytes(self.archive), archive)
        self.assertEqual(self.file_bytes(self.store_root / "1"), generation)
        self.assertEqual(sentinel.read_text(), "keep")
        self.chunk(result)


if __name__ == "__main__":
    unittest.main()
