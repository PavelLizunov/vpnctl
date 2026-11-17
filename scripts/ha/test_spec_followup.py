"""Independent tests written from controller-ha.md, without implementation access.

Run with ``python3 -m unittest discover -s scripts/ha -p test_spec_followup.py``.
The fixture contains deliberately fake credentials and no live inventory.
"""

from __future__ import annotations

from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zlib


sys.path.insert(0, str(Path(__file__).resolve().parent))
from replica import SnapshotStore  # noqa: E402
from common import decode_chunk, encode_chunk  # noqa: E402


MIB = 1024 * 1024
BUILD = "spec-only-build"
SCHEMA = 1
NOW = 100_000
MAX_AGE = 10_000
MIGRATION_CHECKSUM = bytes(range(48))


class SnapshotFollowupSpec(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpnctl-ha-spec-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base / "source.db"
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript(
                """
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMP NOT NULL,
                    success BOOLEAN NOT NULL,
                    checksum BLOB NOT NULL,
                    execution_time BIGINT NOT NULL
                );
                CREATE TABLE users (
                    uuid TEXT PRIMARY KEY,
                    token TEXT NOT NULL,
                    private_key TEXT NOT NULL
                );
                CREATE TABLE server_metrics (server_id TEXT, value TEXT);
                CREATE TABLE unknown_config (name TEXT PRIMARY KEY, value BLOB);
                """
            )
            db.execute(
                "INSERT INTO _sqlx_migrations VALUES (?, ?, ?, ?, ?, ?)",
                (1, "spec fixture", "2026-01-01 00:00:00", 1, MIGRATION_CHECKSUM, 1),
            )
        self.identity_paths = {
            name: self.base / (name + ".source")
            for name in ("deploy_key", "known_hosts", "env")
        }
        self.set_credentials("alpha")

    def set_credentials(self, version):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("DELETE FROM users")
            db.execute("DELETE FROM unknown_config")
            db.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                ("user-" + version, "token-" + version, "private-" + version),
            )
            db.execute(
                "INSERT INTO unknown_config VALUES (?, ?)",
                ("unrecognized-setting", ("configuration-" + version).encode()),
            )
        for name, path in self.identity_paths.items():
            path.write_bytes(("fake-spec-" + name + "-" + version + "\n").encode())

    def set_telemetry(self, value):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("DELETE FROM server_metrics")
            db.execute("INSERT INTO server_metrics VALUES (?, ?)", ("node", value))

    def make_large(self):
        # An incompressible transfer is unnecessary: raw chunks must be bounded
        # regardless of whether the HTTP adapter later compresses them.
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute(
                "INSERT INTO unknown_config VALUES (?, ?)",
                ("large-fixture", bytes(range(256)) * (MIB // 256 * 2 + 7)),
            )

    def store(self, label, **options):
        options.setdefault("credential_root", self.base / (label + "-credentials"))
        options.setdefault("reserve_bytes", 0)
        return SnapshotStore(self.base / label, BUILD, SCHEMA, **options)

    def create(self, store, generation):
        return store.create(self.db, self.identity_paths, generation, NOW)

    def description(self, large=False):
        if large:
            self.make_large()
        source = self.store("source")
        manifest = self.create(source, 1)
        description = source.describe(1)
        self.assertEqual(description["manifest"], manifest)
        return source, description

    @staticmethod
    def reader(source):
        return lambda name, index, entry: source.read_chunk(1, name, index)

    def assert_unpublished(self, store, generation=1):
        with self.assertRaises(Exception):
            store.verify(generation, NOW, MAX_AGE)

    def test_describe_and_raw_chunks_attest_the_exact_generation(self):
        source, description = self.description(large=True)
        chunks = description["chunks"]
        self.assertTrue(chunks)
        self.assertTrue(any(len(entries) >= 3 for entries in chunks.values()))
        for name, entries in chunks.items():
            self.assertRegex(name, r"^[a-z][a-z0-9_-]{0,63}$")
            for index, entry in enumerate(entries):
                self.assertIs(type(entry["size_bytes"]), int)
                self.assertGreater(entry["size_bytes"], 0)
                self.assertLessEqual(entry["size_bytes"], MIB)
                self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
                raw = source.read_chunk(1, name, index)
                self.assertIsInstance(raw, bytes)
                self.assertEqual(len(raw), entry["size_bytes"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
        self.assertEqual(source.verify(1, NOW + MAX_AGE, MAX_AGE), description["manifest"])
        with self.assertRaises(Exception):
            source.verify(1, NOW + MAX_AGE + 1, MAX_AGE)

    def test_read_chunk_rejects_invalid_names_and_indices(self):
        source, description = self.description()
        name, entries = next(iter(description["chunks"].items()))
        for invalid in ("../env", "/etc/passwd", "env/../../outside", "missing", "", "manifest"):
            with self.subTest(name=invalid), self.assertRaises(Exception):
                source.read_chunk(1, invalid, 0)
        for invalid in (-1, len(entries), 1.5, "0", None, True):
            with self.subTest(index=invalid), self.assertRaises(Exception):
                source.read_chunk(1, name, invalid)
        with self.assertRaises(Exception):
            source.describe(999)

    def test_read_chunk_detects_corruption_in_immutable_file(self):
        source, description = self.description()
        credential = self.identity_paths["deploy_key"].read_bytes()
        name = next(
            logical
            for logical, entries in description["chunks"].items()
            if b"".join(source.read_chunk(1, logical, i) for i in range(len(entries))) == credential
        )
        # Locate the generated bytes without coupling this spec test to the
        # operational generation directory's private layout.
        candidates = [
            path
            for path in (self.base / "source").rglob("*")
            if path.is_file() and path.read_bytes() == credential
        ]
        self.assertEqual(len(candidates), 1)
        candidates[0].write_bytes(b"X" + credential[1:])
        with self.assertRaises(Exception):
            source.read_chunk(1, name, 0)

    def test_receive_round_trip_and_retained_chunk_reuse(self):
        source, description = self.description(large=True)
        destination = self.store("destination")
        calls = []

        def reader(name, index, entry):
            calls.append((name, index))
            return source.read_chunk(1, name, index)

        destination.receive(description, reader, NOW, MAX_AGE)
        self.assertTrue(calls)
        self.assertEqual(destination.describe(1), description)
        source.create(self.db, self.identity_paths, 2, NOW)
        second = source.describe(2)

        def never_download(name, index, entry):
            self.fail("unchanged retained chunks must be reused locally")

        destination.receive(second, never_download, NOW, MAX_AGE)
        self.assertEqual(destination.describe(2), second)

    def test_interrupted_receive_never_publishes_and_can_be_restarted(self):
        source, description = self.description(large=True)
        destination = self.store("destination")
        calls = []

        def interrupted(name, index, entry):
            calls.append((name, index))
            if len(calls) == 2:
                raise OSError("spec fixture interrupted transfer")
            return source.read_chunk(1, name, index)

        with self.assertRaises(Exception):
            destination.receive(description, interrupted, NOW, MAX_AGE)
        self.assert_unpublished(destination)
        destination.receive(description, self.reader(source), NOW, MAX_AGE)
        self.assertEqual(destination.verify(1, NOW, MAX_AGE), description["manifest"])

    def test_receive_corrupt_short_oversized_and_nonbytes_chunks_never_publish(self):
        source, description = self.description()
        mutations = {
            "corrupt": lambda raw: bytes([raw[0] ^ 1]) + raw[1:],
            "short": lambda raw: raw[:-1],
            "oversized": lambda raw: b"x" * (MIB + 1),
            "nonbytes": lambda raw: "not raw bytes",
        }
        for label, mutate in mutations.items():
            with self.subTest(kind=label):
                destination = self.store("receive-" + label)

                def reader(name, index, entry):
                    return mutate(source.read_chunk(1, name, index))

                with self.assertRaises(Exception):
                    destination.receive(description, reader, NOW, MAX_AGE)
                self.assert_unpublished(destination)

    def test_receive_checks_full_hash_even_when_chunk_hash_matches(self):
        source, description = self.description()
        name = next(iter(description["chunks"]))
        raw = source.read_chunk(1, name, 0)
        changed = bytes([raw[0] ^ 1]) + raw[1:]
        plan = copy.deepcopy(description)
        plan["chunks"][name][0]["sha256"] = hashlib.sha256(changed).hexdigest()
        destination = self.store("changed-full-hash")

        def reader(logical, index, entry):
            if logical == name and index == 0:
                return changed
            return source.read_chunk(1, logical, index)

        with self.assertRaises(Exception):
            destination.receive(plan, reader, NOW, MAX_AGE)
        self.assert_unpublished(destination)

    def test_receive_rejects_malformed_chunk_plans_before_publication(self):
        source, description = self.description()
        name = next(iter(description["chunks"]))

        def bad_name(plan):
            plan["chunks"]["../outside"] = plan["chunks"].pop(name)

        def missing_file(plan):
            del plan["chunks"][name]

        def extra_file(plan):
            plan["chunks"]["unallocated_file"] = copy.deepcopy(plan["chunks"][name])

        def too_large(plan):
            plan["chunks"][name][0]["size_bytes"] = MIB + 1

        def wrong_size_type(plan):
            plan["chunks"][name][0]["size_bytes"] = "1"

        def bad_hash(plan):
            plan["chunks"][name][0]["sha256"] = "not-sha256"

        def bad_entries(plan):
            plan["chunks"][name] = {"0": plan["chunks"][name][0]}

        def excessive_total(plan):
            entry = {"size_bytes": MIB, "sha256": "0" * 64}
            plan["chunks"][name] = [entry] * (8 * 1024 + 1)

        for change in (bad_name, missing_file, extra_file, too_large, wrong_size_type, bad_hash, bad_entries, excessive_total):
            with self.subTest(kind=change.__name__):
                destination = self.store("plan-" + change.__name__)
                malformed = copy.deepcopy(description)
                change(malformed)
                with self.assertRaises(Exception):
                    destination.receive(malformed, self.reader(source), NOW, MAX_AGE)
                self.assert_unpublished(destination)
        self.assertFalse((self.base / "outside").exists())

    def test_receive_rejects_future_stale_wrong_build_and_wrong_schema(self):
        source, description = self.description()
        for label, now, build, schema in (
            ("future", NOW - 1, BUILD, SCHEMA),
            ("stale", NOW + MAX_AGE + 1, BUILD, SCHEMA),
            ("build", NOW, BUILD + "-different", SCHEMA),
            ("schema", NOW, BUILD, SCHEMA + 1),
        ):
            with self.subTest(kind=label):
                destination = SnapshotStore(
                    self.base / label,
                    build,
                    schema,
                    credential_root=self.base / (label + "-credentials"),
                    reserve_bytes=0,
                )
                with self.assertRaises(Exception):
                    destination.receive(description, self.reader(source), now, MAX_AGE)
                self.assert_unpublished(destination)

    def test_receive_never_replaces_an_existing_generation(self):
        source, description = self.description()
        destination = self.store("destination")
        destination.receive(description, self.reader(source), NOW, MAX_AGE)
        self.set_credentials("beta")
        changed_source = self.store("changed-source")
        self.create(changed_source, 1)
        changed = changed_source.describe(1)
        try:
            destination.receive(changed, self.reader(changed_source), NOW, MAX_AGE)
        except Exception:
            pass
        self.assertEqual(destination.describe(1), description)

    def test_capacity_failure_preserves_verified_recovery_generation(self):
        source, description = self.description()
        destination = self.store("destination")
        destination.receive(description, self.reader(source), NOW, MAX_AGE)
        source.create(self.db, self.identity_paths, 2, NOW)
        free = shutil.disk_usage(self.base).free
        constrained = SnapshotStore(
            self.base / "destination",
            BUILD,
            SCHEMA,
            credential_root=self.base / "destination-credentials",
            reserve_bytes=free + MIB,
        )
        with self.assertRaises(Exception):
            constrained.receive(source.describe(2), lambda name, index, entry: source.read_chunk(2, name, index), NOW, MAX_AGE)
        self.assertEqual(destination.describe(1), description)
        self.assert_unpublished(destination, 2)
        with self.assertRaises(Exception):
            constrained.create(self.db, self.identity_paths, 3, NOW)
        self.assertEqual(destination.describe(1), description)
        self.assert_unpublished(destination, 3)

    def credential_versions(self, credential_root):
        versions_dir = credential_root / "versions"
        if not versions_dir.exists():
            return []
        return sorted(path for path in versions_dir.iterdir() if path.is_dir())

    def read_archive(self, version):
        self.assertRegex(version.name, r"^[0-9a-f]{64}$")
        self.assertTrue((version / "manifest.json").is_file())
        with closing(sqlite3.connect(":memory:")) as db, db:
            db.executescript((version / "database.sql").read_text())
            users = db.execute("SELECT uuid, token, private_key FROM users").fetchall()
            unknown = db.execute("SELECT name, value FROM unknown_config").fetchall()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM server_metrics").fetchone()[0], 0)
            migrations = db.execute("SELECT version, checksum FROM _sqlx_migrations").fetchall()
            self.assertEqual(migrations, [(1, MIGRATION_CHECKSUM)])
        identities = {name: (version / name).read_bytes() for name in self.identity_paths}
        return users, unknown, identities

    def test_prune_deduplicates_unchanged_credentials_and_retains_changed_deleted_values(self):
        credential_root = self.base / "archive"
        store = self.store("operational", credential_root=credential_root)
        self.set_telemetry("metric-one")
        self.create(store, 1)
        alpha_files = {name: path.read_bytes() for name, path in self.identity_paths.items()}
        self.set_telemetry("metric-two")
        self.create(store, 2)
        self.set_credentials("beta")
        self.create(store, 3)
        beta_files = {name: path.read_bytes() for name, path in self.identity_paths.items()}
        store.prune(3)
        self.assert_unpublished(store, 1)
        store.verify(2, NOW, MAX_AGE)
        store.verify(3, NOW, MAX_AGE)
        first_versions = self.credential_versions(credential_root)
        self.assertTrue(first_versions)
        immutable_bytes = {
            str(path.relative_to(credential_root)): path.read_bytes()
            for version in first_versions
            for path in version.rglob("*")
            if path.is_file()
        }
        self.set_telemetry("metric-three")
        self.create(store, 4)
        store.prune(4)
        self.assertEqual(self.credential_versions(credential_root), first_versions)
        self.assert_unpublished(store, 2)
        store.verify(3, NOW, MAX_AGE)
        store.verify(4, NOW, MAX_AGE)
        self.set_credentials("gamma")
        self.create(store, 5)
        self.create(store, 6)
        store.prune(6)
        self.assert_unpublished(store, 3)
        self.assert_unpublished(store, 4)
        store.verify(5, NOW, MAX_AGE)
        store.verify(6, NOW, MAX_AGE)
        versions = self.credential_versions(credential_root)
        restored = [self.read_archive(version) for version in versions]
        for label, files in (("alpha", alpha_files), ("beta", beta_files)):
            self.assertTrue(
                any(
                    users == [("user-" + label, "token-" + label, "private-" + label)]
                    and unknown == [("unrecognized-setting", ("configuration-" + label).encode())]
                    and identities == files
                    for users, unknown, identities in restored
                ),
                "changed/deleted " + label + " credentials must remain fully recoverable",
            )
        for relative, expected in immutable_bytes.items():
            self.assertEqual((credential_root / relative).read_bytes(), expected)
        index_text = (credential_root / "index.json").read_text()
        json.loads(index_text)
        for version in versions:
            self.assertIn(version.name, index_text)
        count = len(versions)
        store.prune(6)
        self.assertEqual(len(self.credential_versions(credential_root)), count)

    def test_prune_keeps_at_least_two_and_ignores_nonnumeric_directories(self):
        # Rejecting an unsafe retention setting and clamping it to two are both
        # valid ways to enforce the minimum promised by the public contract.
        try:
            store = self.store("operational", keep_generations=1)
        except (ValueError, RuntimeError):
            return
        self.create(store, 1)
        self.create(store, 2)
        self.create(store, 3)
        marker = self.base / "operational" / "operator-notes"
        marker.mkdir()
        (marker / "keep").write_text("not an operational generation")
        store.prune(3)
        store.verify(2, NOW, MAX_AGE)
        store.verify(3, NOW, MAX_AGE)
        self.assertEqual((marker / "keep").read_text(), "not an operational generation")

    def test_failed_archive_cannot_remove_latest_or_recovery_generation(self):
        credential_root = self.base / "archive-is-a-file"
        store = self.store("operational", credential_root=credential_root)
        for generation in (1, 2, 3):
            self.create(store, generation)
        # A durable archive cannot be established at this path. Prune must fail
        # before removal, preserving all usable recovery state and identities.
        if credential_root.exists():
            shutil.rmtree(credential_root)
        credential_root.write_text("spec fixture blocks archive directory")
        with self.assertRaises(Exception):
            store.prune(3)
        for generation in (1, 2, 3):
            store.verify(generation, NOW, MAX_AGE)


class ChunkEncodingFollowupSpec(unittest.TestCase):
    @staticmethod
    def entry(raw):
        return {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_round_trip_minimum_and_maximum_bounded_chunks(self):
        for raw in (b"x", b"x" * MIB, bytes(range(256)) * (MIB // 256)):
            with self.subTest(size=len(raw)):
                record = encode_chunk(raw)
                self.assertIn(record["encoding"], ("raw", "zlib"))
                self.assertIsInstance(record["data_b64"], str)
                self.assertEqual(decode_chunk(record, self.entry(raw)), raw)

    def test_encode_rejects_empty_and_oversized_raw_chunks(self):
        for raw in (b"", b"x" * (MIB + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(Exception):
                encode_chunk(raw)

    def test_decode_rejects_invalid_encoding_base64_size_and_hash(self):
        raw = b"spec chunk payload"
        good = encode_chunk(raw)
        cases = []
        for encoding in ("gzip", "", None):
            bad = dict(good, encoding=encoding)
            cases.append((bad, self.entry(raw)))
        for encoded in ("!@#$", "YQ", None, 123):
            bad = dict(good, data_b64=encoded)
            cases.append((bad, self.entry(raw)))
        for size in (0, -1, len(raw) + 1, MIB + 1, "18", True):
            bad_entry = dict(self.entry(raw), size_bytes=size)
            cases.append((good, bad_entry))
        cases.append((good, dict(self.entry(raw), sha256="0" * 64)))
        cases.append((good, dict(self.entry(raw), sha256="invalid")))
        for record, entry in cases:
            with self.subTest(record=record, entry=entry), self.assertRaises(Exception):
                decode_chunk(record, entry)

    def test_decode_rejects_compression_bomb_truncation_and_trailing_data(self):
        import base64

        raw = b"bounded compressed chunk"
        compressed = zlib.compress(raw)
        payloads = (
            compressed[:-1],
            compressed + b"trailing bytes",
            compressed + zlib.compress(b"second stream"),
            zlib.compress(b"x" * (MIB + 1)),
        )
        for payload in payloads:
            record = {"encoding": "zlib", "data_b64": base64.b64encode(payload).decode("ascii")}
            with self.subTest(compressed_size=len(payload)), self.assertRaises(Exception):
                decode_chunk(record, self.entry(raw))


if __name__ == "__main__":
    unittest.main()
