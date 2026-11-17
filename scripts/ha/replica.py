"""Bounded, immutable SQLite replicas for the opt-in HA supervisor.

The caller must stop the worker before ``install`` and must not activate it if
installation raises: replacement is atomic per file, not across all files.
The manifest attests copied identity bytes, not their correctness at the source.
"""

import base64
import binascii
from collections.abc import Mapping
from contextlib import closing, contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time


MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_IDENTITY_FILES = 64
MAX_MANIFEST_BYTES = 64 * 1024
SQLITE_TIMEOUT_SECONDS = 30
FORMAT_VERSION = 1
_CHUNK = 65536
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MANIFEST = "manifest.json"
_DB = "inv_db"
_RESERVED = {_DB, "manifest"}
_MANIFEST_KEYS = {
    "format_version", "build", "schema_version", "generation", "created_at_ms",
    "files", "identity_sha256", "migration_sha256", "schema_sha256",
}


class SnapshotError(ValueError):
    """A replica is invalid or could not be durably published/installed."""


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise SnapshotError(f"{name} must be an integer >= {minimum}")
    return value


def _identity_name(name):
    if not isinstance(name, str) or not _NAME.fullmatch(name) or name in _RESERVED:
        raise SnapshotError("invalid or reserved identity logical name")
    return name


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("duplicate manifest key")
        result[key] = value
    return result


@contextmanager
def _io_errors():
    try:
        yield
    except SnapshotError:
        raise
    except (OSError, sqlite3.Error, UnicodeError, binascii.Error) as error:
        raise SnapshotError(f"snapshot operation failed: {error}") from error


def _path(value):
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except TypeError as error:
        raise SnapshotError("expected a filesystem path") from error
    for part in reversed((path, *path.parents)):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise SnapshotError("symlink paths are forbidden")
    return path


def _directory(path, private=False):
    path = _path(path)
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700)
        _fsync_directory(item.parent)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise SnapshotError("expected directory")
    if private:
        path.chmod(0o700)
    return path


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _regular(path):
    path = _path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SnapshotError("expected a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream, info
    finally:
        os.close(descriptor)


def _write_new(path, chunks, expected=None, budget=MAX_SNAPSHOT_BYTES):
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    with os.fdopen(descriptor, "wb") as stream:
        for chunk in chunks:
            size += len(chunk)
            if size > budget:
                raise SnapshotError("snapshot byte limit exceeded")
            digest.update(chunk)
            stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    result = {"size_bytes": size, "sha256": digest.hexdigest()}
    if expected is not None and result != expected:
        raise SnapshotError("copied file does not match manifest")
    return result


def _copy_new(source, target, budget, expected=None):
    with _regular(source) as (stream, info):
        if info.st_size > budget:
            raise SnapshotError("snapshot byte limit exceeded")
        return _write_new(target, iter(lambda: stream.read(_CHUNK), b""),
                          expected=expected, budget=budget)


def _file_hash(path, budget):
    digest = hashlib.sha256()
    size = 0
    with _regular(path) as (stream, info):
        if info.st_size > budget:
            raise SnapshotError("snapshot byte limit exceeded")
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            size += len(chunk)
            if size > budget:
                raise SnapshotError("snapshot byte limit exceeded")
            digest.update(chunk)
    return {"size_bytes": size, "sha256": digest.hexdigest()}


def _database_fingerprints(path, schema):
    deadline = time.monotonic() + SQLITE_TIMEOUT_SECONDS
    uri = path.as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as database:
        database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_SNAPSHOT_BYTES)
        database.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
        integrity = database.execute("PRAGMA integrity_check")
        if integrity.fetchone() != ("ok",) or integrity.fetchone() is not None:
            raise SnapshotError("database integrity check failed")
        if database.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise SnapshotError("database foreign key check failed")
        migration_hash = hashlib.sha256()
        count = 0
        for version, success, checksum in database.execute(
                "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version"):
            count += 1
            if (type(version) is not int or version != count or version > schema
                    or success != 1 or not isinstance(checksum, bytes)
                    or len(checksum) != 48):
                raise SnapshotError("invalid or unsuccessful migration history")
            migration_hash.update(f"{version}:{checksum.hex()}\n".encode("ascii"))
        if count != schema:
            raise SnapshotError("database migration schema does not match")
        schema_hash = hashlib.sha256()
        for row in database.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "ORDER BY type, name, tbl_name"):
            schema_hash.update(_json_bytes(row) + b"\n")
        return migration_hash.hexdigest(), schema_hash.hexdigest()


class SnapshotStore:
    """Own immutable positive-numbered generations under a private directory."""

    def __init__(self, root, build, schema):
        if not isinstance(build, str) or not build.strip() or len(build) > 512:
            raise SnapshotError("build must be a nonempty string of at most 512 characters")
        self.build = build
        self.schema = _integer(schema, "schema", 1)
        with _io_errors():
            self.root = _directory(root, private=True)

    @contextmanager
    def _locked(self, exclusive):
        _path(self.root)
        descriptor = os.open(self.root / ".lock",
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SnapshotError("invalid snapshot lock")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            os.close(descriptor)

    def _manifest(self, manifest, generation, now_ms, max_age_ms):
        _integer(generation, "generation", 1)
        _integer(now_ms, "now_ms")
        _integer(max_age_ms, "max_age_ms")
        if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
            raise SnapshotError("invalid manifest fields")
        if (type(manifest["format_version"]) is not int
                or manifest["format_version"] != FORMAT_VERSION
                or manifest["build"] != self.build
                or type(manifest["schema_version"]) is not int
                or manifest["schema_version"] != self.schema
                or type(manifest["generation"]) is not int
                or manifest["generation"] != generation):
            raise SnapshotError("manifest generation, build or schema does not match")
        created = _integer(manifest["created_at_ms"], "created_at_ms")
        if created > now_ms or now_ms - created > max_age_ms:
            raise SnapshotError("snapshot is future-dated or stale")
        files = manifest["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= MAX_IDENTITY_FILES + 1:
            raise SnapshotError("invalid snapshot file count")
        if _DB not in files:
            raise SnapshotError("snapshot database is missing")
        total = 0
        for name, entry in files.items():
            if name != _DB:
                _identity_name(name)
            if not isinstance(entry, dict) or set(entry) != {"size_bytes", "sha256"}:
                raise SnapshotError("invalid file manifest")
            total += _integer(entry["size_bytes"], "size_bytes")
            if (not isinstance(entry["sha256"], str)
                    or not _HASH.fullmatch(entry["sha256"])):
                raise SnapshotError("invalid file digest")
        if total > MAX_SNAPSHOT_BYTES or files[_DB]["size_bytes"] == 0:
            raise SnapshotError("snapshot byte limit exceeded or empty database")
        for key in ("identity_sha256", "migration_sha256", "schema_sha256"):
            if not isinstance(manifest[key], str) or not _HASH.fullmatch(manifest[key]):
                raise SnapshotError("invalid manifest digest")
        if manifest["identity_sha256"] != hashlib.sha256(_json_bytes(files)).hexdigest():
            raise SnapshotError("identity digest does not match")
        if len(_json_bytes(manifest)) > MAX_MANIFEST_BYTES:
            raise SnapshotError("manifest byte limit exceeded")
        return manifest

    def _read_manifest(self, directory):
        with _regular(directory / _MANIFEST) as (stream, info):
            if info.st_size > MAX_MANIFEST_BYTES:
                raise SnapshotError("manifest byte limit exceeded")
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise SnapshotError("manifest byte limit exceeded")
        try:
            return json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError) as error:
            raise SnapshotError("invalid manifest JSON") from error

    def _verify(self, directory, generation, now_ms, max_age_ms):
        directory = _path(directory)
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise SnapshotError("generation is not a directory")
        manifest = self._manifest(self._read_manifest(directory), generation,
                                  now_ms, max_age_ms)
        expected_names = set(manifest["files"]) | {_MANIFEST}
        if set(os.listdir(directory)) != expected_names:
            raise SnapshotError("generation contains unexpected or missing files")
        remaining = MAX_SNAPSHOT_BYTES
        for name, entry in manifest["files"].items():
            actual = _file_hash(directory / name, remaining)
            if actual != entry:
                raise SnapshotError("snapshot file hash or size does not match")
            remaining -= actual["size_bytes"]
        migrations, schema = _database_fingerprints(directory / _DB, self.schema)
        if (migrations != manifest["migration_sha256"]
                or schema != manifest["schema_sha256"]):
            raise SnapshotError("database schema fingerprints do not match")
        return manifest

    def _publish(self, temporary, generation):
        destination = self.root / str(generation)
        if os.path.lexists(destination):
            raise SnapshotError("immutable generation already exists")
        _fsync_directory(temporary)
        os.rename(temporary, destination)
        _fsync_directory(self.root)

    def create(self, source_db, identity_files, generation, created_at_ms):
        """Back up SQLite online, copy explicit identities, verify, then publish."""
        _integer(generation, "generation", 1)
        _integer(created_at_ms, "created_at_ms")
        identities = self._identities(identity_files)
        with _io_errors(), self._locked(True):
            if os.path.lexists(self.root / str(generation)):
                raise SnapshotError("immutable generation already exists")
            temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.root))
            try:
                self._backup(source_db, temporary / _DB)
                files = {_DB: _file_hash(temporary / _DB, MAX_SNAPSHOT_BYTES)}
                remaining = MAX_SNAPSHOT_BYTES - files[_DB]["size_bytes"]
                for name, source in sorted(identities.items()):
                    files[name] = _copy_new(source, temporary / name, remaining)
                    remaining -= files[name]["size_bytes"]
                migrations, schema = _database_fingerprints(temporary / _DB, self.schema)
                manifest = {
                    "format_version": FORMAT_VERSION, "build": self.build,
                    "schema_version": self.schema, "generation": generation,
                    "created_at_ms": created_at_ms, "files": files,
                    "identity_sha256": hashlib.sha256(_json_bytes(files)).hexdigest(),
                    "migration_sha256": migrations, "schema_sha256": schema,
                }
                self._manifest(manifest, generation, created_at_ms, 0)
                _write_new(temporary / _MANIFEST, [_json_bytes(manifest)],
                           budget=MAX_MANIFEST_BYTES)
                self._verify(temporary, generation, created_at_ms, 0)
                self._publish(temporary, generation)
                return manifest
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)

    def _backup(self, source_db, target):
        source_db = _path(source_db)
        with _regular(source_db) as (_, info):
            if info.st_size > MAX_SNAPSHOT_BYTES:
                raise SnapshotError("snapshot byte limit exceeded")
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            deadline = time.monotonic() + SQLITE_TIMEOUT_SECONDS
            with closing(sqlite3.connect(source_db.as_uri() + "?mode=ro", uri=True,
                                         timeout=5)) as source:
                page_size = source.execute("PRAGMA page_size").fetchone()[0]

                def progress(_status, _remaining, total):
                    if total * page_size > MAX_SNAPSHOT_BYTES:
                        raise SnapshotError("snapshot byte limit exceeded")
                    if time.monotonic() > deadline:
                        raise SnapshotError("SQLite backup timed out")

                with closing(sqlite3.connect(target)) as destination:
                    source.backup(destination, pages=256, progress=progress, sleep=0.01)
                    destination.execute("PRAGMA journal_mode=DELETE")
            with _regular(target) as (stream, _):
                os.fsync(stream.fileno())

    @staticmethod
    def _identities(identities):
        if not isinstance(identities, Mapping) or len(identities) > MAX_IDENTITY_FILES:
            raise SnapshotError("invalid identity mapping")
        return {_identity_name(name): _path(path) for name, path in identities.items()}

    def verify(self, generation, now_ms, max_age_ms):
        """Verify every byte, SQLite constraints, build/schema and source age."""
        _integer(generation, "generation", 1)
        with _io_errors(), self._locked(False):
            return self._verify(self.root / str(generation), generation, now_ms,
                                max_age_ms)

    def install(self, generation, target_db, identity_targets, now_ms, max_age_ms):
        """Replace verified files; worker-stop proof is the caller's obligation."""
        _integer(generation, "generation", 1)
        targets = self._identities(identity_targets)
        with _io_errors(), self._locked(False):
            manifest = self._verify(self.root / str(generation), generation,
                                    now_ms, max_age_ms)
            if set(targets) != set(manifest["files"]) - {_DB}:
                raise SnapshotError("identity targets do not exactly match snapshot")
            targets[_DB] = _path(target_db)
            companions = [Path(str(targets[_DB]) + suffix)
                          for suffix in ("-wal", "-shm", "-journal")]
            if (len(set(targets.values())) != len(targets)
                    or set(targets.values()) & set(companions)
                    or any(path.is_relative_to(self.root) for path in targets.values())):
                raise SnapshotError("install targets overlap or modify the snapshot store")
            staged = []
            try:
                for name, target in targets.items():
                    _directory(target.parent)
                    self._destination(target)
                    descriptor, filename = tempfile.mkstemp(prefix=".vpnctl-ha-",
                                                             dir=target.parent)
                    os.close(descriptor)
                    os.unlink(filename)
                    temporary = Path(filename)
                    staged.append((temporary, target))
                    _copy_new(self.root / str(generation) / name, temporary,
                              manifest["files"][name]["size_bytes"],
                              expected=manifest["files"][name])
                    if target.exists():
                        owner = target.stat()
                        os.chown(temporary, owner.st_uid, owner.st_gid)
                for companion in companions:
                    self._destination(companion)
                for companion in companions:
                    if companion.exists():
                        companion.unlink()
                _fsync_directory(targets[_DB].parent)
                for temporary, target in staged:
                    self._destination(target)
                    os.replace(temporary, target)
                    _fsync_directory(target.parent)
                return manifest
            finally:
                for temporary, _ in staged:
                    if temporary.exists():
                        temporary.unlink()

    @staticmethod
    def _destination(path):
        _path(path)
        if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
            raise SnapshotError("install destination is not a regular file")

    def export(self, generation):
        """Return a bounded JSON-compatible record with fixed logical names."""
        _integer(generation, "generation", 1)
        with _io_errors(), self._locked(False):
            directory = self.root / str(generation)
            manifest = self._read_manifest(directory)
            if not isinstance(manifest, dict):
                raise SnapshotError("invalid manifest")
            self._verify(directory, generation, manifest.get("created_at_ms"), 0)
            files = {}
            for name, expected in manifest["files"].items():
                output = io.StringIO()
                digest = hashlib.sha256()
                size = 0
                with _regular(directory / name) as (stream, _):
                    for chunk in iter(lambda: stream.read(65535), b""):
                        size += len(chunk)
                        if size > expected["size_bytes"]:
                            raise SnapshotError("snapshot changed during export")
                        digest.update(chunk)
                        output.write(base64.b64encode(chunk).decode("ascii"))
                if {"size_bytes": size, "sha256": digest.hexdigest()} != expected:
                    raise SnapshotError("snapshot changed during export")
                files[name] = output.getvalue()
            return {"manifest": manifest, "files": files}

    def import_snapshot(self, record, now_ms, max_age_ms):
        """Validate a bounded fixed-name record before publishing a generation."""
        if not isinstance(record, dict) or set(record) != {"manifest", "files"}:
            raise SnapshotError("invalid snapshot record")
        manifest = record["manifest"]
        if not isinstance(manifest, dict):
            raise SnapshotError("invalid manifest")
        generation = _integer(manifest.get("generation"), "generation", 1)
        self._manifest(manifest, generation, now_ms, max_age_ms)
        files = record["files"]
        if not isinstance(files, dict) or set(files) != set(manifest["files"]):
            raise SnapshotError("record files do not exactly match manifest")
        for name, encoded in files.items():
            size = manifest["files"][name]["size_bytes"]
            if (not isinstance(encoded, str) or not encoded.isascii()
                    or len(encoded) != 4 * ((size + 2) // 3)
                    or "=" in encoded[:max(0, len(encoded) - 2)]):
                raise SnapshotError("invalid or oversized base64 file")
        with _io_errors(), self._locked(True):
            if os.path.lexists(self.root / str(generation)):
                raise SnapshotError("immutable generation already exists")
            temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.root))
            try:
                for name, encoded in files.items():
                    chunks = (base64.b64decode(encoded[offset:offset + _CHUNK], validate=True)
                              for offset in range(0, len(encoded), _CHUNK))
                    _write_new(temporary / name, chunks,
                               expected=manifest["files"][name],
                               budget=manifest["files"][name]["size_bytes"])
                _write_new(temporary / _MANIFEST, [_json_bytes(manifest)],
                           budget=MAX_MANIFEST_BYTES)
                self._verify(temporary, generation, now_ms, max_age_ms)
                self._publish(temporary, generation)
                return manifest
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
