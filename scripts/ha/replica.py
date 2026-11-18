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


MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024 * 1024
MAX_LEGACY_BYTES = 8 * 1024 * 1024
TRANSFER_CHUNK_BYTES = 1024 * 1024
MAX_DESCRIPTION_BYTES = 2 * 1024 * 1024
MAX_IDENTITY_FILES = 64
MAX_MANIFEST_BYTES = 64 * 1024
SQLITE_TIMEOUT_SECONDS = 600
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


class _ArchiveSqlError(SnapshotError):
    """Credential SQL extraction could not prove recoverability."""


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
        try:
            item.mkdir(mode=0o700)
        except FileExistsError:
            _path(item)
            if not stat.S_ISDIR(item.lstat().st_mode):
                raise SnapshotError("expected directory")
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


def _space(path, required, reserve_bytes):
    if shutil.disk_usage(path).free < required + reserve_bytes:
        raise SnapshotError("snapshot/credential capacity reserve would be exhausted")


def _write_new(path, chunks, expected=None, budget=MAX_SNAPSHOT_BYTES, reserve_bytes=0):
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    with os.fdopen(descriptor, "wb") as stream:
        for chunk in chunks:
            size += len(chunk)
            if size > budget:
                raise SnapshotError("snapshot byte limit exceeded")
            if reserve_bytes:
                _space(path.parent, len(chunk) + 4096, reserve_bytes)
            digest.update(chunk)
            stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    result = {"size_bytes": size, "sha256": digest.hexdigest()}
    if expected is not None and result != expected:
        raise SnapshotError("copied file does not match manifest")
    return result


def _copy_new(source, target, budget, expected=None, reserve_bytes=0):
    with _regular(source) as (stream, info):
        if info.st_size > budget:
            raise SnapshotError("snapshot byte limit exceeded")
        return _write_new(target, iter(lambda: stream.read(_CHUNK), b""),
                          expected=expected, budget=budget, reserve_bytes=reserve_bytes)


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
        database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
        database.execute("PRAGMA cache_size=-8192")
        database.execute("PRAGMA temp_store=FILE")
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

    def __init__(self, root, build, schema, credential_root=None,
                 reserve_bytes=2147483648, keep_generations=2):
        if not isinstance(build, str) or not build.strip() or len(build) > 512:
            raise SnapshotError("build must be a nonempty string of at most 512 characters")
        self.build = build
        self.schema = _integer(schema, "schema", 1)
        with _io_errors():
            self.root = _directory(root, private=True)
            store_id = hashlib.sha256(os.fsencode(self.root)).hexdigest()[:24]
            self.credential_root = _directory(credential_root if credential_root is not None else
                Path.home() / ".local/share/agent-credentials/vpnctl-ha" / store_id, private=True)
            if self.credential_root.is_relative_to(self.root):
                raise SnapshotError("credential archive must be outside operational store")
            self.reserve_bytes = _integer(reserve_bytes, "reserve_bytes")
            self.keep_generations = _integer(keep_generations, "keep_generations", 2)
            with self._locked(True):
                for path in self.root.iterdir():
                    if path.name.startswith((".pending-", ".retired-")):
                        shutil.rmtree(_path(path))
                _fsync_directory(self.root)

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

    def _capacity(self, required):
        _space(self.root, required, self.reserve_bytes)

    def _archive(self, directory):
        # Explicit allowlist: unknown tables are always recovery data. Never add
        # credential/config tables here merely to reduce archive size.
        telemetry = {
            "server_metrics", "vpn_connection_stats", "node_health", "vpn_user_daily",
            "vpn_user_destinations", "vpn_user_sessions", "vpn_user_source_ips",
            "vpn_user_ip_concurrency", "vpn_server_hourly", "server_quality_samples",
            "protocol_assurance_samples", "sub_access_log",
            "dns_ptr_cache", "vpn_server_counter_baselines", "vpn_user_counter_baselines",
        }
        archive = self.credential_root
        versions = _directory(archive / "versions", private=True)
        descriptor = os.open(archive / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        temporary = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=archive))
            manifest = self._read_manifest(directory)
            files = {}
            # SQL is directly restorable with sqlite3, including complete BLOBs,
            # NUL-containing text (CAST from hex), deleted historical identities,
            # unknown table data, schema and indexes. Iteration is bounded.
            def literal(value):
                if value is None:
                    return "NULL"
                if isinstance(value, bytes):
                    return "X'" + value.hex() + "'"
                if isinstance(value, str):
                    return "CAST(X'" + value.encode("utf-8").hex() + "' AS TEXT)"
                return repr(value)

            def sql_chunks():
                yield b"PRAGMA foreign_keys=OFF;\nBEGIN;\n"
                uri = (directory / _DB).as_uri() + "?mode=ro&immutable=1"
                with closing(sqlite3.connect(uri, uri=True)) as source:
                    source.execute("PRAGMA cache_size=-8192")
                    source.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
                    objects = ("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL "
                               "AND name NOT LIKE 'sqlite_%' ORDER BY type='table' DESC,name")
                    for kind, name, sql in source.execute(objects):
                        if kind == "table":
                            yield (sql + ";\n").encode()
                            if name in telemetry:
                                continue
                            quoted = '"' + name.replace('"', '""') + '"'
                            columns = [row[1] for row in source.execute("PRAGMA table_xinfo(" + quoted + ")") if row[6] == 0]
                            column_sql = ",".join('"' + column.replace('"', '""') + '"' for column in columns)
                            for row in source.execute("SELECT " + column_sql + " FROM " + quoted):
                                yield ("INSERT INTO " + quoted + "(" + column_sql + ") VALUES(" +
                                       ",".join(literal(value) for value in row) + ");\n").encode()
                    if source.execute("SELECT 1 FROM sqlite_schema WHERE name='sqlite_sequence'").fetchone():
                        yield b"DELETE FROM sqlite_sequence;\n"
                        for name, sequence in source.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name"):
                            yield ("INSERT INTO sqlite_sequence(name,seq) VALUES(" + literal(name) + "," + literal(sequence) + ");\n").encode()
                    for kind, _, sql in source.execute(objects):
                        if kind != "table":
                            yield (sql + ";\n").encode()
                yield b"COMMIT;\n"
            database_path = directory / _DB
            sql_valid = False
            if database_path.exists() and not manifest.get("raw_database"):
                try:
                    with closing(sqlite3.connect(database_path.as_uri() + "?mode=ro&immutable=1", uri=True)) as source:
                        source.execute("SELECT count(*) FROM sqlite_schema").fetchone()
                    sql_valid = True
                except sqlite3.Error:
                    pass
            sql_size = sum(len(chunk) for chunk in sql_chunks()) if sql_valid else 0
            required = sum(entry["size_bytes"] for name, entry in manifest["files"].items() if name != _DB)
            required += sql_size if sql_valid else database_path.stat().st_size if database_path.exists() else 0
            _space(archive, required + sql_size + 1024 * 1024 + MAX_MANIFEST_BYTES, self.reserve_bytes)
            for name, entry in manifest["files"].items():
                if name != _DB:
                    files[name] = _copy_new(directory / name, temporary / name,
                                            entry["size_bytes"], expected=entry,
                                            reserve_bytes=self.reserve_bytes)
            if sql_valid:
                files["database.sql"] = _write_new(temporary / "database.sql", sql_chunks(),
                                                    budget=MAX_SNAPSHOT_BYTES * 3,
                                                    reserve_bytes=self.reserve_bytes)
                self._verify_archive_sql(temporary / "database.sql")
            elif database_path.exists():
                files["database.raw"] = _copy_new(database_path, temporary / "database.raw", MAX_SNAPSHOT_BYTES,
                                                   reserve_bytes=self.reserve_bytes)
            version = hashlib.sha256(_json_bytes(files)).hexdigest()
            record = {"format": 1, "files": files, "excluded_pure_telemetry": sorted(telemetry)}
            _write_new(temporary / _MANIFEST, [_json_bytes(record)], budget=MAX_MANIFEST_BYTES,
                       reserve_bytes=self.reserve_bytes)
            destination = versions / version
            if destination.exists():
                # Revalidate immutable prior bytes before relying on deduplication.
                for name, expected in files.items():
                    if _file_hash(destination / name, expected["size_bytes"]) != expected:
                        raise SnapshotError("permanent credential archive is corrupt")
            else:
                _fsync_directory(temporary)
                os.rename(temporary, destination)
                temporary = None
                _fsync_directory(versions)
            index_file = archive / "index.json"
            index = json.loads(index_file.read_bytes()) if index_file.exists() else []
            if not any(item["version"] == version for item in index):
                index.append({"version": version, "project": "vpnctl-ha", "machine": str(self.root),
                              "purpose": "permanent recoverable credentials/config", "created_at_ms": time.time_ns() // 1000000,
                              "path": str(destination)})
                from common import atomic_json
                _space(archive, len(_json_bytes(index)) + 4096, self.reserve_bytes)
                atomic_json(index_file, index)
        finally:
            try:
                if temporary is not None and temporary.exists():
                    shutil.rmtree(temporary)
            finally:
                os.close(descriptor)

    def _verify_archive_sql(self, sql_path):
        restored_path = sql_path.parent / ".restore-check.db"
        try:
            with closing(sqlite3.connect(restored_path)) as restored:
                restored.execute("PRAGMA cache_size=-8192")
                restored.execute("PRAGMA temp_store=FILE")
                restored.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
                restored.set_progress_handler(lambda: shutil.disk_usage(sql_path.parent).free <
                                              self.reserve_bytes + 1024 * 1024, 10000)
                statement = ""
                with _regular(sql_path) as (stream, _):
                    for raw in stream:
                        statement += raw.decode("utf-8")
                        if len(statement) > 64 * 1024 * 1024:
                            raise _ArchiveSqlError("credential restore statement exceeds bounded limit")
                        if sqlite3.complete_statement(statement):
                            _space(sql_path.parent, len(statement.encode()) + 1024 * 1024, self.reserve_bytes)
                            restored.execute(statement)
                            statement = ""
                if statement.strip() or restored.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise _ArchiveSqlError("credential SQL archive cannot be restored")
        except sqlite3.Error as error:
            raise _ArchiveSqlError("credential SQL archive restore validation failed") from error
        finally:
            for suffix in ("", "-journal", "-wal", "-shm"):
                path = Path(str(restored_path) + suffix)
                if path.exists():
                    path.unlink()

    def prune(self, latest_generation):
        """Bound operational history only after durable independent retention."""
        _integer(latest_generation, "latest_generation", 1)
        with _io_errors(), self._locked(True):
            latest = self._read_manifest(self.root / str(latest_generation))
            self._verify(self.root / str(latest_generation), latest_generation,
                         latest["created_at_ms"], 0)
            generations = sorted((int(path.name) for path in self.root.iterdir()
                                  if path.name.isdecimal() and int(path.name) > 0), reverse=True)
            keep = {latest_generation}
            keep.update(g for g in generations if g < latest_generation and
                        len([n for n in generations if g < n < latest_generation]) < self.keep_generations - 1)
            for generation in generations:
                directory = self.root / str(generation)
                # A newer generation may be fully verified but still awaiting
                # its authority recheck/pointer commit in another request.
                if generation in keep or generation > latest_generation:
                    continue
                self._retire_generation(generation)
            # These are private staging/retired copies, never advertised. Valid
            # numbered copies were archived before retirement. Pending imports
            # have their source retained and cannot be used as recovery state.
            for path in self.root.iterdir():
                if path.name.startswith(".retired-"):
                    shutil.rmtree(_path(path))
                    _fsync_directory(self.root)

    def _retire_unpublished(self, latest_generation):
        # Caller serializes the complete publication lifecycle, so a numeric
        # generation above this pointer cannot be an in-flight transfer.
        _integer(latest_generation, "latest_generation")
        with _io_errors(), self._locked(True):
            for directory in self.root.iterdir():
                if not directory.name.isdecimal() or int(directory.name) <= latest_generation:
                    continue
                self._retire_generation(int(directory.name))

    def _retire_generation(self, generation):
        directory = self.root / str(generation)
        manifest = self._read_manifest(directory)
        self._verify(directory, generation, manifest["created_at_ms"], 0)
        self._archive(directory)
        # Interrupted deletion never leaves a numbered, partially valid copy.
        retired = self.root / (".retired-" + str(generation))
        os.rename(directory, retired)
        _fsync_directory(self.root)

        shutil.rmtree(retired)
        cache = self.root / (".chunks-" + str(generation) + ".json")
        if cache.exists():
            cache.unlink()
        _fsync_directory(self.root)

    def _link_generation(self, generation, destination):
        _integer(generation, "generation", 1)
        destination = _path(destination)
        with _io_errors(), self._locked(False):
            directory = self.root / str(generation)
            manifest = self._read_manifest(directory)
            self._manifest(manifest, generation, manifest["created_at_ms"], 0)
            _space(self.root, 4096 * (len(manifest["files"]) + 2) + MAX_DESCRIPTION_BYTES, self.reserve_bytes)
            _directory(destination.parent, private=True)
            destination.mkdir(mode=0o700)
            for name in [*manifest["files"], _MANIFEST]:
                with _regular(directory / name):
                    os.link(directory / name, destination / name, follow_symlinks=False)
            _fsync_directory(destination)
            _fsync_directory(destination.parent)

    def describe(self, generation):
        """Describe ordered bounded chunks; no complete file enters memory."""
        _integer(generation, "generation", 1)
        with _io_errors(), self._locked(False):
            directory = self.root / str(generation)
            manifest = self._read_manifest(directory)
            self._verify(directory, generation, manifest["created_at_ms"], 0)
            chunks = {}
            for name in manifest["files"]:
                entries = []
                with _regular(directory / name) as (stream, _):
                    for chunk in iter(lambda: stream.read(TRANSFER_CHUNK_BYTES), b""):
                        entries.append({"size_bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()})
                chunks[name] = entries
            result = {"manifest": manifest, "chunks": chunks}
            if len(_json_bytes(result)) > MAX_DESCRIPTION_BYTES:
                raise SnapshotError("chunk description too large")
            from common import atomic_json
            _space(self.root, len(_json_bytes(result)) + 4096, self.reserve_bytes)
            atomic_json(self.root / (".chunks-" + str(generation) + ".json"), result)
            return result

    def read_chunk(self, generation, name, index):
        """Read exactly one fixed-name chunk, with no caller-selected paths."""
        _integer(generation, "generation", 1)
        _integer(index, "index")
        if name != _DB:
            _identity_name(name)
        cache = self.root / (".chunks-" + str(generation) + ".json")
        if not cache.exists():
            self.describe(generation)
        with _io_errors(), self._locked(False):
            directory = self.root / str(generation)
            manifest = self._read_manifest(directory)
            self._manifest(manifest, generation, manifest["created_at_ms"], 0)
            if name not in manifest["files"] or index * TRANSFER_CHUNK_BYTES >= manifest["files"][name]["size_bytes"]:
                raise SnapshotError("chunk index or logical name is invalid")
            with _regular(directory / name) as (stream, _):
                stream.seek(index * TRANSFER_CHUNK_BYTES)
                data = stream.read(TRANSFER_CHUNK_BYTES)
            with _regular(cache) as (stream, info):
                if info.st_size > MAX_DESCRIPTION_BYTES:
                    raise SnapshotError("chunk description too large")
                description = json.load(stream)
            if description.get("manifest") != manifest:
                raise SnapshotError("chunk description differs from immutable manifest")
            expected = description["chunks"][name][index]
            if {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} != expected:
                raise SnapshotError("source chunk hash or length mismatch")
            return data

    def receive(self, description, reader, now_ms, max_age_ms):
        """Reuse local chunks, stream missing bytes, then verify and publish."""
        if not isinstance(description, dict) or set(description) != {"manifest", "chunks"}:
            raise SnapshotError("invalid chunk description")
        manifest = description["manifest"]
        if not isinstance(manifest, dict):
            raise SnapshotError("invalid manifest")
        generation = _integer(manifest.get("generation"), "generation", 1)
        self._manifest(manifest, generation, now_ms, max_age_ms)
        plan = description["chunks"]
        if not isinstance(plan, dict) or set(plan) != set(manifest["files"]) or len(_json_bytes(description)) > MAX_DESCRIPTION_BYTES:
            raise SnapshotError("invalid chunk description files or size")
        for name, entries in plan.items():
            size = manifest["files"][name]["size_bytes"]
            if not isinstance(entries, list) or len(entries) != (size + TRANSFER_CHUNK_BYTES - 1) // TRANSFER_CHUNK_BYTES:
                raise SnapshotError("invalid chunk count")
            for index, entry in enumerate(entries):
                expected_size = min(TRANSFER_CHUNK_BYTES, size - index * TRANSFER_CHUNK_BYTES)
                if (not isinstance(entry, dict) or set(entry) != {"size_bytes", "sha256"}
                        or type(entry["size_bytes"]) is not int or entry["size_bytes"] != expected_size
                        or not isinstance(entry["sha256"], str) or not _HASH.fullmatch(entry["sha256"])):
                    raise SnapshotError("invalid chunk entry")
        with _io_errors(), self._locked(True):
            if os.path.lexists(self.root / str(generation)):
                raise SnapshotError("immutable generation already exists")
            self._capacity(sum(entry["size_bytes"] for entry in manifest["files"].values()))
            # Index one prior verified generation. Reuse by content, regardless
            # of shifted file offsets, with bounded index size (8 GiB / 1 MiB).
            reusable = {}
            prior = sorted((int(p.name) for p in self.root.iterdir() if p.name.isdecimal()), reverse=True)
            if prior:
                old_dir = self.root / str(prior[0])
                old = self._read_manifest(old_dir)
                self._verify(old_dir, prior[0], old["created_at_ms"], 0)
                for name in old["files"]:
                    with _regular(old_dir / name) as (stream, _):
                        index = 0
                        for data in iter(lambda: stream.read(TRANSFER_CHUNK_BYTES), b""):
                            reusable[(hashlib.sha256(data).hexdigest(), len(data))] = (old_dir / name, index)
                            index += 1
            temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.root))
            try:
                for name, entries in plan.items():
                    def chunks():
                        for index, entry in enumerate(entries):
                            reuse = reusable.get((entry["sha256"], entry["size_bytes"]))
                            if reuse:
                                with _regular(reuse[0]) as (stream, _):
                                    stream.seek(reuse[1] * TRANSFER_CHUNK_BYTES)
                                    data = stream.read(entry["size_bytes"])
                            else:
                                data = reader(name, index, entry)
                            if (not isinstance(data, bytes) or len(data) != entry["size_bytes"]
                                    or hashlib.sha256(data).hexdigest() != entry["sha256"]):
                                raise SnapshotError("chunk hash or size does not match")
                            yield data
                    _write_new(temporary / name, chunks(), expected=manifest["files"][name],
                               budget=manifest["files"][name]["size_bytes"], reserve_bytes=self.reserve_bytes)
                _write_new(temporary / _MANIFEST, [_json_bytes(manifest)], budget=MAX_MANIFEST_BYTES,
                           reserve_bytes=self.reserve_bytes)
                self._verify(temporary, generation, now_ms, max_age_ms)
                self._archive(temporary)
                self._publish(temporary, generation)
                return manifest
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)

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
                with _regular(source_db) as (_, info):
                    self._capacity(info.st_size + sum(path.stat().st_size for path in identities.values()))
                self._backup(source_db, temporary / _DB)
                files = {_DB: _file_hash(temporary / _DB, MAX_SNAPSHOT_BYTES)}
                remaining = MAX_SNAPSHOT_BYTES - files[_DB]["size_bytes"]
                for name, source in sorted(identities.items()):
                    files[name] = _copy_new(source, temporary / name, remaining, reserve_bytes=self.reserve_bytes)
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
                           budget=MAX_MANIFEST_BYTES, reserve_bytes=self.reserve_bytes)
                self._verify(temporary, generation, created_at_ms, 0)
                self._archive(temporary)
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
                    _space(target.parent, 1024 * 1024, self.reserve_bytes)

                with closing(sqlite3.connect(target)) as destination:
                    source.execute("PRAGMA cache_size=-8192")
                    destination.execute("PRAGMA cache_size=-8192")
                    # Pin one WAL read transaction: continuous metric writes
                    # must not restart a production-size backup every batch.
                    source.execute("BEGIN")
                    source.execute("SELECT count(*) FROM sqlite_schema").fetchone()
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
            for target in targets.values():
                self._destination(target)
            for companion in companions:
                self._destination(companion)
            store_device = self.root.stat().st_dev
            capacities = {store_device: [self.root, sum(path.stat().st_size for path in [*targets.values(), *companions] if path.exists())]}
            for name, target in targets.items():
                _directory(target.parent)
                device = target.parent.stat().st_dev
                capacities.setdefault(device, [target.parent, 0])[1] += manifest["files"][name]["size_bytes"]
            for path, required in capacities.values():
                _space(path, required, self.reserve_bytes)
            self._retain_destinations(targets)
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
                              expected=manifest["files"][name], reserve_bytes=self.reserve_bytes)
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

    def _retain_destinations(self, targets):
        """Keep divergent credentials before recovery replaces local state."""
        existing = {name: path for name, path in targets.items() if path.exists()}
        if not existing:
            return
        temporary = Path(tempfile.mkdtemp(prefix=".pending-preserve-", dir=self.root))
        try:
            files = {}
            raw_database = False
            for name, path in existing.items():
                self._destination(path)
                if name == _DB:
                    try:
                        self._backup(path, temporary / name)
                    except (SnapshotError, sqlite3.Error):
                        raw_database = True
                        self._stage_raw_database(path, temporary, files)
                    files[name] = _file_hash(temporary / name, MAX_SNAPSHOT_BYTES)
                else:
                    files[name] = _copy_new(path, temporary / name, MAX_SNAPSHOT_BYTES,
                                            reserve_bytes=self.reserve_bytes)
            _write_new(temporary / _MANIFEST, [_json_bytes({"files": files, "raw_database": raw_database})], budget=MAX_MANIFEST_BYTES)
            try:
                self._archive(temporary)
            except (sqlite3.Error, _ArchiveSqlError):
                if raw_database or _DB not in existing:
                    raise
                # A readable schema/online backup does not prove data pages or
                # exported SQL are recoverable. Retain the original full raw
                # recovery set before replacement when extraction fails too.
                self._stage_raw_database(existing[_DB], temporary, files)
                (temporary / _MANIFEST).unlink()
                _write_new(temporary / _MANIFEST, [_json_bytes({"files": files, "raw_database": True})], budget=MAX_MANIFEST_BYTES)
                self._archive(temporary)
        finally:
            shutil.rmtree(temporary)

    def _stage_raw_database(self, source, temporary, files):
        for path, logical in ((source, _DB), *((Path(str(source) + suffix), logical)
                               for suffix, logical in (("-wal", "db_wal"), ("-shm", "db_shm"), ("-journal", "db_journal")))):
            if path.exists():
                target = temporary / logical
                if target.exists():
                    target.unlink()
                files[logical] = _copy_new(path, target, MAX_SNAPSHOT_BYTES, reserve_bytes=self.reserve_bytes)

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
            if sum(entry["size_bytes"] for entry in manifest["files"].values()) > MAX_LEGACY_BYTES:
                raise SnapshotError("whole-record export is limited to small fixtures; use chunks")
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
        if sum(entry["size_bytes"] for entry in manifest["files"].values()) > MAX_LEGACY_BYTES:
            raise SnapshotError("whole-record import is limited to small fixtures; use chunks")
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
                               budget=manifest["files"][name]["size_bytes"], reserve_bytes=self.reserve_bytes)
                _write_new(temporary / _MANIFEST, [_json_bytes(manifest)],
                           budget=MAX_MANIFEST_BYTES, reserve_bytes=self.reserve_bytes)
                self._verify(temporary, generation, now_ms, max_age_ms)
                self._archive(temporary)
                self._publish(temporary, generation)
                return manifest
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
