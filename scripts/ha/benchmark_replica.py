#!/usr/bin/env python3
"""Explicit disposable >= current-size replica benchmark; no production input.

Run: python3 scripts/ha/benchmark_replica.py --output /path/result.json
Uses <=512 MiB virtual memory, 1.1 GB incompressible telemetry and synthetic
identities. Cold/one-row-change transfer includes real chunk encoding+decoding.
Disk cache is not flushed; reported timings are this machine, not a WAN estimate.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import resource
import sqlite3
import tempfile
import time

from common import decode_chunk, encode_chunk
from replica import SnapshotStore, TRANSFER_CHUNK_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    results = {"fixture": "synthetic incompressible telemetry; no live data", "virtual_memory_limit_bytes": 512 * 1024 * 1024,
               "baseline_bytes": 1101983744, "cycles": []}
    with tempfile.TemporaryDirectory(prefix="vpnctl-ha-size-") as temporary:
        root = Path(temporary)
        source = root / "source.db"
        with closing(sqlite3.connect(source)) as db:
            db.execute("PRAGMA cache_size=-8192")
            db.executescript("CREATE TABLE _sqlx_migrations(version INTEGER PRIMARY KEY,success INTEGER,checksum BLOB);"
                             "CREATE TABLE users(uuid TEXT,token TEXT,private_key BLOB);"
                             "CREATE TABLE server_metrics(id INTEGER PRIMARY KEY,value BLOB);")
            db.execute("INSERT INTO _sqlx_migrations VALUES(1,1,?)", (b'f' * 48,))
            db.execute("INSERT INTO users VALUES('fixture-uuid','fixture-token',?)", (b'fixture-private-key',))
            # Distinct random chunks defeat compression and prove bounded buffers.
            while db.execute("PRAGMA page_count").fetchone()[0] * 4096 < results["baseline_bytes"]:
                db.execute("INSERT INTO server_metrics(value) VALUES(?)", (os.urandom(TRANSFER_CHUNK_BYTES),))
            db.commit()
        identities = {"deploy_key": root / "deploy_key", "worker_env": root / "worker_env"}
        for path in identities.values():
            path.write_bytes(b"fixture-only-not-live\n")
        stores = [SnapshotStore(root / name, "fixture-build", 1, credential_root=root / (name + "-credentials")) for name in ("source-store", "destination-store")]
        results["source_bytes"] = source.stat().st_size
        for generation in (1, 2, 3, 4):
            if generation == 2:
                with closing(sqlite3.connect(source)) as db:
                    db.execute("UPDATE server_metrics SET value=? WHERE id=1", (os.urandom(TRANSFER_CHUNK_BYTES),)); db.commit()
            if generation == 3:
                identities["worker_env"].write_bytes(b"fixture-only-not-live-changed\n")
            started = time.monotonic()
            manifest = stores[0].create(source, identities, generation, int(time.time() * 1000))
            description = stores[0].describe(generation)
            copied = {"raw_bytes": 0, "wire_bytes": 0, "chunks": 0}
            def reader(name, index, entry):
                raw = stores[0].read_chunk(generation, name, index)
                encoded = encode_chunk(raw)
                copied["raw_bytes"] += len(raw)
                copied["wire_bytes"] += len(json.dumps(encoded).encode())
                copied["chunks"] += 1
                return decode_chunk(encoded, entry)
            stores[1].receive(description, reader, int(time.time() * 1000), 600000)
            for store in stores:
                store.prune(generation)
            results["cycles"].append({"generation": generation, "elapsed_seconds": round(time.monotonic() - started, 3),
                                      "database_bytes": manifest["files"]["inv_db"]["size_bytes"], **copied,
                                      "operational_generations": [len([p for p in store.root.iterdir() if p.name.isdecimal()]) for store in stores],
                                      "credential_archive_bytes": [sum(p.stat().st_size for p in store.credential_root.rglob('*') if p.is_file()) for store in stores]})
            print(json.dumps(results["cycles"][-1]), flush=True)
        results["maximum_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        results["conclusions"] = "Local storage/codec benchmark; no WAN latency or real production distribution claim. Cold JSON-base64 chunk wire cost includes expansion; unchanged chunks reused."
    Path(args.output).write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
