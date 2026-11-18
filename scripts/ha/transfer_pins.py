"""Bounded authenticated handles retaining immutable snapshot transfer files."""
from __future__ import annotations

import math
from pathlib import Path
import re
import shutil
import threading
import time
import uuid

from replica import SnapshotError, SnapshotStore, _directory, _fsync_directory, _identity_name, _path

_PIN = re.compile(r"[0-9a-f]{32}\Z")


class TransferPins:
    def __init__(self, root, store, holders, ttl_seconds=600, clock=time.monotonic):
        if (type(ttl_seconds) not in (int, float) or not math.isfinite(ttl_seconds)
                or not 0 < ttl_seconds <= 3600):
            raise SnapshotError("transfer pin lifetime must be 0..3600 seconds")
        if isinstance(holders, (str, bytes)):
            raise SnapshotError("transfer holders must be a collection")
        try:
            self.holders = {_identity_name(holder) for holder in holders}
        except TypeError as error:
            raise SnapshotError("invalid transfer holders") from error
        if not self.holders:
            raise SnapshotError("transfer holders must be configured")
        root = _path(root)
        if (root == store.root or not root.is_relative_to(store.root)
                or root.is_relative_to(store.credential_root)
                or root.relative_to(store.root).parts[0].isdecimal()):
            raise SnapshotError("unsafe transfer pin root")
        self.root = _directory(root, private=True)
        self.store = store
        self.ttl = ttl_seconds
        self.clock = clock
        self.lock = threading.Lock()
        self.holder_locks = {holder: threading.Lock() for holder in self.holders}
        self.entries = {}
        # A witness restart cancels transfers; tokens are never adopted from an
        # old process's clock domain. Retained credentials live elsewhere.
        for path in self.root.iterdir():
            if path.name.startswith("pin-") and _PIN.fullmatch(path.name[4:]):
                self._remove(path)

    def _holder(self, holder):
        if not isinstance(holder, str) or holder not in self.holders:
            raise SnapshotError("transfer holder is not configured")

    def _remove(self, path):
        if path.exists():
            shutil.rmtree(_path(path))
            _fsync_directory(self.root)

    def reap(self):
        with self.lock:
            expired = [holder for holder, entry in self.entries.items() if self.clock() >= entry["expires"]]
            paths = [self.entries.pop(holder)["root"] for holder in expired]
        for path in paths:
            self._remove(path)

    def acquire(self, holder, generation):
        self._holder(holder)
        with self.holder_locks[holder]:
            return self._acquire(holder, generation)

    def _acquire(self, holder, generation):
        self.reap()
        pin = uuid.uuid4().hex
        root = self.root / ("pin-" + pin)
        entry = {"pin": pin, "generation": generation, "root": root,
                 "expires": self.clock() + self.ttl, "store": None}
        with self.lock:
            old = self.entries.pop(holder, None)
            self.entries[holder] = entry
        if old:
            self._remove(old["root"])
        try:
            self.store._link_generation(generation, root / str(generation))
            pinned = SnapshotStore(root, self.store.build, self.store.schema,
                                   credential_root=self.store.credential_root,
                                   reserve_bytes=self.store.reserve_bytes,
                                   keep_generations=self.store.keep_generations)
            description = pinned.describe(generation)
            with self.lock:
                if self.entries.get(holder) is not entry or self.clock() >= entry["expires"]:
                    raise SnapshotError("transfer pin expired or was replaced during verification")
                entry["store"] = pinned
            return {"pin": pin, "description": description}
        except Exception:
            with self.lock:
                if self.entries.get(holder) is entry:
                    self.entries.pop(holder)
            self._remove(root)
            raise

    def chunk(self, holder, pin, generation, name, index):
        self._holder(holder)
        with self.lock:
            entry = self.entries.get(holder)
            if (not isinstance(pin, str) or not _PIN.fullmatch(pin) or not entry
                    or entry["pin"] != pin or entry["generation"] != generation
                    or self.clock() >= entry["expires"] or entry["store"] is None):
                raise SnapshotError("transfer pin expired, unknown or belongs to another controller")
            store = entry["store"]
        return store.read_chunk(generation, name, index)

    def release(self, holder, pin):
        self._holder(holder)
        with self.lock:
            entry = self.entries.get(holder)
            if not entry or entry["pin"] != pin:
                return
            self.entries.pop(holder)
        self._remove(entry["root"])
