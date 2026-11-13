"""Keep the security backport byte-identical to the published upstream sources."""

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SqlxSqliteVendorTests(unittest.TestCase):
    def test_only_documented_manifest_dependency_changes_differ_from_upstream(self):
        package = ROOT / "vendor" / "sqlx-sqlite"
        hashes = json.loads(
            (ROOT / "vendor" / "sqlx-sqlite-upstream-sha256.json").read_text()
        )
        actual_files = {
            path.relative_to(package).as_posix()
            for path in package.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual_files, set(hashes))
        for name, expected in hashes.items():
            with self.subTest(file=name):
                content = (package / name).read_bytes()
                if name in {"Cargo.toml", "Cargo.toml.orig"}:
                    patched = b'[dependencies.libsqlite3-sys]\nversion = "=0.39.1"'
                    upstream = b'[dependencies.libsqlite3-sys]\nversion = "0.30.1"'
                    self.assertEqual(content.count(patched), 1)
                    content = content.replace(patched, upstream)
                self.assertEqual(hashlib.sha256(content).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
