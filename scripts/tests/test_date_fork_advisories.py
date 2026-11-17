"""Independent specification tests for the maintained-date-forks contract."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/audit-date-forks.py"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
FORKS = (
    ("chrono", "0.4.44", "https://github.com/PavelLizunov/ninitux-chrono",
     "c14b4599d07ef36ffa1f8a531fb0bc7eb3b42464",
     "c673075a2e0e5f4a1dde27ce9dee1ea4558c7ffe648f576438a20ca1d2acc4b0"),
    ("chrono-tz", "0.10.4", "https://github.com/PavelLizunov/ninitux-chrono-tz",
     "e15d1f308a1ac2fdf3f1bf19c325dc202d418081",
     "a6139a8597ed92cf816dfb33f5dd6cf0bb93a6adc938f11039f371bc5bcd26c3"),
)
BASELINE = "RUSTSEC-2020-0001"
MAINTENANCE = {"RUSTSEC-2026-0543", "RUSTSEC-2026-0555"}
NEW_ADVISORY = "RUSTSEC-2026-9999"
UNRELATED = '''[[package]]
name = "unrelated"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# Preserve this comment and spacing exactly.

'''


def source(fork):
    return f"git+{fork[2]}?rev={fork[3]}#{fork[3]}"


def load_subject():
    spec = importlib.util.spec_from_file_location("date_fork_audit_subject", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DateForkAdvisories(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.subject = load_subject()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "audit.lock"
        self.manifest = '[package]\nname = "fixture"\nversion = "0.1.0"\n\n[patch.crates-io]\n'
        for name, _, url, rev, _ in FORKS:
            self.manifest += f'{name} = {{ git = "{url}", rev = "{rev}" }}\n'
        self.lock = '# Synthetic complete lockfile\nversion = 3\n\n' + UNRELATED
        for fork in FORKS:
            self.lock += (f'[[package]]\nname = "{fork[0]}"\n'
                          f'version = "{fork[1]}"\nsource = "{source(fork)}"\n')
            if fork[0] == "chrono-tz":
                self.lock += f'dependencies = [\n "chrono 0.4.44 ({source(FORKS[0])})",\n]\n'
            self.lock += '\n'
        self.write_fixture()

    def write_fixture(self):
        (self.root / "Cargo.toml").write_text(self.manifest)
        (self.root / "Cargo.lock").write_text(self.lock)
        (self.root / "deny.toml").write_text(
            f'[advisories]\nignore = ["{BASELINE}"]\n')

    def assert_rejected(self):
        # Both creation and overwriting must be prevented on invalid provenance.
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.output.write_bytes(b"existing audit artifact\n")
                elif self.output.exists():
                    self.output.unlink()
                before = (self.root / "Cargo.lock").read_bytes()
                with self.assertRaises(ValueError):
                    self.subject.prepare_lock(self.root, self.output)
                self.assertEqual((self.root / "Cargo.lock").read_bytes(), before)
                if existing:
                    self.assertEqual(self.output.read_bytes(), b"existing audit artifact\n")
                else:
                    self.assertFalse(self.output.exists())

    def test_normalizes_only_owned_entries_and_qualified_references(self):
        before = (self.root / "Cargo.lock").read_bytes()
        self.subject.prepare_lock(self.root, self.output)
        actual = self.output.read_text()
        self.assertEqual((self.root / "Cargo.lock").read_bytes(), before)
        self.assertIn(UNRELATED, actual)
        for fork in FORKS:
            self.assertNotIn(source(fork), actual)
            self.assertIn(f'checksum = "{fork[4]}"', actual)
            self.assertIn(f'name = "{fork[0]}"\nversion = "{fork[1]}"', actual)
        self.assertEqual(actual.count(f'source = "{REGISTRY}"'), 3)
        self.assertIn(f'chrono 0.4.44 ({REGISTRY})', actual)

    def test_rejects_foreign_version_source_and_resolved_commit(self):
        original = self.lock
        for fork in FORKS:
            mutations = (
                (f'version = "{fork[1]}"', 'version = "99.0.0"'),
                (source(fork), source(fork).replace("PavelLizunov", "foreign")),
                (source(fork), source(fork).rsplit("#", 1)[0] + "#" + "0" * 40),
                (source(fork), source(fork).replace("?rev=" + fork[3], "?rev=" + "0" * 40)),
            )
            for old, new in mutations:
                with self.subTest(crate=fork[0], replacement=new):
                    self.lock = original.replace(old, new)
                    self.write_fixture()
                    self.assert_rejected()

    def test_rejects_patch_drift_missing_patch_and_short_revision(self):
        original = self.manifest
        for fork in FORKS:
            line = f'{fork[0]} = {{ git = "{fork[2]}", rev = "{fork[3]}" }}\n'
            for replacement in ("", line.replace(fork[3], "0" * 40),
                                line.replace(fork[3], fork[3][:7]),
                                line.replace("PavelLizunov", "foreign")):
                with self.subTest(crate=fork[0], replacement=replacement):
                    self.manifest = original.replace(line, replacement)
                    self.write_fixture()
                    self.assert_rejected()

    def test_rejects_missing_and_duplicate_fork_packages(self):
        original = self.lock
        for fork in FORKS:
            block = next(block for block in original.split('[[package]]')
                         if f'name = "{fork[0]}"' in block)
            package = '[[package]]' + block
            for mutated in (original.replace(package, ''), original + package):
                with self.subTest(crate=fork[0], duplicate=mutated.endswith(package)):
                    self.lock = mutated
                    self.write_fixture()
                    self.assert_rejected()

    def test_rejects_malformed_inputs_before_writing(self):
        for filename in ("Cargo.toml", "Cargo.lock"):
            with self.subTest(filename=filename):
                self.write_fixture()
                (self.root / filename).write_text('[[this is invalid TOML')
                self.assert_rejected()

    def test_rejects_unrecorded_package_from_owned_repository_at_another_revision(self):
        original = self.lock
        for fork in FORKS:
            for suffix in ("", ".git"):
                with self.subTest(crate=fork[0], suffix=suffix):
                    foreign_revision = "0" * 40
                    extra = (f'[[package]]\nname = "unrecorded-date-helper"\n'
                             f'version = "1.0.0"\nsource = "git+{fork[2]}{suffix}'
                             f'?rev={foreign_revision}#{foreign_revision}"\n')
                    self.lock = original + extra
                    self.write_fixture()
                    self.assert_rejected()

    def test_command_has_exact_ignored_ids_and_blocks_informational_findings(self):
        command = self.subject.audit_command(self.root, self.output)
        self.assertEqual(command[:2], ["cargo", "audit"])
        self.assertEqual(command[command.index("--file") + 1], str(self.output))
        ignored = [command[i + 1] for i, token in enumerate(command) if token == "--ignore"]
        self.assertCountEqual(ignored, [BASELINE, *MAINTENANCE])
        denied = [command[i + 1] for i, token in enumerate(command) if token == "--deny"]
        self.assertTrue({"warnings", "unmaintained", "unsound"}.issubset(denied))
        self.assertNotIn(NEW_ADVISORY, command)

    def test_cli_prepare_only_needs_no_external_tool(self):
        fixture_script = self.root / "scripts/audit-date-forks.py"
        fixture_script.parent.mkdir()
        shutil.copyfile(SCRIPT, fixture_script)
        env = dict(os.environ, PATH="")
        result = subprocess.run(
            [sys.executable, str(fixture_script), "--output", str(self.output), "--prepare-only"],
            cwd=self.root, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.output.is_file())
        self.assertEqual((self.root / "Cargo.lock").read_text(), self.lock)

    @unittest.skipUnless(os.environ.get("CI") and shutil.which("cargo-audit"),
                         "hosted CI with cargo-audit is required")
    def test_real_audit_blocks_new_inherited_chrono_vulnerability(self):
        db = self.root / "advisory-db"
        advisory = db / "crates/chrono" / (NEW_ADVISORY + ".md")
        advisory.parent.mkdir(parents=True)
        advisory.write_text('''```toml
[advisory]
id = "RUSTSEC-2026-9999"
package = "chrono"
date = "2026-01-01"
url = "https://example.com/chrono-probe"

[versions]
patched = []
unaffected = ["< 0.4.44", "> 0.4.44"]
```

# Synthetic inherited vulnerability probe

This local test advisory deliberately affects chrono 0.4.44.
''')
        for args in (["init", "--quiet"], ["add", "."],
                     ["-c", "user.name=Specification Test", "-c",
                      "user.email=spec@example.invalid", "commit", "--quiet", "-m", "probe"]):
            subprocess.run(["git", *args], cwd=db, check=True, capture_output=True)
        self.subject.prepare_lock(self.root, self.output)
        command = self.subject.audit_command(self.root, self.output)
        result = subprocess.run(command + ["--db", str(db), "--no-fetch"],
                                cwd=self.root, env=dict(os.environ, CARGO_NET_OFFLINE="true"),
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(NEW_ADVISORY, result.stdout + result.stderr)
        self.assertEqual((self.root / "Cargo.lock").read_text(), self.lock)


if __name__ == "__main__":
    unittest.main()
