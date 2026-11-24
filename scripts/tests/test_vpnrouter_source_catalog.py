#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "vpnrouter-source-catalog.py"


@unittest.skipUnless(shutil.which("git"), "requires git")
class SourceCatalogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "VPNRouter"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "user.name", "Synthetic Operator")
        self.source = self.repo / "VPNRouter.Core" / "Services" / "Example.cs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(
            "namespace Synthetic;\n"
            "// line 2\n"
            "// line 3\n"
            "// line 4\n"
            "// line 5\n"
        )
        self.git("add", "VPNRouter.Core/Services/Example.cs")
        self.git("commit", "-qm", "synthetic release")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments):
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def manifest(self, **overrides):
        release = {
            "version": "2.51.0-r2",
            "commit": self.commit,
            "targets": [{"platform": "windows", "arch": "x64"}],
            "excerpts": [
                {
                    "path": "VPNRouter.Core/Services/Example.cs",
                    "first": 2,
                    "last": 4,
                    "areas": ["settings"],
                    "signals": ["none"],
                }
            ],
        }
        release.update(overrides)
        return {"schema": 1, "releases": [release]}

    def generate(self, manifest, *, env=None, raw=None):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_bytes(raw if raw is not None else json.dumps(manifest).encode())
        environment = dict(os.environ)
        if not shutil.which("gitleaks"):
            scanner = self.root / "gitleaks"
            scanner.write_text(
                "#!" + sys.executable + "\nimport sys\n"
                "sys.exit(0 if sys.stdin.read() == '// line 2\\n// line 3\\n// line 4' else 1)\n"
            )
            scanner.chmod(0o700)
            environment["PATH"] = str(self.root) + os.pathsep + environment["PATH"]
        environment.update(env or {})
        output = self.root / "catalog.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo",
                str(self.repo),
                "--manifest",
                str(manifest_path),
                "--output",
                str(output),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, output

    def test_extracts_exact_committed_lines_and_ignores_the_worktree(self):
        self.source.write_text("namespace Dirty;\n// dirty\n// dirty\n// dirty\n")
        result, output = self.generate(self.manifest())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sha256", result.stderr)
        catalog = json.loads(output.read_text())
        self.assertEqual(catalog["schema"], 1)
        self.assertEqual(catalog["releases"][0]["commit"], self.commit)
        self.assertEqual(
            catalog["releases"][0]["targets"],
            [{"platform": "windows", "arch": "x64"}],
        )
        self.assertEqual(
            catalog["releases"][0]["excerpts"][0],
            {
                "path": "VPNRouter.Core/Services/Example.cs",
                "first": 2,
                "last": 4,
                "text": "// line 2\n// line 3\n// line 4",
                "areas": ["settings"],
                "signals": ["none"],
            },
        )

    def test_rejects_out_of_range_lines_and_duplicate_targets(self):
        result, output = self.generate(
            self.manifest(
                excerpts=[
                    {
                        "path": "VPNRouter.Core/Services/Example.cs",
                        "first": 2,
                        "last": 6,
                    }
                ]
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the committed file", result.stderr)
        self.assertFalse(output.exists())

        result, output = self.generate(
            self.manifest(
                targets=[
                    {"platform": "windows", "arch": "x64"},
                    {"platform": "windows", "arch": "x64"},
                ]
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate target", result.stderr)
        self.assertFalse(output.exists())

    def test_ignores_git_replace_refs(self):
        original = self.commit
        self.source.write_text(
            "namespace Replaced;\n"
            "// replaced 2\n"
            "// replaced 3\n"
            "// replaced 4\n"
        )
        self.git("add", "VPNRouter.Core/Services/Example.cs")
        self.git("commit", "-qm", "synthetic replacement")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", original, replacement)

        result, output = self.generate(self.manifest())
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(output.read_text())
        self.assertEqual(
            catalog["releases"][0]["excerpts"][0]["text"],
            "// line 2\n// line 3\n// line 4",
        )

    def test_ignores_ambient_git_repository_and_object_configuration(self):
        missing = str(self.root / "missing")
        result, output = self.generate(
            self.manifest(), env={"GIT_DIR": missing, "GIT_OBJECT_DIRECTORY": missing,
                                  "GIT_CONFIG_COUNT": "garbage"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        excerpt = json.loads(output.read_text())["releases"][0]["excerpts"][0]
        self.assertEqual(excerpt["text"], "// line 2\n// line 3\n// line 4")

    def test_rejects_ambiguous_or_oversized_manifest_before_writing(self):
        for raw in [
            b'{"schema":1,"releases":[]}',
            json.dumps(dict(self.manifest(), schema=True)).encode(),
            b'{"schema":2,' + json.dumps(self.manifest()).encode()[1:],
            bytes([0xff]),
            b" " * (256 * 1024 + 1),
        ]:
            with self.subTest(size=len(raw)):
                result, output = self.generate(None, raw=raw)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(output.exists())

    def test_sensitive_excerpt_preserves_prior_catalog_and_redacts_output(self):
        synthetic = "ghp_" + "AbCdEf0123456789" * 2 + "WxyZ"
        self.source.write_text("// public\n// " + synthetic + "\n// fixture\n// only\n")
        self.git("add", "VPNRouter.Core/Services/Example.cs")
        self.git("commit", "-qm", "scanner fixture")
        prior = self.root / "catalog.json"
        prior.write_bytes(b"prior catalog")
        result, output = self.generate(self.manifest(commit=self.git("rev-parse", "HEAD").strip()))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("disclosure scan failed", result.stderr)
        self.assertNotIn(synthetic, result.stdout + result.stderr)
        self.assertEqual(output.read_bytes(), b"prior catalog")

    def test_rejects_symlink_blobs(self):
        link = self.repo / "VPNRouter.Core" / "Services" / "Link.cs"
        try:
            link.symlink_to("Example.cs")
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable")
        self.git("add", "VPNRouter.Core/Services/Link.cs")
        self.git("commit", "-qm", "synthetic symlink")
        commit = self.git("rev-parse", "HEAD").strip()

        result, output = self.generate(
            self.manifest(
                commit=commit,
                excerpts=[
                    {
                        "path": "VPNRouter.Core/Services/Link.cs",
                        "first": 1,
                        "last": 1,
                    }
                ],
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("regular committed file", result.stderr)
        self.assertFalse(output.exists())

    def test_rejects_unknown_fields_and_unsafe_paths(self):
        manifest = self.manifest()
        manifest["extra"] = True
        result, output = self.generate(manifest)
        self.assertEqual(result.returncode, 2)
        self.assertIn("exactly schema and releases", result.stderr)
        self.assertFalse(output.exists())

        result, output = self.generate(
            self.manifest(
                excerpts=[
                    {
                        "path": "VPNRouter.Core/../Secrets.cs",
                        "first": 1,
                        "last": 1,
                    }
                ]
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid source path", result.stderr)
        self.assertFalse(output.exists())

        result, output = self.generate(
            self.manifest(
                excerpts=[
                    {
                        "path": "VPNRouter.Core/Services/Example.cs",
                        "first": 2,
                        "last": 4,
                        "areas": ["routing", "routing"],
                    }
                ]
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate areas selector", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
