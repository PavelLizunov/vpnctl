#!/usr/bin/env python3
"""Build a trusted VPNRouter source catalog from committed Git blobs.

The operator supplies a manifest with an exact 40-hex release commit,
supported platform/architecture pairs and the selected source ranges. This
tool reads those paths from the commit with `git cat-file`, ignoring replace
refs and accepting only regular committed files; it never reads the working
tree, the network or the assistant provider. The output is a catalog that
vpnctld can load from a root-owned service path.

Manifest schema:

    {
      "schema": 1,
      "releases": [{
        "version": "2.51.0-r2",
        "commit": "<40 lowercase hex>",
        "targets": [{"platform": "windows", "arch": "x64"}],
        "excerpts": [{
          "path": "VPNRouter.Core/Services/Example.cs",
          "first": 15,
          "last": 23,
          "areas": ["routing", "startup"],
          "signals": ["tun_busy"],
          "faults": ["network"]
        }]
      }]
    }

The optional `areas`, `signals` and `faults` selectors use the same values as
the `/step` crash enums. They are copied into the catalog so vpnctld can rank
excerpts for the observed crash. An excerpt without selectors is a fallback;
an excerpt with selectors is not sent when none of them match.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_CATALOG_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_BLOB_BYTES = 1024 * 1024
MAX_RELEASES = 64
MAX_TARGETS = 8
MAX_EXCERPTS = 24
MAX_EXCERPT_LINES = 48
MAX_EXCERPT_BYTES = 4096
PLATFORMS = {"windows", "linux", "macos"}
ARCHITECTURES = {"x64", "arm64"}
FAULTS = {
    "unknown",
    "null_reference",
    "invalid_operation",
    "io",
    "access_denied",
    "out_of_memory",
    "network",
    "configuration",
    "native",
}
AREAS = {"unknown", "ui", "startup", "routing", "settings"}
SIGNALS = {"none", "proxy_unreachable", "tun_busy", "stop_unconfirmed"}
SELECTORS = (("areas", AREAS), ("signals", SIGNALS), ("faults", FAULTS))


class CatalogError(ValueError):
    pass


def fail(message: str) -> None:
    raise CatalogError(message)


def valid_version(version: object) -> bool:
    if not isinstance(version, str) or not version or len(version) > 32:
        return False
    core, separator, revision = version.partition("-r")
    if "-" in core or (separator and (not revision or len(revision) > 6)):
        return False
    if separator and not revision.isascii():
        return False
    if separator and not revision.isdigit():
        return False
    components = core.split(".")
    if len(components) != 3:
        return False
    return all(
        0 < len(component) <= 6
        and component.isascii()
        and component.isdigit()
        for component in components
    )


def valid_commit(commit: object) -> bool:
    return (
        isinstance(commit, str)
        and len(commit) == 40
        and all(character in "0123456789abcdef" for character in commit)
    )


def valid_path(path: object) -> bool:
    if not isinstance(path, str) or not 1 <= len(path) <= 200:
        return False
    if not path.startswith(("VPNRouter.Core/", "VPNRouter.App/")):
        return False
    if not path.endswith(".cs") or "\\" in path:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return all(
        component and component not in {".", ".."} and set(component) <= allowed
        for component in path.split("/")
    )


def git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = dict(
        {key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_LAZY_FETCH="1",
        GIT_ALLOW_PROTOCOL="",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_TERMINAL_PROMPT="0",
    )
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
        env=environment,
    )


def verify_commit(repo: Path, commit: str) -> None:
    result = git(repo, "cat-file", "-t", commit)
    if result.returncode != 0 or result.stdout.strip() != b"commit":
        fail(f"commit {commit} is not an exact readable commit in {repo}")


def verify_regular_blob(repo: Path, commit: str, path: str) -> None:
    result = git(repo, "ls-tree", "-z", commit, "--", path)
    if result.returncode != 0:
        fail(f"{path} is not a readable path in commit {commit}")
    records = [record for record in result.stdout.split(b"\0") if record]
    if len(records) != 1:
        fail(f"{path} is not a single committed file")
    info, separator, listed = records[0].partition(b"\t")
    fields = info.split(b" ")
    if (
        not separator
        or listed != path.encode("utf-8")
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        fail(f"{path} is not a regular committed file")


def read_blob(repo: Path, commit: str, path: str) -> list[str]:
    verify_regular_blob(repo, commit, path)
    size = git(repo, "cat-file", "-s", f"{commit}:{path}")
    if size.returncode != 0:
        fail(f"{path} is not a readable path in commit {commit}")
    try:
        blob_size = int(size.stdout.strip())
    except ValueError:
        fail(f"Git returned an invalid blob size for {path}")
    if blob_size > MAX_BLOB_BYTES:
        fail(f"{path} exceeds the {MAX_BLOB_BYTES}-byte blob limit")

    result = git(repo, "cat-file", "blob", f"{commit}:{path}")
    if result.returncode != 0:
        fail(f"{path} is not a readable blob in commit {commit}")
    try:
        content = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{path} is not valid UTF-8")

    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def build_excerpt(repo: Path, commit: str, value: object) -> dict[str, object]:
    required = {"path", "first", "last"}
    allowed = required | {name for name, _ in SELECTORS}
    if (
        not isinstance(value, dict)
        or not required <= set(value) <= allowed
    ):
        fail(
            "each excerpt must contain path, first and last, with optional "
            "areas, signals and faults selectors"
        )
    path = value["path"]
    first = value["first"]
    last = value["last"]
    if not valid_path(path):
        fail(f"invalid source path: {path!r}")
    if (
        not isinstance(first, int)
        or isinstance(first, bool)
        or not isinstance(last, int)
        or isinstance(last, bool)
    ):
        fail(f"{path}: first and last must be integers")
    if first < 1 or last < first:
        fail(f"{path}: invalid inclusive line range {first}..{last}")
    if last - first + 1 > MAX_EXCERPT_LINES:
        fail(f"{path}: excerpt exceeds {MAX_EXCERPT_LINES} lines")

    lines = read_blob(repo, commit, path)
    if last > len(lines):
        fail(f"{path}: line range {first}..{last} is outside the committed file")
    text = "\n".join(lines[first - 1 : last])
    encoded = text.encode("utf-8")
    if not text or len(encoded) > MAX_EXCERPT_BYTES:
        fail(f"{path}: excerpt exceeds {MAX_EXCERPT_BYTES} UTF-8 bytes")
    if any(
        (ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F)
        and character not in "\n\t"
        for character in text
    ):
        fail(f"{path}: excerpt contains a control character")

    output: dict[str, object] = {
        "path": path,
        "first": first,
        "last": last,
        "text": text,
    }
    for name, known in SELECTORS:
        selectors = value.get(name, [])
        if not isinstance(selectors, list):
            fail(f"{path}: {name} must be a list")
        if any(
            not isinstance(selector, str) or selector not in known
            for selector in selectors
        ):
            fail(f"{path}: invalid {name} selector")
        if len(set(selectors)) != len(selectors):
            fail(f"{path}: duplicate {name} selector")
        if selectors:
            output[name] = selectors
    return output


def build_catalog(repo: Path, manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "releases"}:
        fail("manifest must contain exactly schema and releases")
    if type(manifest["schema"]) is not int or manifest["schema"] != 1:
        fail("unsupported manifest schema")
    releases = manifest["releases"]
    if not isinstance(releases, list) or not 1 <= len(releases) <= MAX_RELEASES:
        fail(f"manifest releases must be a list of 1..{MAX_RELEASES} entries")

    seen_builds: set[tuple[str, str, str, str]] = set()
    output_releases = []
    for release in releases:
        if not isinstance(release, dict) or set(release) != {
            "version",
            "commit",
            "targets",
            "excerpts",
        }:
            fail("each release must contain exactly version, commit, targets and excerpts")
        version = release["version"]
        commit = release["commit"]
        if not valid_version(version):
            fail(f"invalid release version: {version!r}")
        if not valid_commit(commit):
            fail(f"invalid release commit: {commit!r}")
        verify_commit(repo, commit)

        targets = release["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
            fail(f"{version}: targets must contain 1..{MAX_TARGETS} entries")
        output_targets = []
        seen_targets = set()
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"platform", "arch"}:
                fail(f"{version}: each target must contain exactly platform and arch")
            platform = target["platform"]
            arch = target["arch"]
            if not isinstance(platform, str) or platform not in PLATFORMS:
                fail(f"{version}: unsupported platform")
            if not isinstance(arch, str) or arch not in ARCHITECTURES:
                fail(f"{version}: unsupported target {platform!r}/{arch!r}")
            if (platform, arch) in seen_targets:
                fail(f"{version}: duplicate target {platform}/{arch}")
            seen_targets.add((platform, arch))
            build = (version, commit, platform, arch)
            if build in seen_builds:
                fail(f"{version}: duplicate build mapping for {platform}/{arch}")
            seen_builds.add(build)
            output_targets.append({"platform": platform, "arch": arch})

        excerpts = release["excerpts"]
        if not isinstance(excerpts, list) or not 1 <= len(excerpts) <= MAX_EXCERPTS:
            fail(f"{version}: excerpts must contain 1..{MAX_EXCERPTS} entries")
        seen_excerpts = set()
        output_excerpts = []
        for excerpt in excerpts:
            output = build_excerpt(repo, commit, excerpt)
            key = (output["path"], output["first"], output["last"])
            if key in seen_excerpts:
                fail(f"{version}: duplicate excerpt {key[0]} {key[1]}..{key[2]}")
            seen_excerpts.add(key)
            output_excerpts.append(output)

        output_releases.append(
            {
                "version": version,
                "commit": commit,
                "targets": output_targets,
                "excerpts": output_excerpts,
            }
        )

    return {"schema": 1, "releases": output_releases}


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate manifest field")
        result[key] = value
    return result


def scan_excerpts(catalog: dict) -> None:
    source = "\n".join(
        excerpt["text"]
        for release in catalog["releases"]
        for excerpt in release["excerpts"]
    )
    # Use the scanner's default rules, independent of the checkout and operator config.
    with tempfile.TemporaryDirectory() as directory:
        scan = subprocess.run(
            ["gitleaks", "stdin", "--redact", "--no-banner", "--ignore-gitleaks-allow"],
            cwd=directory,
            env={key: value for key, value in os.environ.items() if not key.startswith("GITLEAKS_")},
            input=source.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if scan.returncode:
        fail("source disclosure scan failed; review the selected ranges before publishing")


def write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(payload)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a trusted VPNRouter source catalog from committed Git blobs."
    )
    parser.add_argument("--repo", required=True, type=Path, help="VPNRouter Git checkout")
    parser.add_argument("--manifest", required=True, type=Path, help="excerpt manifest JSON")
    parser.add_argument(
        "--output",
        required=True,
        help="catalog path, or - for standard output",
    )
    arguments = parser.parse_args()

    try:
        with arguments.manifest.open("rb") as manifest_file:
            manifest_bytes = manifest_file.read(MAX_MANIFEST_BYTES + 1)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            fail(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=unique_object)
        catalog = build_catalog(arguments.repo.resolve(), manifest)
        payload = (
            json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_CATALOG_BYTES:
            fail(f"catalog exceeds {MAX_CATALOG_BYTES} bytes")
        scan_excerpts(catalog)
    except (CatalogError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if arguments.output == "-":
        sys.stdout.buffer.write(payload)
        return 0

    output = Path(arguments.output)
    try:
        write_atomic(output, payload)
    except OSError as error:
        print(f"error: cannot write {output}: {error}", file=sys.stderr)
        return 2

    digest = hashlib.sha256(payload).hexdigest()
    print(
        f"wrote {output} ({len(payload)} bytes, {len(catalog['releases'])} releases, "
        f"sha256 {digest})",
        file=sys.stderr,
    )
    print(
        "install root:root 0644 and restart vpnctld; do not add private data",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
