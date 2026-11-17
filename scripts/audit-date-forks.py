#!/usr/bin/env python3
"""Keep crates.io advisory coverage for the two maintained date-library forks."""

import argparse
from datetime import date, datetime, timezone
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.parse import urlsplit


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
BASES = {
    "chrono": (
        "0.4.44",
        "c673075a2e0e5f4a1dde27ce9dee1ea4558c7ffe648f576438a20ca1d2acc4b0",
    ),
    "chrono-tz": (
        "0.10.4",
        "a6139a8597ed92cf816dfb33f5dd6cf0bb93a6adc938f11039f371bc5bcd26c3",
    ),
}
MAINTENANCE_IDS = {"RUSTSEC-2026-0543", "RUSTSEC-2026-0555"}


def owned_repository(source: str) -> bool:
    if not source.startswith("git+"):
        return False
    url = urlsplit(source[4:])
    path = url.path.rstrip("/").removesuffix(".git").casefold()
    return url.hostname == "github.com" and path in {
        f"/pavellizunov/ninitux-{name}" for name in BASES
    }


def prepare_lock(root: Path, output: Path) -> None:
    """Normalize validated fork identities only; this copy must never be built."""
    source_lock = root / "Cargo.lock"
    if output.resolve() == source_lock.resolve():
        raise ValueError("Audit output must differ from the real lockfile")
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    patches = manifest.get("patch", {}).get("crates-io", {})
    sources = {}
    for name in BASES:
        patch = patches.get(name, {})
        if not isinstance(patch, dict):
            raise ValueError(f"{name}: invalid owned-fork patch")
        repository = f"https://github.com/PavelLizunov/ninitux-{name}"
        revision = patch.get("rev", "")
        if patch.get("git") != repository or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(f"{name}: invalid owned-fork patch")
        sources[name] = f"git+{repository}?rev={revision}#{revision}"

    content = source_lock.read_text()
    tomllib.loads(content)
    blocks = re.split(r"(?m)(?=^\[\[package\]\]$)", content)
    seen = set()
    for index, block in enumerate(blocks):
        packages = tomllib.loads(block).get("package", [])
        if not packages:
            continue
        package = packages[0]
        name = package.get("name")
        if name not in BASES:
            if owned_repository(package.get("source", "")):
                raise ValueError("Unrecorded package from an owned date fork")
            continue
        version, checksum = BASES[name]
        if name in seen or package.get("version") != version:
            raise ValueError(f"{name}: missing, duplicate or unrecorded base version")
        if package.get("source") != sources[name] or "checksum" in package:
            raise ValueError(f"{name}: lockfile does not match the pinned fork")
        seen.add(name)
        replacement = f'source = "{REGISTRY}"\nchecksum = "{checksum}"'
        blocks[index], count = re.subn(r'^source = "[^"\n]+"$', replacement, block, flags=re.M)
        if count != 1:
            raise ValueError(f"{name}: ambiguous package source")
    if seen != BASES.keys():
        raise ValueError("Both owned date forks must occur exactly once")
    normalized = "".join(blocks)
    for name, source in sources.items():
        version = BASES[name][0]
        normalized = normalized.replace(
            f'"{name} {version} ({source})"',
            f'"{name} {version} ({REGISTRY})"',
        )
    tomllib.loads(normalized)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(normalized)


def audit_command(root: Path, lock: Path) -> list[str]:
    policy = tomllib.loads((root / "deny.toml").read_text())
    ignored = set(MAINTENANCE_IDS)
    for entry in policy.get("advisories", {}).get("ignore", []):
        identifier = entry if isinstance(entry, str) else entry.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", identifier):
            raise ValueError("Invalid advisory policy identifier")
        if isinstance(entry, dict) and "expires" in entry:
            expiry = entry["expires"]
            if isinstance(expiry, str):
                expiry = date.fromisoformat(expiry)
            if expiry <= datetime.now(timezone.utc).date():
                raise ValueError("Expired advisory exception")
        ignored.add(identifier)
    command = [
        "cargo", "audit", "--file", str(lock),
        "--deny", "unmaintained", "--deny", "unsound", "--deny", "warnings",
    ]
    for identifier in sorted(ignored):
        command.extend(["--ignore", identifier])
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        prepare_lock(root, args.output)
        if args.prepare_only:
            return 0
        return subprocess.run(audit_command(root, args.output), check=False).returncode
    except (OSError, ValueError) as error:
        parser.exit(2, f"Date-fork advisory check failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
