#!/usr/bin/env python3
"""Project Map Generator for vpnctl.

Scans workspace metadata, tracked Rust source lines of code (LOC),
workspace crates and targets, SQLite migrations, and daemon HTTP routes
to emit a deterministic Markdown codebase inventory.

Usage:
    python3 scripts/project-map.py          # Write to docs/CODEBASE_INVENTORY.md
    python3 scripts/project-map.py --check  # Verify docs/CODEBASE_INVENTORY.md is up-to-date
    python3 scripts/project-map.py --stdout # Print generated Markdown to stdout
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any, Dict, List, Tuple


def find_repo_root() -> Path:
    """Resolve repository root directory."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            return Path(out).resolve()
    except Exception:
        pass
    # Fallback based on script location
    return Path(__file__).resolve().parent.parent


def get_tracked_files(repo_root: Path) -> List[str]:
    """Get all git-tracked files relative to repo root."""
    try:
        out = subprocess.check_output(
            ["git", "ls-files", "--cached"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return sorted(
            line.strip()
            for line in out.splitlines()
            if line.strip() and (repo_root / line.strip()).is_file()
        )
    except Exception:
        # Fallback to filesystem scan excluding VCS / build artifacts
        tracked = []
        for root, dirs, files in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in {".git", "target", ".cargo", "node_modules"}]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), repo_root)
                tracked.append(rel)
        return sorted(tracked)


def get_workspace_crates(repo_root: Path) -> List[Dict[str, Any]]:
    """Query cargo metadata or fallback to Cargo.toml parsing."""
    crates: List[Dict[str, Any]] = []

    # Try cargo metadata first
    try:
        res = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(res.stdout)
        for pkg in data.get("packages", []):
            manifest_path = Path(pkg["manifest_path"]).resolve()
            rel_manifest = manifest_path.relative_to(repo_root)
            crate_path = str(rel_manifest.parent)
            if crate_path == ".":
                crate_path = ""

            targets_info = []
            for tgt in pkg.get("targets", []):
                kinds = tgt.get("kind", [])
                kind_name = kinds[0] if kinds else "unknown"
                targets_info.append({
                    "name": tgt.get("name", ""),
                    "kind": kind_name,
                    "src_path": tgt.get("src_path", ""),
                })

            crates.append({
                "name": pkg["name"],
                "version": pkg["version"],
                "path": crate_path,
                "targets": targets_info,
            })
    except Exception:
        # Fallback to direct Cargo.toml parsing
        root_toml_path = repo_root / "Cargo.toml"
        if root_toml_path.exists():
            with open(root_toml_path, "rb") as f:
                root_toml = tomllib.load(f)
            ws = root_toml.get("workspace", {})
            members = ws.get("members", [])
            ws_pkg_ver = ws.get("package", {}).get("version", "0.0.0")

            for member in members:
                cpath = repo_root / member / "Cargo.toml"
                if not cpath.exists():
                    continue
                with open(cpath, "rb") as cf:
                    cdata = tomllib.load(cf)
                pkg = cdata.get("package", {})
                name = pkg.get("name", member)
                ver = pkg.get("version", ws_pkg_ver)
                if isinstance(ver, dict) and ver.get("workspace"):
                    ver = ws_pkg_ver

                targets_info = []
                mdir = repo_root / member
                if (mdir / "src" / "lib.rs").exists():
                    targets_info.append({"name": name.replace("-", "_"), "kind": "lib", "src_path": str(mdir / "src" / "lib.rs")})
                if (mdir / "src" / "main.rs").exists():
                    targets_info.append({"name": name, "kind": "bin", "src_path": str(mdir / "src" / "main.rs")})
                for test_file in sorted((mdir / "tests").glob("*.rs") if (mdir / "tests").exists() else []):
                    targets_info.append({"name": test_file.stem, "kind": "test", "src_path": str(test_file)})

                crates.append({
                    "name": name,
                    "version": ver,
                    "path": member,
                    "targets": targets_info,
                })

    return sorted(crates, key=lambda x: x["path"])


def summarize_targets(targets: List[Dict[str, Any]]) -> str:
    """Format targets list into a concise summary string."""
    kinds = [t.get("kind", "") for t in targets]
    has_lib = "lib" in kinds
    bin_count = sum(1 for k in kinds if k == "bin")
    test_count = sum(1 for k in kinds if k == "test")
    example_count = sum(1 for k in kinds if k == "example")
    bench_count = sum(1 for k in kinds if k == "bench")

    parts = []
    if has_lib:
        parts.append("lib")
    if bin_count == 1:
        parts.append("bin")
    elif bin_count > 1:
        parts.append(f"{bin_count} bins")
    if test_count == 1:
        parts.append("1 test")
    elif test_count > 1:
        parts.append(f"{test_count} tests")
    if example_count > 0:
        parts.append(f"{example_count} examples")
    if bench_count > 0:
        parts.append(f"{bench_count} benches")

    return ", ".join(parts) if parts else "none"


def scan_rust_loc(repo_root: Path, tracked_files: List[str], crates: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]]]:
    """Scan tracked Rust files, count lines, and associate with crates."""
    rs_files = [f for f in tracked_files if f.endswith(".rs")]
    file_records = []
    crate_stats: Dict[str, Dict[str, int]] = {
        c["path"]: {"prod_loc": 0, "prod_files": 0, "test_loc": 0, "test_files": 0}
        for c in crates
    }

    for rel_path in rs_files:
        full_path = repo_root / rel_path
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines = sum(1 for _ in f)

        # Match to crate
        matched_crate = None
        for c in crates:
            cpath = c["path"]
            if rel_path == cpath or rel_path.startswith(cpath + "/"):
                matched_crate = cpath
                break

        is_test = "/tests/" in rel_path or rel_path.endswith("_test.rs") or rel_path.endswith("_tests.rs")

        file_records.append({
            "path": rel_path,
            "lines": lines,
            "crate": matched_crate or "other",
            "is_test": is_test,
        })

        if matched_crate and matched_crate in crate_stats:
            if is_test:
                crate_stats[matched_crate]["test_loc"] += lines
                crate_stats[matched_crate]["test_files"] += 1
            else:
                crate_stats[matched_crate]["prod_loc"] += lines
                crate_stats[matched_crate]["prod_files"] += 1

    return file_records, crate_stats


def scan_migrations(repo_root: Path, tracked_files: List[str]) -> List[Dict[str, Any]]:
    """Scan SQLite migration files in crates/inventory/migrations/."""
    migration_files = sorted(
        [f for f in tracked_files if f.startswith("crates/inventory/migrations/") and f.endswith(".sql")]
    )
    migrations = []
    for mf in migration_files:
        full_path = repo_root / mf
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines = sum(1 for _ in f)

        filename = os.path.basename(mf)
        match = re.match(r"^(\d+)_?(.*)\.sql$", filename)
        if match:
            num = match.group(1)
            name = match.group(2).replace("_", " ")
        else:
            num = "-"
            name = filename

        migrations.append({
            "version": num,
            "name": name,
            "file": mf,
            "lines": lines,
        })
    return migrations


def scan_routes(repo_root: Path) -> List[Dict[str, str]]:
    """Scan literal `.route(...)` registrations from daemon/src/app.rs."""
    app_rs = repo_root / "daemon/src/app.rs"
    if not app_rs.exists():
        return []

    text = app_rs.read_text(encoding="utf-8", errors="replace")
    routes: List[Dict[str, str]] = []

    pos = 0
    while True:
        idx = text.find(".route(", pos)
        if idx == -1:
            break
        depth = 0
        start = idx + len(".route(")
        end = start
        for i in range(start, len(text)):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                if depth == 0:
                    end = i
                    break
                depth -= 1
        call_args = text[start:end].strip()
        pos = end + 1

        str_match = re.match(r'\"([^\"]+)\"\s*,\s*(.*)', call_args, re.DOTALL)
        if str_match:
            path = str_match.group(1)
            raw_handler = str_match.group(2)
            lines = [re.sub(r"//.*", "", l) for l in raw_handler.splitlines()]
            clean = " ".join(" ".join(lines).split()).rstrip(",")

            found = False
            for m in re.finditer(
                r"(get|post|put|delete|patch|head|options|trace)\s*\(\s*([a-zA-Z0-9_:]+)\s*\)",
                clean,
            ):
                routes.append({
                    "method": m.group(1).upper(),
                    "path": path,
                    "handler": m.group(2),
                })
                found = True
            if not found:
                routes.append({
                    "method": "ANY",
                    "path": path,
                    "handler": clean,
                })

    return sorted(routes, key=lambda r: (r["path"], r["method"], r["handler"]))


def generate_project_map_markdown(
    repo_root: Path,
    tracked_files: List[str],
    crates: List[Dict[str, Any]],
    file_records: List[Dict[str, Any]],
    crate_stats: Dict[str, Dict[str, int]],
    migrations: List[Dict[str, Any]],
    routes: List[Dict[str, str]],
) -> str:
    """Render deterministic Markdown project map."""
    total_prod_loc = sum(cs["prod_loc"] for cs in crate_stats.values())
    total_prod_files = sum(cs["prod_files"] for cs in crate_stats.values())
    total_test_loc = sum(cs["test_loc"] for cs in crate_stats.values())
    total_test_files = sum(cs["test_files"] for cs in crate_stats.values())
    total_rust_loc = total_prod_loc + total_test_loc
    total_rust_files = total_prod_files + total_test_files

    out: List[str] = []
    out.append("# Codebase Inventory & Project Map")
    out.append("")
    out.append("<!-- Generated deterministically by scripts/project-map.py. Do not edit directly. -->")
    out.append("")
    out.append("## Overview")
    out.append("")
    out.append(f"- **Workspace Crates:** {len(crates)}")
    out.append(f"- **Tracked Rust Files:** {total_rust_files} ({total_prod_files} prod / {total_test_files} test)")
    out.append(f"- **Total Rust LOC:** {total_rust_loc:,} ({total_prod_loc:,} prod / {total_test_loc:,} test)")
    out.append(f"- **Database Migrations:** {len(migrations)}")
    out.append(f"- **`daemon/src/app.rs` `.route(...)` Registrations:** {len(routes)}")
    out.append("")

    out.append("## Workspace Crates & Targets")
    out.append("")
    out.append("| Crate | Path | Version | Targets | Prod LOC (Files) | Test LOC (Files) | Total LOC |")
    out.append("|---|---|---|---|---|---|---|")

    for c in crates:
        cpath = c["path"]
        st = crate_stats.get(cpath, {"prod_loc": 0, "prod_files": 0, "test_loc": 0, "test_files": 0})
        t_loc = st["prod_loc"] + st["test_loc"]
        targets_summary = summarize_targets(c["targets"])
        out.append(
            f"| `{c['name']}` | `{cpath}` | {c['version']} | {targets_summary} | "
            f"{st['prod_loc']:,} ({st['prod_files']}) | {st['test_loc']:,} ({st['test_files']}) | **{t_loc:,}** |"
        )

    out.append(
        f"| **Total** | | | | **{total_prod_loc:,} ({total_prod_files})** | "
        f"**{total_test_loc:,} ({total_test_files})** | **{total_rust_loc:,}** |"
    )
    out.append("")

    out.append("## Largest Rust Modules (Top 25)")
    out.append("")
    out.append("| File | LOC | Crate | Role |")
    out.append("|---|---|---|---|")

    top_files = sorted(file_records, key=lambda x: x["lines"], reverse=True)[:25]
    for rec in top_files:
        role = "Test" if rec["is_test"] else "Prod"
        out.append(f"| `{rec['path']}` | {rec['lines']:,} | `{rec['crate']}` | {role} |")
    out.append("")

    out.append(f"## Database Migrations ({len(migrations)})")
    out.append("")
    out.append("| Version | Migration Name | File | Lines |")
    out.append("|---|---|---|---|")
    for m in migrations:
        out.append(f"| `{m['version']}` | {m['name']} | `{m['file']}` | {m['lines']} |")
    out.append("")

    out.append(f"## `daemon/src/app.rs` `.route(...)` Registrations ({len(routes)})")
    out.append("")
    out.append("| Method | Path | Handler |")
    out.append("|---|---|---|")
    for r in routes:
        out.append(f"| `{r['method']}` | `{r['path']}` | `{r['handler']}` |")
    out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic project map and codebase inventory.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare generated inventory against target file and exit non-zero if different.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Emit generated inventory Markdown to stdout.",
    )
    args = parser.parse_args()

    repo_root = find_repo_root()
    output_rel = "docs/CODEBASE_INVENTORY.md"
    output_path = repo_root / output_rel

    tracked_files = get_tracked_files(repo_root)
    crates = get_workspace_crates(repo_root)
    file_records, crate_stats = scan_rust_loc(repo_root, tracked_files, crates)
    migrations = scan_migrations(repo_root, tracked_files)
    routes = scan_routes(repo_root)

    markdown = generate_project_map_markdown(
        repo_root=repo_root,
        tracked_files=tracked_files,
        crates=crates,
        file_records=file_records,
        crate_stats=crate_stats,
        migrations=migrations,
        routes=routes,
    )

    if args.stdout:
        sys.stdout.write(markdown)
        return 0

    if args.check:
        if not output_path.exists():
            sys.stderr.write(f"Error: Output file {output_rel} does not exist.\n")
            return 1

        current_content = output_path.read_text(encoding="utf-8")
        if current_content != markdown:
            diff = difflib.unified_diff(
                current_content.splitlines(keepends=True),
                markdown.splitlines(keepends=True),
                fromfile=f"a/{output_rel}",
                tofile=f"b/{output_rel}",
            )
            sys.stderr.write(f"Error: {output_rel} is out of date.\n")
            sys.stderr.writelines(diff)
            sys.stderr.write(f"\nRun `just project-map` or `python3 {os.path.relpath(__file__, repo_root)}` to regenerate.\n")
            return 1

        print(f"✔ {output_rel} is up-to-date")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    print(f"✔ Generated {output_rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
