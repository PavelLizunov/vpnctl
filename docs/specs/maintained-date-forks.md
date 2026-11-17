# Maintained date dependencies

## Intent and ownership

The owner chose Ninitux-maintained forks on 2026-11-17 to retain existing date
APIs and stored formats. PavelLizunov owns maintenance and issue triage through
the fork repositories. Preserve upstream history, MIT OR Apache-2.0 licensing
and authorship. A fork establishes maintenance responsibility; it does not
repair an inherited vulnerability by itself.

| Crate | Base version | Owner repository | Upstream base commit | Registry archive SHA256 |
|---|---|---|---|---|
| chrono | 0.4.44 | https://github.com/PavelLizunov/ninitux-chrono | c14b4599d07ef36ffa1f8a531fb0bc7eb3b42464 | c673075a2e0e5f4a1dde27ce9dee1ea4558c7ffe648f576438a20ca1d2acc4b0 |
| chrono-tz | 0.10.4 | https://github.com/PavelLizunov/ninitux-chrono-tz | e15d1f308a1ac2fdf3f1bf19c325dc202d418081 | a6139a8597ed92cf816dfb33f5dd6cf0bb93a6adc938f11039f371bc5bcd26c3 |

Both initially retain byte-identical published Rust source. chrono is the root
package; chrono-tz is a workspace member using committed generated timezone
data. Regeneration requires the upstream eggert/tz submodule at
7e1145bfdb9630c127841dc8ce808a937a300938; never silently regenerate on deployment.
Apply both crates.io patch overrides to exact full commit IDs, including all
transitive users. Preserve crate names, features and versions. Security fixes
and timezone-data updates require review, provenance updates and compatible
server CI before changing the pinned commits. Review maintenance at least
monthly and on each newly reported advisory; record fixes or explicit findings.

## Advisory coverage contract

Cargo-deny excludes Git sources from crates.io advisory matching. Keep its
normal graph checks and exact source allowlist, then run a mandatory companion
cargo-audit scan of a temporary audit-only copy of the complete Cargo.lock.
Normalize ONLY the two validated owned-fork entries to their recorded registry
versions/checksums, including exact source-qualified dependency references.
Never build from the audit copy or change the real lockfile. Preserve unrelated
entries byte-for-byte. Fail closed on unrecorded packages from these forks,
missing/duplicate fork packages, wrong version/source/commit, missing or
mismatched root patch declarations, malformed input, or audit execution/database
failures. Full 40-character hexadecimal patch revisions must
match the query and resolved commit in each corresponding lockfile source.

Only RUSTSEC-2026-0543 and RUSTSEC-2026-0555 are acknowledged in the companion
scan because maintenance now belongs to these forks. Existing deny.toml ID
exceptions apply unchanged. Every other vulnerability or informational finding
remains blocking; enable cargo-audit unmaintained/unsound warnings as errors.

Script interface for independent tests:
- scripts/audit-date-forks.py exposes prepare_lock(root:Path, output:Path)->None
  and audit_command(root:Path, lock:Path)->list[str].
- prepare_lock raises ValueError for invalid identity/provenance without writing
  or overwriting output. The base package table above is authoritative.
- audit_command returns cargo audit with --file and repeatable --ignore for
  exactly deny.toml advisories.ignore plus the two maintenance IDs, and --deny
  unmaintained plus --deny unsound and --deny warnings. It never invokes a compiler.
- CLI --output PATH --prepare-only prepares without running any external tool;
  otherwise runs the command and propagates its failure exit status. The project
  root is the parent of the script directory, independent of the caller's cwd.

## Verification

Prove normalization preserves the real lockfile and unrelated dependencies,
rejects drift/foreign sources/duplicates, and cannot ignore a newly planted
chrono vulnerability. Run the inherited-advisory probe using the real
cargo-audit binary and a local synthetic advisory DB in hosted CI. No local
compilation, client rebuild or source API migration belongs to this change.
