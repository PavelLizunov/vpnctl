# Dependency security gate remediation

## Intent & Invariants

Restore the dependency gate blocked by RUSTSEC-2026-0459 and RUSTSEC-2026-0495
without hiding advisories. Preserve inventory identities, migration checksums,
client artifacts, SSH behavior, and the static-musl release path. No production
database is opened or migrated for this change.

## Interface / Data contract

- Keep SQLx and its Rust sources at 0.8.6. Patch only the vendored SQLite
  driver's dependency manifests to select `libsqlite3-sys =0.39.1`, bundling
  fixed SQLite 3.54.1. Preserve bundled/static compilation and existing features.
- Verify the complete vendored package against the official archive SHA-256
  documented in `vendor/README.md`; only those two manifest lines may differ.
  Its unchanged third-party Rust sources are not vpnctl workspace members.
- Upgrade russh from 0.64.1 to 0.65.1. Adapt test-server signatures to its
  verified-key callback; production SSH client behavior remains unchanged.
- Align the workspace's declared Rust minimum with russh's existing 1.89
  requirement. No schema or migration edits are needed.
- A runtime regression test must verify that SQLx uses SQLite >=3.54.1, so a
  lockfile-only update cannot falsely appear to remediate the bundled engine.
- Remove the vendor patch after a suitable published SQLx upgrade; track this
  workaround in `BACKLOG.md`.

## Verification checklist

- [ ] Independent review of dependency changes and vendor provenance.
- [ ] Vendor package comparison permits only the two dependency-line edits.
- [ ] `cargo deny check` passes without adding advisory ignores.
- [ ] Runtime SQLite security-floor test, inventory tests and migration/restore
      fixtures pass against isolated databases; backup script regressions pass.
- [ ] Five canonical Cargo commands and `just ci` pass on the candidate.
- [ ] All three Docker-backed SSH suites pass.
- [ ] `just build-release` builds both binaries and neither has an ELF interpreter.
