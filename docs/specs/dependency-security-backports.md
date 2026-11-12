# Dependency security backports

## Intent & Invariants

Resolve RUSTSEC-2026-0459 and RUSTSEC-2026-0495 without suppressing advisories,
changing SQLx's public API, or changing inventory schemas or client artefacts.
Keep SQLx at 0.8.6; its published SQLite driver cannot select patched
`libsqlite3-sys`, and SQLx 0.9 requires a separate API/toolchain migration.

## Interface/Data contract

- Patch only `sqlx-sqlite` with its checksum-verified 0.8.6 crate archive;
  retain licenses and record source, checksum, and removal condition alongside
  it. Its Rust sources must remain byte-identical to the upstream archive.
- Change only the driver's FFI requirement to `libsqlite3-sys` 0.39.1;
  commit the resolved lockfile. The application's `sqlite` feature must still
  use bundled SQLite, including the static musl release build.
- Exclude the vendored driver from workspace membership; leave SQLx's other
  packages at 0.8.6. Existing databases, migrations, transactions, and backup
  and restore behavior must keep working.
- Require russh 0.65.1 or a compatible patched release; adapt in-process test
  handlers to its verified-public-key callback without changing SSH behavior.
  Do not raise the workspace's declared Rust version for this dependency bump:
  the previously selected russh release already required Rust 1.89.

## Verification checklist

- [ ] Verify archive SHA-256, retained licenses, unchanged upstream Rust files,
      and the vendor's absence from `cargo metadata` workspace members.
- [ ] Check lockfile changes are confined to the two security updates and
      their necessary dependency resolution; `cargo deny check` passes.
- [ ] Run `cargo fmt --all`, all canonical workspace gates, inventory tests
      including backup/restore, and the Docker-backed SSH suites.
- [ ] Verify the static musl release links with the bundled patched SQLite.
