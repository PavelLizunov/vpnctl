# SQLx SQLite security backport

`sqlx-sqlite/` is the published `sqlx-sqlite 0.8.6` crate from crates.io.
Archive SHA-256:
`c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea`.
Upstream commit: `bab1b022bd56a64f9a08b46b36b97c5cff19d77e` (`v0.8.6`).

The only changes to the 56 upstream files are the `libsqlite3-sys` requirement
in `Cargo.toml` and `Cargo.toml.orig`: `0.30.1` becomes `=0.39.1`.
All Rust source, licensing and provenance files remain byte-identical to the
official archive. This third-party dependency is excluded from workspace
membership; do not reformat it or apply vpnctl's source lints to upstream code.
`sqlx-sqlite-upstream-sha256.json` records each upstream file's hash; the Python
regression suite permits only the two documented dependency-line substitutions.
The scoped Git whitespace attribute preserves upstream's existing documentation
whitespace rather than modifying the verified source snapshot.

`libsqlite3-sys 0.39.1` bundles SQLite 3.54.1 and resolves
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).
Its archive SHA-256 is
`14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3`.
SQLx upstream allows this SQLite generation in
[PR #4502](https://github.com/transact-rs/sqlx/pull/4502), but its published
0.8.6 and 0.9.0 releases do not. Keeping the 0.8.6 Rust sources preserves the
existing SQLx API and migrations while updating the vulnerable C library.

Remove this patch when a reviewed published SQLx release supports the fixed
bundled SQLite. Re-run inventory, migration/restore, SSH and static-musl gates
before acceptance; see `docs/specs/dependency-security-remediation.md`.
