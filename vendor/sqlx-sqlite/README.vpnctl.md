# SQLx SQLite security dependency backport

This directory contains the published `sqlx-sqlite` **0.8.6** crate from
<https://static.crates.io/crates/sqlx-sqlite/sqlx-sqlite-0.8.6.crate>.
The archive's SHA-256, checked against `Cargo.lock` before extraction, is:

```text
c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea
```

Its recorded upstream revision is
`bab1b022bd56a64f9a08b46b36b97c5cff19d77e`, path `sqlx-sqlite`, in
<https://github.com/launchbadge/sqlx>. `LICENSE-MIT` and `LICENSE-APACHE`
are retained unchanged. All 51 Rust source files are byte-for-byte identical
to the verified archive; the original manifest remains in `Cargo.toml.orig`.

The only upstream-file change is the `Cargo.toml` dependency requirement for
`libsqlite3-sys`: `0.30.1` → `0.39.1`. This selects the patched SQLite release
for RUSTSEC-2026-0459; `Cargo.lock` pins 0.39.1 (bundled SQLite 3.54.1).
No advisory is suppressed and no application database migration is added.

Upstream [PR #4502](https://github.com/launchbadge/sqlx/pull/4502), merged as
`10462fa4414c6c7f1ed1d39bb31678e3b726878c`, independently permits the same
0.39.x FFI series, but belongs to SQLx 0.9.0 with Rust 1.94 and a different
`sqlx-core` API. This backport preserves the application's SQLx 0.8.6 API and
raises the FFI minimum to the patched version. The vendored crate is excluded
from workspace membership so workspace formatting and lint policy do not
rewrite upstream dependency code.

Remove this patch when a published, compatible SQLx release supports a patched
SQLite dependency. Before changing or removing it, run the workspace gates,
inventory tests including backup/restore, SSH suites, and `cargo deny check`.
