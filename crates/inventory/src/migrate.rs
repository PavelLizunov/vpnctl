//! Pure parsers + planner for **`vpnctl migrate from-bash`** (Phase C-5).
//!
//! Lives in the inventory crate because the OUTPUT is an inventory
//! shape (`Server`, `User`, secrets HashMap, grants list). The CLI
//! orchestrates the SSH I/O — *this* module never reads files or
//! talks to a network. That separation makes the whole pipeline
//! unit-testable with fixtures (see `tests/fixtures/bash_migration/`).
//!
//! # Why "additive" matters
//!
//! The bash project (`/home/user/vpn-control/`) is the live source of
//! truth for ~20 phones on production server `104.194.156.93`. Pavel's
//! constraint at C-5 kick-off was «важно сейчас не уранить vpn не
//! одному из пользователей». So this module's planner deliberately
//! produces ZERO writes to the bash server — it ONLY tells vpnctl
//! "here's what I see; copy these rows into your DB". The bash side
//! keeps serving traffic; vpnctl gains read-only visibility + the
//! ability to mint new `sub_token`s + monitor /sub access without
//! touching the production node.
//!
//! Re-running `vpnctl deploy <bash-server>` AFTER migration *would*
//! cause a takeover (vpnctl would overwrite config.json with its own
//! rendering — possibly missing legacy quirks like the second VLESS
//! inbound on :2083). The migration tool does NOT run deploy; the
//! operator does that manually when ready to flip ownership.
//!
//! # What we import vs skip
//!
//! From `104.194.156.93` recon (2026-05-17):
//!
//! | Population | Count | Action |
//! |---|---|---|
//! | VLESS users in `vless-reality-in` inbound | 23 | ✅ import as `User { uuid, tuic_password: ... }` |
//! | TUIC users in `tuic-in` inbound | 9 | usually empty intersection with VLESS — see policy below |
//! | Second VLESS inbound (e.g. `vless-reality-2083`) | 1 inbound | ⏭ skip — vpnctl's `Server` model has one port per protocol |
//! | Legacy per-device TUIC tokens (`brat-pc`, `brat-mac`, …) | 9 | ⏭ skip — pre-unified scheme |
//!
//! **User-merging policy**:
//!   * Same name in BOTH inbounds with the SAME UUID → unified vpnctl
//!     `User` with both VLESS uuid + tuic_password set.
//!   * Same name with DIFFERENT UUIDs (split-identity, e.g. legacy
//!     server `93.95.226.167` where bash generated per-protocol
//!     UUIDs) → import VLESS-only (no `tuic_password` for that user),
//!     emit a non-fatal warning into `plan.warnings`, AND push a
//!     `SkippedUser` for the TUIC half so dry-run output lists every
//!     non-imported entity in one place. Bash continues serving the
//!     TUIC traffic to phones that already hold the bash-scanned
//!     TUIC link — vpnctl just won't mint a *new* TUIC link for that
//!     user. Previously this case was a fatal `Err`; that proved too
//!     strict — see commit history for context.
//!   * TUIC name with no VLESS counterpart → `SkippedUser` with
//!     reason "tuic-only legacy" (these were per-device tokens
//!     like `brat-pc`, `brat-mac` from the pre-unified scheme).
//!
//! # share_link byte-equality (THE invariant)
//!
//! Old phones already hold `vless://<UUID>@<ip>:443?...#<name>`
//! links scanned from bash. After migration vpnctl's
//! `VlessReality::share_link` MUST produce IDENTICAL bytes. The
//! GO/NO-GO live check was done at C-5 kick-off (real `main-brat`
//! UUID on real 104 secrets) — 238 bytes, byte-identical. The
//! regression net is in `crates/protocols/tests/spec_share_link_byte_equality.rs`.

mod executor;
mod parsers;
mod planner;
mod types;

#[cfg(test)]
mod tests;

pub use executor::apply_migration_plan;
pub use parsers::{parse_bash_inventory_env, parse_bash_singbox};
pub use planner::{build_migration_plan, derive_server_id_from_ip};
pub use types::{
    BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser, MigrationOutcome,
    MigrationPlan, SkippedUser,
};
