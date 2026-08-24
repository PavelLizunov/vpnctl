//! Hot snapshots of the inventory DB (`inv.db`) for disaster recovery.
//!
//! # The threat model
//!
//! `192.168.0.236` (the homelab host running vpnctld) is today a
//! single point of failure. If the disk dies, the rootfs is corrupted,
//! or someone `rm -rf`'s `/var/lib/vpnctl/`, every per-user secret
//! (sub-tokens, WG private keys, TUIC passwords) is gone — and every
//! VPN client has to be re-onboarded by hand. CLAUDE.md "Strategic
//! context" calls this out as critical.
//!
//! This module solves the *snapshot* half — making a coherent copy
//! of `inv.db` while the daemon is still writing to it — and the
//! *retention* half (don't fill the disk with hourly snapshots
//! forever). The *off-site* half is operator-driven: the Settings
//! page surfaces each snapshot as a downloadable file; the operator
//! copies it to whatever off-machine target they trust (USB,
//! cloud bucket). That keeps credentials for off-site
//! destinations OUT of the daemon — zero blast radius if the host
//! is compromised.
//!
//! # How the snapshot stays coherent
//!
//! SQLite's `VACUUM INTO 'path'` writes a fresh, fully-checkpointed
//! database file at `path` while honouring the WAL — no readers are
//! blocked, in-flight writes are serialised against the VACUUM via
//! the usual SQLite write lock. The output is a self-contained
//! single-file copy you can drop into another vpnctld instance and
//! it opens immediately.
//!
//! `VACUUM INTO` requires the target file NOT to exist (it refuses
//! to overwrite), which is what we want — never silently clobber.
//! The `snapshot_now` helper uses a timestamped filename so
//! collisions are statistically impossible at the homelab cadence
//! (1 ms resolution).
//!
//! # Why no encryption at this layer
//!
//! Encrypting at the daemon would mean either:
//! 1. The decryption key lives next to the encrypted file on the
//!    same disk (zero benefit — burn the disk, lose both), or
//! 2. The operator memorises / offline-stores the key (high
//!    operational burden, easy to lock yourself out).
//!
//! Neither is right for a single-operator homelab. Instead, we keep
//! the local snapshot in plaintext (same trust boundary as the
//! daemon-owned inv.db itself: `user:user 0640`) and let the
//! operator apply encryption at the off-site step (`age`, `gpg`,
//! filesystem encryption, etc) on whichever target they pick.
//!
//! # Restore
//!
//! Restore is a `vpnctl restore <snapshot>` CLI command (see
//! `cli/src/cmd/restore.rs`). It MUST run while the daemon is
//! stopped — otherwise the daemon's open WAL file would race with
//! the new DB. The CLI command pre-validates the snapshot
//! (opens it, runs a sanity SELECT) before performing the atomic
//! rename, so a corrupt snapshot fails fast.
//!
//! The Settings page surfaces the restore command pre-filled with
//! the snapshot path; the operator copies the command into a
//! terminal (one of the few approved CLI exceptions to the
//! "web-only" rule, because the daemon literally cannot replace
//! its own DB while it's holding it open).

mod listing;
mod restore;
mod retention;
mod snapshot;
mod verify;

#[cfg(test)]
mod tests;

pub use listing::{
    DEFAULT_BACKUP_DIR, SNAPSHOT_FILENAME_PREFIX, SNAPSHOT_FILENAME_SUFFIX, SnapshotInfo,
    list_snapshots, parse_snapshot_filename, snapshot_filename_at,
};
pub use restore::restore_from;
pub use retention::{Retention, prune_snapshots};
pub use snapshot::{snapshot_now, snapshot_to};
pub use verify::{CheckResult, CheckStatus, SelfTestReport, verify_snapshot};
