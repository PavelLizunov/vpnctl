use std::collections::HashMap;

use vpnctl_core::{Server, ServerId, User, UserId};

/// Parsed `inventory/<IP>.env` from the bash project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashInventoryEnv {
    pub server_ip: String,
    pub ssh_port: u16,
    pub reality_public: String,
    pub short_id: String,
    /// Comma-split user-name list (operator-managed cache; the server
    /// `config.json` is the actual source of truth for membership).
    pub users: Vec<String>,
}

/// One VLESS user as it appears in `/etc/sing-box/config.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashVlessUser {
    pub name: String,
    pub uuid: String,
    /// `xtls-rprx-vision` in every modern bash deploy. Captured here
    /// for the diagnostic warning if we ever see a divergent flow.
    pub flow: Option<String>,
}

/// One TUIC user. `uuid` MAY differ from the user's VLESS uuid (it
/// did NOT on 104.194.156.93 — different name populations entirely).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashTuicUser {
    pub name: String,
    pub uuid: String,
    pub password: String,
}

/// Parsed view of the bash server's per-protocol material — what
/// the migration tool needs to build a vpnctl `Server` + `User` rows.
#[derive(Clone, Debug, Default)]
pub struct BashSingboxData {
    /// Users in the FIRST `vless-reality-*` inbound (lowest port —
    /// we ignore secondary inbounds like the `2083` fallback).
    pub vless_users: Vec<BashVlessUser>,
    /// Users in the `tuic-in` inbound.
    pub tuic_users: Vec<BashTuicUser>,
    /// Server-side REALITY private key (from `keys.env`). REQUIRED
    /// for vpnctl to render its OWN sing-box config in the future
    /// — but not used by `share_link` (clients only need the public
    /// half + short_id).
    pub reality_private: Option<String>,
}

/// One row in `MigrationPlan::skipped` — why a name we saw in the
/// bash data didn't make it into the vpnctl import set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedUser {
    pub name: String,
    pub reason: String,
}

/// The full per-server plan the CLI prints in `--dry-run` and acts
/// on under `--apply`. Pure data — no I/O.
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    pub server: Server,
    pub server_secrets: HashMap<String, String>,
    /// Users to upsert. Existing `User` rows in inv.db with the same
    /// `id` are NOT overwritten by the plan executor — they're added
    /// to `existing_users_skipped` at apply time. `tuic_password`
    /// reflects the bash mapping; missing if the user has only
    /// VLESS access.
    pub users_to_import: Vec<User>,
    /// `(user_id, server_id)` pairs to grant. Always the new server
    /// times every imported user.
    pub grants: Vec<(UserId, ServerId)>,
    /// Why we didn't import some bash users (legacy TUIC, name
    /// collision with a different uuid, etc).
    pub skipped: Vec<SkippedUser>,
    /// Operator-facing diagnostics that AREN'T fatal but worth a
    /// look — e.g. "ignored secondary VLESS inbound on port 2083".
    pub warnings: Vec<String>,
}

/// Summary line printed by the CLI after `--apply` so the operator
/// can see at a glance "n new + m already-existed + k secrets +
/// p grants". Also written into the audit payload.
#[derive(Clone, Debug, Default)]
pub struct MigrationOutcome {
    pub server_created: bool,
    pub server_already_existed: bool,
    /// `true` when `--overwrite-existing` corrected the existing
    /// server's address/port/user to match the bash inventory.
    pub server_address_updated: bool,
    pub secrets_set: usize,
    pub users_created: usize,
    /// User names that already existed AND were overwritten because
    /// the operator passed `--overwrite-existing` (CLI) / `true` (apply).
    /// Empty when `overwrite_existing=false` (the default).
    pub users_overwritten: Vec<String>,
    /// User names that already existed AND were preserved because
    /// `overwrite_existing=false`. Empty when overwrite mode is on.
    pub users_skipped_existing: Vec<String>,
    pub grants_made: usize,
    /// `"<user>|<server>"` pairs that were restored after a
    /// `remove_user`-cascade in overwrite mode. Empty when
    /// `overwrite_existing=false`. Operator-facing — surfaced in
    /// the audit payload + the CLI summary so it's visible that
    /// the migration preserved cross-server grants the bash
    /// inventory itself didn't know about.
    pub other_server_grants_preserved: Vec<String>,
}
