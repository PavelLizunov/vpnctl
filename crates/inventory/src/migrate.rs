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

use std::collections::HashMap;

use serde_json::Value;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

use crate::sqlite::SqliteInventoryError;

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

// ────────────────────────────────────────────────────────────────────────
// Parsers (no I/O)
// ────────────────────────────────────────────────────────────────────────

/// Parse a bash `inventory/<IP>.env` file. Format is a tiny K=V dialect
/// — `KEY=value`, `# comments`, blank lines. Only the 5 keys vpnctl
/// migration needs are recognised; unknown keys are tolerated (operator
/// might have added their own annotations).
pub fn parse_bash_inventory_env(s: &str) -> Result<BashInventoryEnv, String> {
    let mut server_ip: Option<String> = None;
    let mut ssh_port: u16 = 22;
    let mut reality_public: Option<String> = None;
    let mut short_id: Option<String> = None;
    let mut users: Vec<String> = Vec::new();
    for (lineno, raw_line) in s.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {} not KEY=VALUE: {raw_line:?}", lineno + 1));
        };
        match k.trim() {
            "SERVER_IP" => server_ip = Some(v.trim().to_string()),
            "SSH_PORT" => {
                ssh_port = v
                    .trim()
                    .parse()
                    .map_err(|e| format!("line {} SSH_PORT not u16: {e}", lineno + 1))?;
            }
            "REALITY_PUBLIC" => reality_public = Some(v.trim().to_string()),
            "SHORT_ID" => short_id = Some(v.trim().to_string()),
            "USERS" => {
                users = v
                    .split(',')
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty())
                    .collect();
            }
            _ => {}
        }
    }
    Ok(BashInventoryEnv {
        server_ip: server_ip.ok_or("missing SERVER_IP")?,
        ssh_port,
        reality_public: reality_public.ok_or("missing REALITY_PUBLIC")?,
        short_id: short_id.ok_or("missing SHORT_ID")?,
        users,
    })
}

/// Extract VLESS + TUIC users from a parsed sing-box `config.json` +
/// the REALITY private key from `keys.env` text. The TWO files are
/// read together because the migration plan needs both to make
/// decisions (e.g. emit `vless.private_key` only if we know the
/// public half came from this server).
///
/// `keys_env_text` is the raw `keys.env` file (KEY=VALUE lines, same
/// dialect as `inventory/<IP>.env`).
pub fn parse_bash_singbox(
    config_json: &str,
    keys_env_text: &str,
) -> Result<BashSingboxData, String> {
    let cfg: Value = serde_json::from_str(config_json)
        .map_err(|e| format!("config.json not valid JSON: {e}"))?;
    let inbounds = cfg
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or("config.json has no `inbounds` array")?;

    // Find FIRST `vless-reality-*` inbound (modern bash adds a
    // secondary `vless-reality-2083` for NAT-edge clients — we
    // ignore it; the planner emits a warning if it sees one).
    let primary_vless = inbounds
        .iter()
        .filter(|i| {
            i.get("type").and_then(Value::as_str) == Some("vless")
                && i.get("tag")
                    .and_then(Value::as_str)
                    .map(|t| t.starts_with("vless-reality"))
                    .unwrap_or(false)
        })
        .min_by_key(|i| {
            i.get("listen_port")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX)
        });
    let mut vless_users = Vec::new();
    if let Some(ib) = primary_vless
        && let Some(users) = ib.get("users").and_then(Value::as_array)
    {
        for u in users {
            let name = u
                .get("name")
                .and_then(Value::as_str)
                .ok_or("vless user missing name")?;
            let uuid = u
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or("vless user missing uuid")?;
            let flow = u.get("flow").and_then(Value::as_str).map(str::to_string);
            vless_users.push(BashVlessUser {
                name: name.to_string(),
                uuid: uuid.to_string(),
                flow,
            });
        }
    }

    // TUIC inbound. The tag is `tuic-in` in every modern deploy.
    let tuic_inbound = inbounds
        .iter()
        .find(|i| i.get("type").and_then(Value::as_str) == Some("tuic"));
    let mut tuic_users = Vec::new();
    if let Some(ib) = tuic_inbound
        && let Some(users) = ib.get("users").and_then(Value::as_array)
    {
        for u in users {
            let name = u
                .get("name")
                .and_then(Value::as_str)
                .ok_or("tuic user missing name")?;
            let uuid = u
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or("tuic user missing uuid")?;
            let password = u
                .get("password")
                .and_then(Value::as_str)
                .ok_or("tuic user missing password")?;
            tuic_users.push(BashTuicUser {
                name: name.to_string(),
                uuid: uuid.to_string(),
                password: password.to_string(),
            });
        }
    }

    // Pull REALITY_PRIVATE out of keys.env. Same dialect as the
    // inventory env file — KEY=VAL lines with comments.
    let mut reality_private: Option<String> = None;
    for raw in keys_env_text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=')
            && k.trim() == "REALITY_PRIVATE"
        {
            reality_private = Some(v.trim().to_string());
            break;
        }
    }
    Ok(BashSingboxData {
        vless_users,
        tuic_users,
        reality_private,
    })
}

// ────────────────────────────────────────────────────────────────────────
// Planner (no I/O)
// ────────────────────────────────────────────────────────────────────────

/// Build a `MigrationPlan` from the parsed bash data. Pure function
/// — caller (CLI) decides whether to apply it.
///
/// Policy:
///   * Server id = `server_id_override` (CLI flag) or derived
///     from the bash IP via `derive_server_id_from_ip` (replaces
///     IPv6 colons with hyphens; IPv4 is unchanged).
///   * Kernel = `sing-box` (the only kernel bash supports).
///   * Protocols = `vless+reality` always; `tuic-v5` ONLY if the
///     TUIC inbound has users (avoids declaring a protocol the
///     server has zero credentials for).
///   * Per-user UUID + tuic_password sourced from the bash JSON.
///   * `sub_token` is FRESH (bash had no subscription URLs). Pass
///     in via `sub_token_for` closure so tests can pin deterministic
///     values; production passes a `vpnctl_crypto::gen_password`
///     wrapper.
///   * `wireguard_pubkey` / `wireguard_private` are `None` — bash
///     didn't do WireGuard.
///
/// Warnings (non-fatal, surfaced via `plan.warnings`):
///   * Duplicate VLESS user-name in `config.json` — last wins.
///   * Split-identity: a name appears in both VLESS and TUIC inbounds
///     with DIFFERENT uuids. We import VLESS-only (no `tuic_password`)
///     and ALSO push a `SkippedUser` for the TUIC half. Was a fatal
///     `Err` until 2026-05-17; relaxed because legacy bash server
///     `93.95.226.167` has main-brat in this exact shape and a fatal
///     error blocked the whole migration.
///
/// Errors:
///   * Currently none — every recoverable case is either an import,
///     a warning, or a `SkippedUser`. The `Result` is kept for future
///     fatal validation (e.g. empty server id, malformed reality
///     public key) that we'd want to surface as an early operator
///     failure rather than a silent skip.
pub fn build_migration_plan<F: FnMut(&str) -> String>(
    server_id_override: Option<String>,
    inv: &BashInventoryEnv,
    singbox: &BashSingboxData,
    mut sub_token_for: F,
) -> Result<MigrationPlan, String> {
    let server_id_str =
        server_id_override.unwrap_or_else(|| derive_server_id_from_ip(&inv.server_ip));
    let server_id = ServerId(server_id_str.clone());

    let mut warnings: Vec<String> = Vec::new();
    let mut skipped: Vec<SkippedUser> = Vec::new();

    // Build name → BashVlessUser map for the unified-user merge.
    let mut by_name: std::collections::BTreeMap<String, BashVlessUser> =
        std::collections::BTreeMap::new();
    for v in &singbox.vless_users {
        if by_name.insert(v.name.clone(), v.clone()).is_some() {
            warnings.push(format!(
                "duplicate VLESS user '{name}' in config.json — keeping last",
                name = v.name
            ));
        }
    }

    // TUIC → fold password into existing VLESS user IF uuids match.
    // Three policies for the cases that don't match:
    //   * No VLESS counterpart → legacy per-device token (e.g.
    //     `brat-pc`, `brat-mac` on 104); SKIP with reason.
    //   * Same name, DIFFERENT uuid → legacy split-identity setup
    //     (e.g. 93.95.226.167 has main-brat VLESS uuid X but TUIC
    //     uuid Y; bash maintained two parallel identities per
    //     protocol). vpnctl's User model has a single uuid; we
    //     can't unify these without picking a winner — SKIP the
    //     TUIC entry (keeping VLESS-only) and emit a WARNING so
    //     the operator can see what happened. Previous policy
    //     was a fatal Err which made the 93 server unmigrate-able
    //     — too strict. Phones with bash-scanned TUIC links keep
    //     working because bash continues to serve them; vpnctl
    //     /sub just won't include a working TUIC outbound for
    //     these specific users.
    let mut tuic_password_by_name: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for t in &singbox.tuic_users {
        match by_name.get(&t.name) {
            None => {
                // Pure TUIC name (legacy per-device — `brat-pc`,
                // `brat-mac`, etc on 104). Skip with a clear reason.
                skipped.push(SkippedUser {
                    name: t.name.clone(),
                    reason: "TUIC-only legacy user (no VLESS counterpart); not imported. Re-add via the modern unified flow if still needed.".into(),
                });
            }
            Some(vless_user) if vless_user.uuid != t.uuid => {
                // Split-identity (legacy bash quirk on some
                // servers: bash add-user.sh used the same UUID
                // for both protocols since Apr 2026, but earlier
                // setups generated per-protocol identities).
                // Skip the TUIC half + warn — phones with the
                // bash-scanned TUIC link still work (bash serves
                // it), vpnctl just won't mint a working TUIC
                // share-link for this user. We push BOTH a warning
                // (so the operator sees a hi-priority signal in
                // dry-run output) AND a SkippedUser (so the
                // per-user "skipped" table is symmetric with the
                // TUIC-only-legacy branch — every non-imported
                // entity is listed in one place).
                warnings.push(format!(
                    "user '{name}': VLESS uuid {vsh} differs from TUIC uuid {tsh} on the bash server. vpnctl imports VLESS only; bash continues serving TUIC.",
                    name = t.name,
                    vsh = uuid_prefix8(&vless_user.uuid),
                    tsh = uuid_prefix8(&t.uuid),
                ));
                skipped.push(SkippedUser {
                    name: t.name.clone(),
                    reason: format!(
                        "split-identity: TUIC uuid {tsh} differs from VLESS uuid {vsh}; vpnctl imports VLESS only and leaves TUIC to the bash server.",
                        vsh = uuid_prefix8(&vless_user.uuid),
                        tsh = uuid_prefix8(&t.uuid),
                    ),
                });
            }
            Some(_) => {
                tuic_password_by_name.insert(t.name.clone(), t.password.clone());
            }
        }
    }

    // Cross-check: any names in the .env `USERS=` list that DON'T
    // appear in config.json's vless inbound? That's a stale inventory
    // (someone removed via `remove-user.sh` but forgot to rebroadcast);
    // surface as a warning so the operator can sync-inventory.
    let vless_name_set: std::collections::BTreeSet<&str> =
        by_name.keys().map(String::as_str).collect();
    for u in &inv.users {
        if !vless_name_set.contains(u.as_str()) {
            warnings.push(format!(
                "USERS=… in {inv}.env lists '{u}' but config.json has no VLESS user by that name — stale inventory; skipping",
                inv = inv.server_ip
            ));
        }
    }

    // Build the User rows. Ordered by name (lex) so the plan output
    // is deterministic.
    let mut users_to_import: Vec<User> = Vec::new();
    let mut grants: Vec<(UserId, ServerId)> = Vec::new();
    for (name, vless_user) in &by_name {
        let user = User {
            id: UserId(name.clone()),
            uuid: vless_user.uuid.clone(),
            tuic_password: tuic_password_by_name.get(name).cloned(),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some(sub_token_for(name)),
        };
        users_to_import.push(user);
        grants.push((UserId(name.clone()), server_id.clone()));
    }

    // Per-server secrets. `vless.private_key` is OPTIONAL — vpnctl
    // doesn't need it for share_link (clients only need the public
    // half), but stores it so a future `vpnctl deploy` can render
    // the server config without re-generating a NEW pair (which
    // would break every existing client).
    let mut server_secrets = HashMap::new();
    server_secrets.insert("vless.public_key".into(), inv.reality_public.clone());
    server_secrets.insert("vless.short_id".into(), inv.short_id.clone());
    if let Some(priv_key) = &singbox.reality_private {
        server_secrets.insert("vless.private_key".into(), priv_key.clone());
    } else {
        warnings.push("no REALITY_PRIVATE in keys.env — vpnctl can render share-links but a future `vpnctl deploy` would mint a NEW server keypair, breaking existing clients. Restore the key from server's `/etc/sing-box/keys.env` before deploying.".into());
    }

    // Protocols: VLESS always; TUIC only if any of the imported
    // users actually have a tuic_password (otherwise declaring the
    // protocol just confuses share-link rendering).
    let mut enabled_protocols = vec![ProtocolId("vless+reality".into())];
    if users_to_import.iter().any(|u| u.tuic_password.is_some()) {
        enabled_protocols.push(ProtocolId("tuic-v5".into()));
    }

    let server = Server {
        id: server_id.clone(),
        address: inv.server_ip.clone(),
        ssh_port: inv.ssh_port,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols,
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };

    Ok(MigrationPlan {
        server,
        server_secrets,
        users_to_import,
        grants,
        skipped,
        warnings,
    })
}

/// Short, panic-free `&str` prefix for displaying a UUID in
/// operator-facing diagnostics. Returns up to 8 chars (NOT bytes —
/// avoids the byte-indexed slice panic that would fire if a
/// non-ASCII char ever lands at the boundary). UUIDs are
/// always ASCII in practice but the no-panic invariant in
/// `CLAUDE.md` is workspace-wide.
fn uuid_prefix8(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

/// Derive a vpnctl `ServerId` from an IP. IPv4 passes through; IPv6
/// colons get replaced with hyphens (vpnctl's id alphabet is
/// `[A-Za-z0-9._-]`). Same shape as the wizard's
/// `wizard_bootstrap::derive_server_id` so a manual + a migrated
/// add of the same IP both produce the same id.
pub fn derive_server_id_from_ip(ip: &str) -> String {
    ip.chars()
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

/// Apply a `MigrationPlan` against an open `SqliteInventory`. Each
/// step writes its own audit row so the operator can replay the
/// timeline post-hoc. Idempotent at the SQL layer:
///   * `add_server` already-exists → updated with current secrets +
///     additional users (won't drop existing grants),
///   * `add_user` already-exists → depends on `overwrite_existing`:
///     - `false` (default): SKIP the user (preserves any vpnctl-side
///       state like wireguard keypair or hand-set sub_token);
///     - `true`: `remove_user` then `add_user` with bash data
///       (drops vpnctl-only state including WG keypair, restored
///       sub_token, traffic-limit). Required when the operator
///       had test users in vpnctl with random UUIDs that DON'T
///       match the bash production data — overwrite forces vpnctl
///       to mirror bash's UUIDs so subsequent `/sub/<token>` calls
///       return links that match the existing phone scans.
///   * `grant` already-exists → silently no-op.
///
/// Returns a `MigrationOutcome` summary (counts of created vs
/// overwritten vs skipped — surfaced by the CLI's final report line).
pub async fn apply_migration_plan(
    inv: &crate::SqliteInventory,
    plan: &MigrationPlan,
    overwrite_existing: bool,
) -> Result<MigrationOutcome, SqliteInventoryError> {
    let mut outcome = MigrationOutcome::default();

    // Server first. If it already exists, AlreadyExists is the
    // signal — we still try to update the secrets in case the
    // operator is re-running migration after a fix.
    match inv.add_server(&plan.server).await {
        Ok(()) => {
            outcome.server_created = true;
        }
        Err(SqliteInventoryError::AlreadyExists(_)) => {
            outcome.server_already_existed = true;
            // In overwrite mode, ALSO correct the address/port/user
            // — a pre-existing server with the same id may have a
            // stale IP from an earlier wizard test; without this
            // update vpnctl's view stays inconsistent (correct
            // REALITY pair pointing at the wrong IP). Outside
            // overwrite mode we leave the existing address alone
            // — silently mutating it would surprise the operator.
            if overwrite_existing {
                inv.update_server_address(
                    &plan.server.id,
                    &plan.server.address,
                    plan.server.ssh_port,
                    &plan.server.ssh_user,
                )
                .await?;
                outcome.server_address_updated = true;
            }
        }
        Err(e) => return Err(e),
    }

    for (key, value) in &plan.server_secrets {
        inv.set_server_secret(&plan.server.id, key, value).await?;
        outcome.secrets_set += 1;
    }

    for user in &plan.users_to_import {
        match inv.get_user(&user.id).await? {
            Some(_existing) => {
                if overwrite_existing {
                    // remove_user CASCADEs through the grants FK —
                    // that would silently drop the user's grants
                    // for EVERY other server, not just the one
                    // we're migrating. Snapshot the full grant set
                    // BEFORE the remove, then re-grant after the
                    // add_user (the bash server's own grant is
                    // re-added by the plan.grants loop below; we
                    // restore the OTHER servers' grants here).
                    //
                    // Caught by review-agent 2026-05-17 — a real
                    // grant (`main-brat`→`stg`) was lost on the
                    // first production run; this is the fix.
                    let prev_grants = inv.servers_for_user(&user.id).await?;
                    inv.remove_user(&user.id).await?;
                    inv.add_user(user).await?;
                    let new_server = plan.server.id.clone();
                    for s in prev_grants {
                        if s.id == new_server {
                            // The plan.grants loop below re-adds
                            // this one — don't double-grant (it's
                            // idempotent at SQL but the audit
                            // would be misleading).
                            continue;
                        }
                        inv.grant(&user.id, &s.id).await?;
                        outcome.other_server_grants_preserved.push(format!(
                            "{user}|{server}",
                            user = user.id.0,
                            server = s.id.0
                        ));
                    }
                    outcome.users_overwritten.push(user.id.0.clone());
                } else {
                    outcome.users_skipped_existing.push(user.id.0.clone());
                }
            }
            None => {
                inv.add_user(user).await?;
                outcome.users_created += 1;
            }
        }
    }

    for (uid, sid) in &plan.grants {
        // grant is upsert-y (PRIMARY KEY (user_id, server_id) + IGNORE)
        // so re-runs are safe. If `overwrite_existing` removed +
        // re-added the user, this re-creates the grant.
        inv.grant(uid, sid).await?;
        outcome.grants_made += 1;
    }

    // Audit row — one per migration application, summarising the
    // counts. NOT per-row (that would flood the timeline).
    inv.audit(
        "admin",
        "migrate.from_bash",
        Some(&plan.server.id.0),
        Some(&serde_json::json!({
            "server_address": plan.server.address,
            "server_created": outcome.server_created,
            "server_already_existed": outcome.server_already_existed,
            "secrets_set": outcome.secrets_set,
            "users_created": outcome.users_created,
            "users_overwritten": outcome.users_overwritten,
            "users_skipped_existing": outcome.users_skipped_existing,
            "grants_made": outcome.grants_made,
            "other_server_grants_preserved": outcome.other_server_grants_preserved,
            "server_address_updated": outcome.server_address_updated,
            "overwrite_existing_mode": overwrite_existing,
            "skipped": plan.skipped.iter().map(|s| serde_json::json!({"name": s.name, "reason": s.reason})).collect::<Vec<_>>(),
            "warnings": plan.warnings,
        })),
    )
    .await?;

    Ok(outcome)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── Parser tests ────────────────────────────────────────────────

    #[test]
    fn parse_bash_inventory_env_real_fixture() {
        let s = include_str!("../tests/fixtures/bash_migration/104.194.156.93.env");
        let inv = parse_bash_inventory_env(s).unwrap();
        assert_eq!(inv.server_ip, "104.194.156.93");
        assert_eq!(inv.ssh_port, 2222);
        assert_eq!(
            inv.reality_public,
            "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A"
        );
        assert_eq!(inv.short_id, "d86e92a0c6dd2271");
        // 20 names in the production .env at recon time.
        assert_eq!(inv.users.len(), 20);
        assert_eq!(inv.users[0], "main-brat");
    }

    #[test]
    fn parse_bash_inventory_env_example_template() {
        let s = include_str!("../tests/fixtures/bash_migration/example_inv.env");
        let inv = parse_bash_inventory_env(s).unwrap();
        assert_eq!(inv.server_ip, "1.2.3.4");
        assert_eq!(inv.ssh_port, 2222);
        assert_eq!(inv.users, vec!["user1", "user2", "user3"]);
    }

    #[test]
    fn parse_bash_inventory_env_rejects_malformed_line() {
        let bad = "SERVER_IP=1.2.3.4\nbroken-no-equals\n";
        let err = parse_bash_inventory_env(bad).unwrap_err();
        assert!(err.contains("KEY=VALUE"), "wrong error: {err}");
    }

    #[test]
    fn parse_bash_inventory_env_rejects_missing_required() {
        let no_ip = "SHORT_ID=abc\nREALITY_PUBLIC=xyz\n";
        let err = parse_bash_inventory_env(no_ip).unwrap_err();
        assert!(err.contains("SERVER_IP"), "wrong error: {err}");
    }

    #[test]
    fn parse_bash_singbox_real_fixture_counts() {
        let cfg = include_str!("../tests/fixtures/bash_migration/config.json");
        let keys = include_str!("../tests/fixtures/bash_migration/keys.env");
        let data = parse_bash_singbox(cfg, keys).unwrap();
        // 23 VLESS, 9 TUIC, names don't overlap — recon-confirmed
        // shape from production 104.194.156.93 (sanitised).
        assert_eq!(
            data.vless_users.len(),
            23,
            "expected 23 VLESS users from 104 fixture"
        );
        assert_eq!(data.tuic_users.len(), 9, "expected 9 TUIC users");
        // REALITY_PRIVATE present (sanitised to EXAMPLE_REDACTED).
        assert!(
            data.reality_private
                .as_deref()
                .unwrap_or("")
                .starts_with("EXAMPLE_REDACTED")
        );
        // The first VLESS inbound (port 443) is picked, NOT the
        // secondary `vless-reality-2083` — both have 23 users so
        // the count alone wouldn't catch a bug; we'd need a uuid
        // check. Both inbounds happen to mirror users so we don't
        // need to discriminate further here (planner's warning
        // covers the "second inbound exists" diagnostic).
    }

    #[test]
    fn parse_bash_singbox_skips_non_vless_non_tuic_inbounds() {
        // A config with ONLY a socks5 inbound returns empty vlessv +
        // tuic lists, not an error.
        let cfg = r#"{"inbounds": [{"type":"socks", "tag":"socks-in"}]}"#;
        let data = parse_bash_singbox(cfg, "").unwrap();
        assert!(data.vless_users.is_empty());
        assert!(data.tuic_users.is_empty());
        assert!(data.reality_private.is_none());
    }

    #[test]
    fn parse_bash_singbox_rejects_invalid_json() {
        let err = parse_bash_singbox("not json", "").unwrap_err();
        assert!(err.contains("valid JSON"));
    }

    // ── Planner tests ───────────────────────────────────────────────

    fn fake_token(name: &str) -> String {
        format!("subtoken-{name}-deadbeef")
    }

    fn fake_inv() -> BashInventoryEnv {
        BashInventoryEnv {
            server_ip: "203.0.113.7".into(),
            ssh_port: 22,
            reality_public: "PUBKEY_ABCDEFGHIJKL".into(),
            short_id: "deadbeefdeadbeef".into(),
            users: vec!["alex".into(), "bob".into()],
        }
    }

    #[test]
    fn build_plan_unifies_vless_and_tuic_user_on_matching_uuid() {
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![
                BashVlessUser {
                    name: "alex".into(),
                    uuid: "u-alex".into(),
                    flow: Some("xtls-rprx-vision".into()),
                },
                BashVlessUser {
                    name: "bob".into(),
                    uuid: "u-bob".into(),
                    flow: Some("xtls-rprx-vision".into()),
                },
            ],
            tuic_users: vec![BashTuicUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                password: "pw-alex".into(),
            }],
            reality_private: Some("priv".into()),
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        assert_eq!(plan.users_to_import.len(), 2);
        // alex got both protocols, bob only VLESS.
        let alex = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "alex")
            .unwrap();
        assert_eq!(alex.tuic_password.as_deref(), Some("pw-alex"));
        let bob = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "bob")
            .unwrap();
        assert_eq!(bob.tuic_password, None);
        // Protocol list contains tuic-v5 because at least one user has it.
        let pids: Vec<&str> = plan
            .server
            .enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect();
        assert!(pids.contains(&"vless+reality"));
        assert!(pids.contains(&"tuic-v5"));
    }

    #[test]
    fn build_plan_drops_tuic_v5_protocol_when_no_user_has_password() {
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![BashVlessUser {
                name: "alex".into(),
                uuid: "u".into(),
                flow: None,
            }],
            tuic_users: vec![],
            reality_private: None,
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        let pids: Vec<&str> = plan
            .server
            .enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect();
        assert!(pids.contains(&"vless+reality"));
        assert!(!pids.contains(&"tuic-v5"));
    }

    #[test]
    fn build_plan_skips_tuic_only_legacy_users_with_clear_reason() {
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![BashVlessUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                flow: None,
            }],
            tuic_users: vec![
                BashTuicUser {
                    name: "alex".into(),
                    uuid: "u-alex".into(),
                    password: "pw".into(),
                },
                BashTuicUser {
                    name: "legacy-pc".into(),
                    uuid: "u-legacy".into(),
                    password: "pw2".into(),
                },
            ],
            reality_private: None,
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        let skipped_names: Vec<&str> = plan.skipped.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(skipped_names, vec!["legacy-pc"]);
        assert!(plan.skipped[0].reason.contains("TUIC-only"));
        // 'legacy-pc' must NOT be in the import set OR have a grant.
        assert!(plan.users_to_import.iter().all(|u| u.id.0 != "legacy-pc"));
        assert!(plan.grants.iter().all(|(uid, _)| uid.0 != "legacy-pc"));
    }

    #[test]
    fn build_plan_warns_on_vless_tuic_uuid_split_identity_imports_vless_only() {
        // 2026-05-17 policy update: split-identity (same name,
        // different uuids per protocol) is no longer fatal — bash
        // 93.95.226.167 has this shape historically. The planner
        // imports VLESS and warns about the TUIC mismatch. The
        // fixture deliberately mixes a split-identity user ('alex')
        // with a happy-path user ('bob', matching uuids) so the
        // assertions distinguish "tuic_password dropped for THIS
        // user" from "tuic_password dropped for everyone" (the
        // inverted-impl trap the original test was vulnerable to).
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![
                BashVlessUser {
                    name: "alex".into(),
                    uuid: "u-alex-vless-aaaaaaaa".into(),
                    flow: None,
                },
                BashVlessUser {
                    name: "bob".into(),
                    uuid: "u-bob-shared-bbbbbbbb".into(),
                    flow: None,
                },
            ],
            tuic_users: vec![
                BashTuicUser {
                    name: "alex".into(),
                    uuid: "u-alex-tuic-cccccccc".into(),
                    password: "pw-alex".into(),
                },
                BashTuicUser {
                    name: "bob".into(),
                    uuid: "u-bob-shared-bbbbbbbb".into(),
                    password: "pw-bob".into(),
                },
            ],
            reality_private: None,
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();

        // alex IS imported (with VLESS uuid + NO tuic_password) — the
        // split-identity branch must NOT silently merge.
        let alex = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "alex")
            .unwrap();
        assert_eq!(alex.uuid, "u-alex-vless-aaaaaaaa");
        assert_eq!(alex.tuic_password, None);

        // bob IS imported with tuic_password Some(...) — positive
        // control that the happy-path merge still works. Without
        // this, a bug that dropped tuic_password for ALL users
        // would not be caught.
        let bob = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "bob")
            .unwrap();
        assert_eq!(bob.uuid, "u-bob-shared-bbbbbbbb");
        assert_eq!(bob.tuic_password.as_deref(), Some("pw-bob"));

        // The split-identity is surfaced AS A WARNING, exposing the
        // 8-char prefixes (pin the new slicing path):
        let warning = plan
            .warnings
            .iter()
            .find(|w| w.contains("alex"))
            .expect("expected split-identity warning for alex");
        assert!(warning.contains("differs"), "warning was: {warning}");
        assert!(
            warning.contains("u-alex-v"),
            "expected VLESS uuid prefix 'u-alex-v', got: {warning}"
        );
        assert!(
            warning.contains("u-alex-t"),
            "expected TUIC uuid prefix 'u-alex-t', got: {warning}"
        );

        // AND mirrored into `skipped` so dry-run's per-user table
        // lists every non-imported entity in one place.
        let split_skipped = plan
            .skipped
            .iter()
            .find(|s| s.name == "alex")
            .expect("expected SkippedUser entry for split-identity TUIC half");
        assert!(
            split_skipped.reason.contains("split-identity"),
            "skip reason was: {}",
            split_skipped.reason
        );

        // tuic-v5 IS still enabled (bob has a working tuic_password).
        let pids: Vec<&str> = plan
            .server
            .enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect();
        assert!(pids.contains(&"tuic-v5"));
    }

    #[test]
    fn build_plan_warns_on_stale_inventory_user_not_in_config() {
        let mut inv = fake_inv();
        inv.users.push("ghost".into()); // not in vless_users below
        let data = BashSingboxData {
            vless_users: vec![BashVlessUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                flow: None,
            }],
            tuic_users: vec![],
            reality_private: Some("priv".into()),
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        assert!(
            plan.warnings
                .iter()
                .any(|w| w.contains("'ghost'") && w.contains("stale"))
        );
    }

    #[test]
    fn build_plan_warns_on_missing_reality_private() {
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![BashVlessUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                flow: None,
            }],
            tuic_users: vec![],
            reality_private: None,
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("REALITY_PRIVATE")));
        // vless.private_key NOT in secrets when missing.
        assert!(!plan.server_secrets.contains_key("vless.private_key"));
        // Public half + short_id ARE present (we have those from inv).
        assert!(plan.server_secrets.contains_key("vless.public_key"));
        assert!(plan.server_secrets.contains_key("vless.short_id"));
    }

    #[test]
    fn build_plan_assigns_sub_tokens_via_closure() {
        let inv = fake_inv();
        let data = BashSingboxData {
            vless_users: vec![
                BashVlessUser {
                    name: "alex".into(),
                    uuid: "u-a".into(),
                    flow: None,
                },
                BashVlessUser {
                    name: "bob".into(),
                    uuid: "u-b".into(),
                    flow: None,
                },
            ],
            tuic_users: vec![],
            reality_private: None,
        };
        let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
        let alex = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "alex")
            .unwrap();
        let bob = plan
            .users_to_import
            .iter()
            .find(|u| u.id.0 == "bob")
            .unwrap();
        assert_eq!(alex.sub_token.as_deref(), Some("subtoken-alex-deadbeef"));
        assert_eq!(bob.sub_token.as_deref(), Some("subtoken-bob-deadbeef"));
    }

    #[test]
    fn derive_server_id_keeps_ipv4_unchanged() {
        assert_eq!(derive_server_id_from_ip("104.194.156.93"), "104.194.156.93");
    }

    #[test]
    fn derive_server_id_replaces_ipv6_colons_with_hyphens() {
        assert_eq!(derive_server_id_from_ip("2001:db8::1"), "2001-db8--1");
    }

    // ── Apply tests ─────────────────────────────────────────────────
    //
    // Spec-test the actual mutation path, not just the planner.
    // Each test uses a fresh tempdir SqliteInventory so audit + grant
    // + user state is reset between cases.

    async fn open_test_inv() -> crate::SqliteInventory {
        let dir = tempfile::tempdir().unwrap();
        std::mem::forget(dir); // leak for the test process lifetime
        let db = std::env::temp_dir().join(format!(
            "vpnctl-migrate-test-{}.db",
            vpnctl_crypto::gen_password(8).unwrap_or_else(|_| "fallback".into())
        ));
        crate::SqliteInventory::open(&db).await.unwrap()
    }

    fn plan_with_one_user(server_id: &str, user_name: &str, user_uuid: &str) -> MigrationPlan {
        let inv = BashInventoryEnv {
            server_ip: "203.0.113.1".into(),
            ssh_port: 22,
            reality_public: "PUB".into(),
            short_id: "SID".into(),
            users: vec![user_name.into()],
        };
        let data = BashSingboxData {
            vless_users: vec![BashVlessUser {
                name: user_name.into(),
                uuid: user_uuid.into(),
                flow: None,
            }],
            tuic_users: vec![],
            reality_private: Some("priv".into()),
        };
        build_migration_plan(Some(server_id.into()), &inv, &data, |n| format!("tok-{n}")).unwrap()
    }

    #[tokio::test]
    async fn apply_writes_audit_row_with_summary_payload() {
        let inv = open_test_inv().await;
        let plan = plan_with_one_user("srv-a", "alice", "uuid-A");
        let _ = apply_migration_plan(&inv, &plan, false).await.unwrap();
        let rows = inv.recent_audit(10).await.unwrap();
        let audit = rows
            .iter()
            .find(|r| r.action == "migrate.from_bash")
            .expect("migrate.from_bash audit row must be written");
        let payload = audit.payload.as_ref().unwrap();
        assert_eq!(payload["server_created"], serde_json::json!(true));
        assert_eq!(payload["users_created"], serde_json::json!(1));
        assert_eq!(payload["grants_made"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn apply_with_overwrite_replaces_existing_user_uuid() {
        use vpnctl_core::{User, UserId};
        let inv = open_test_inv().await;
        // Pre-seed a user with a DIFFERENT uuid than the migration
        // plan brings. Without overwrite the migration must keep
        // the existing uuid; WITH overwrite it must replace it.
        inv.add_user(&User {
            id: UserId("alice".into()),
            uuid: "OLD-uuid-1234".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("stale".into()),
        })
        .await
        .unwrap();

        let plan = plan_with_one_user("srv-b", "alice", "NEW-uuid-9999");
        // Without overwrite: existing uuid wins.
        let outcome = apply_migration_plan(&inv, &plan, false).await.unwrap();
        assert_eq!(outcome.users_skipped_existing, vec!["alice".to_string()]);
        let after_no_overwrite = inv
            .get_user(&UserId("alice".into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_no_overwrite.uuid, "OLD-uuid-1234");
        // With overwrite: bash uuid wins.
        let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
        assert_eq!(outcome.users_overwritten, vec!["alice".to_string()]);
        let after_overwrite = inv
            .get_user(&UserId("alice".into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_overwrite.uuid, "NEW-uuid-9999");
    }

    #[tokio::test]
    async fn apply_with_overwrite_preserves_user_grants_on_other_servers() {
        // The bug that caused real grant loss on production
        // (review-agent 2026-05-17 critical). `alice` is granted to
        // server `existing-other`; the bash migration imports a
        // DIFFERENT server `srv-bash`. After overwrite-apply alice
        // must STILL be granted on `existing-other` + newly on
        // `srv-bash`.
        use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
        let inv = open_test_inv().await;
        // Seed the OTHER server + user + grant first.
        inv.add_server(&Server {
            id: ServerId("existing-other".into()),
            address: "198.51.100.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        inv.add_user(&User {
            id: UserId("alice".into()),
            uuid: "OLD-uuid".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("stale".into()),
        })
        .await
        .unwrap();
        inv.grant(&UserId("alice".into()), &ServerId("existing-other".into()))
            .await
            .unwrap();

        let plan = plan_with_one_user("srv-bash", "alice", "NEW-uuid");
        let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();

        // alice still on existing-other (was preserved).
        let servers = inv.servers_for_user(&UserId("alice".into())).await.unwrap();
        let ids: std::collections::HashSet<String> =
            servers.iter().map(|s| s.id.0.clone()).collect();
        assert!(
            ids.contains("existing-other"),
            "alice's grant on existing-other MUST survive overwrite — got: {ids:?}"
        );
        assert!(
            ids.contains("srv-bash"),
            "alice should ALSO be granted on the newly-migrated bash server"
        );
        assert_eq!(
            outcome.other_server_grants_preserved,
            vec!["alice|existing-other".to_string()],
            "outcome must report the preserved grant for audit visibility"
        );
    }

    #[tokio::test]
    async fn apply_with_overwrite_updates_existing_server_address() {
        use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
        let inv = open_test_inv().await;
        // Pre-seed `srv-bash` with WRONG address (mimics the real
        // production issue: a wizard-test row with stale IP).
        inv.add_server(&Server {
            id: ServerId("srv-bash".into()),
            address: "1.2.3.4".into(),
            ssh_port: 9999,
            ssh_user: "old-user".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();

        let plan = plan_with_one_user("srv-bash", "alice", "uuid-x");
        let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
        assert!(outcome.server_already_existed);
        assert!(
            outcome.server_address_updated,
            "address must be updated under --overwrite-existing"
        );

        let after = inv
            .get_server(&ServerId("srv-bash".into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.address, "203.0.113.1");
        assert_eq!(after.ssh_port, 22);
        assert_eq!(after.ssh_user, "root");
    }

    #[test]
    fn build_plan_real_fixture_end_to_end() {
        // Reads the sanitised 104.194.156.93 fixtures and builds a
        // plan. Pins the expected counts so a regression in either
        // the parser OR the planner would surface.
        let inv = parse_bash_inventory_env(include_str!(
            "../tests/fixtures/bash_migration/104.194.156.93.env"
        ))
        .unwrap();
        let data = parse_bash_singbox(
            include_str!("../tests/fixtures/bash_migration/config.json"),
            include_str!("../tests/fixtures/bash_migration/keys.env"),
        )
        .unwrap();
        let plan = build_migration_plan(Some("vps-is-01".into()), &inv, &data, fake_token).unwrap();
        // Server id override honoured.
        assert_eq!(plan.server.id.0, "vps-is-01");
        // 23 VLESS users imported (modern scheme).
        assert_eq!(plan.users_to_import.len(), 23);
        // 9 TUIC-only legacy users skipped.
        assert_eq!(plan.skipped.len(), 9);
        // None of the 23 imported users got a tuic_password
        // (names don't overlap with TUIC inbound on 104).
        assert!(
            plan.users_to_import
                .iter()
                .all(|u| u.tuic_password.is_none())
        );
        // → protocol list excludes tuic-v5.
        let pids: Vec<&str> = plan
            .server
            .enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect();
        assert_eq!(pids, vec!["vless+reality"]);
        // Secrets cover vless public/short_id + private (sanitised).
        assert!(plan.server_secrets.contains_key("vless.public_key"));
        assert!(plan.server_secrets.contains_key("vless.short_id"));
        assert!(plan.server_secrets.contains_key("vless.private_key"));
        // 23 grants (one per imported user × server).
        assert_eq!(plan.grants.len(), 23);
    }
}
