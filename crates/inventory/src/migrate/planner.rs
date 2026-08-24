use std::collections::{BTreeMap, BTreeSet, HashMap};

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

use super::types::{BashInventoryEnv, BashSingboxData, BashVlessUser, MigrationPlan, SkippedUser};

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
    let mut by_name: BTreeMap<String, BashVlessUser> = BTreeMap::new();
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
    let mut tuic_password_by_name: BTreeMap<String, String> = BTreeMap::new();
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
    let vless_name_set: BTreeSet<&str> = by_name.keys().map(String::as_str).collect();
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
            // bash project pre-dates the ninitux merge; users
            // arriving via `vpnctl migrate from-bash` carry no
            // device_id (operator pins one later via the Phase 3
            // import script or web UI).
            vpn_router_device_id: None,
            // Migration 0026 default — imported users start enabled.
            disabled: false,
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
pub(crate) fn uuid_prefix8(uuid: &str) -> String {
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
