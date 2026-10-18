use std::collections::{BTreeMap, BTreeSet, HashMap};

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

use super::types::{BashInventoryEnv, BashSingboxData, BashVlessUser, MigrationPlan, SkippedUser};

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

    let mut by_name: BTreeMap<String, BashVlessUser> = BTreeMap::new();
    for v in &singbox.vless_users {
        if by_name.insert(v.name.clone(), v.clone()).is_some() {
            warnings.push(format!(
                "duplicate VLESS user '{name}' in config.json — keeping last",
                name = v.name
            ));
        }
    }

    let mut tuic_password_by_name: BTreeMap<String, String> = BTreeMap::new();
    for t in &singbox.tuic_users {
        match by_name.get(&t.name) {
            None => {
                skipped.push(SkippedUser {
                    name: t.name.clone(),
                    reason: "TUIC-only legacy user (no VLESS counterpart); not imported. Re-add via the modern unified flow if still needed.".into(),
                });
            }
            Some(vless_user) if vless_user.uuid != t.uuid => {
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

    let vless_name_set: BTreeSet<&str> = by_name.keys().map(String::as_str).collect();
    for u in &inv.users {
        if !vless_name_set.contains(u.as_str()) {
            warnings.push(format!(
                "USERS=… in {inv}.env lists '{u}' but config.json has no VLESS user by that name — stale inventory; skipping",
                inv = inv.server_ip
            ));
        }
    }

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
            vpn_router_device_id: None,
            disabled: false,
        };
        users_to_import.push(user);
        grants.push((UserId(name.clone()), server_id.clone()));
    }

    let mut server_secrets = HashMap::new();
    server_secrets.insert("vless.public_key".into(), inv.reality_public.clone());
    server_secrets.insert("vless.short_id".into(), inv.short_id.clone());
    if let Some(priv_key) = &singbox.reality_private {
        server_secrets.insert("vless.private_key".into(), priv_key.clone());
    } else {
        warnings.push("no REALITY_PRIVATE in keys.env — vpnctl can render share-links but a future `vpnctl deploy` would mint a NEW server keypair, breaking existing clients. Restore the key from server's `/etc/sing-box/keys.env` before deploying.".into());
    }

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

pub(crate) fn uuid_prefix8(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

pub fn derive_server_id_from_ip(ip: &str) -> String {
    ip.chars()
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}
