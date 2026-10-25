use crate::{OutputFormat, ui};
use clap::Subcommand;
use serde_json::json;
use std::path::{Path, PathBuf};
use vpnctl_core::{ServerId, User, UserId};
use vpnctl_crypto::{gen_password, gen_uuid, gen_vpn_router_device_id, gen_wireguard_keypair};
use vpnctl_inventory::SqliteInventory;

const TUIC_PASSWORD_BYTES: usize = 24;

#[derive(Subcommand, Debug)]
pub(crate) enum UserCmd {
    /// Add a user. Auto-generates UUID v4, a 24-byte URL-safe TUIC password,
    /// and a WireGuard keypair unless they are passed explicitly.
    Add {
        /// Stable id, e.g. "alex-laptop".
        id: String,
        /// Use this UUID instead of generating a fresh one.
        #[arg(long, allow_hyphen_values = true)]
        uuid: Option<String>,
        /// Use this TUIC password instead of generating one. URL-safe base64
        /// passwords (what `crypto::gen_password` emits) legitimately start
        /// with `-`/`_`, so allow a leading hyphen instead of mis-parsing it
        /// as a flag.
        #[arg(long, allow_hyphen_values = true)]
        tuic_password: Option<String>,
        /// WireGuard PUBLIC key (44 base64 chars ending '='). The
        /// matching PRIVATE key stays on the operator's client
        /// device — vpnctl never sees it. Operator-paranoid flow.
        /// Mutually exclusive with `--gen-wireguard`.
        #[arg(long, conflicts_with = "gen_wireguard")]
        wireguard_pubkey: Option<String>,
        /// Generate a fresh WireGuard / AmneziaWG keypair server-side (the default)
        /// and store BOTH halves (the recipient gets a single
        /// ready-to-import `.conf` via `/sub/<token>` with no
        /// keygen step on their device). Mutually exclusive with
        /// `--wireguard-pubkey`. The private key is SECRET; it lives
        /// in inv.db and is included only in the owning user's
        /// subscription response. Printed once to stdout for the
        /// operator to verify; never re-emitted on `vpnctl user show`.
        #[arg(long, conflicts_with = "wireguard_pubkey")]
        gen_wireguard: bool,
    },

    /// List all users.
    List,

    /// Show user details.
    Show {
        id: String,
        /// Reveal secret material (tuic_password, sub_token) instead of
        /// `<redacted>`. Off by default: `user show` is repeatable and
        /// its output lands in terminals / CI logs / support sessions,
        /// and sub_token is a bearer credential. Applies to BOTH the text
        /// and `--output json` forms (JSON omits the secret fields unless
        /// this flag is set — matching `User`'s skip-on-serialize).
        #[arg(long)]
        show_secrets: bool,
    },

    /// Remove a user (FK CASCADE removes their grants).
    Remove {
        id: String,
        #[arg(long)]
        yes: bool,
    },

    /// Regenerate the user's subscription token (rotation). Old sub URL
    /// stops working immediately; clients need the new one.
    RegenSub {
        id: String,
        #[arg(long)]
        yes: bool,
    },

    /// Disable a user in inventory. Deploy the listed servers to revoke node access.
    Disable {
        /// User id.
        id: String,
        /// Immediately deploy the listed pending servers; fail if any deploy fails.
        #[arg(long)]
        deploy: bool,
    },

    /// Enable a user in inventory. Deploy the listed servers to restore node access.
    Enable {
        /// User id.
        id: String,
        /// Immediately deploy the listed pending servers; fail if any deploy fails.
        #[arg(long)]
        deploy: bool,
    },

    /// Set or clear monthly bandwidth limit and alert threshold.
    TrafficLimit {
        /// User id.
        id: String,
        /// Monthly limit in GiB (e.g. 50.0). 0 or --clear to remove limit.
        #[arg(long, required_unless_present = "clear")]
        limit_gib: Option<f64>,
        /// Alert threshold percentage (1..=100, default: 80).
        #[arg(long, default_value_t = 80)]
        threshold_pct: u8,
        /// Clear the traffic limit (sets limit to None).
        #[arg(long, conflicts_with = "limit_gib")]
        clear: bool,
    },

    /// Regenerate the user's WireGuard / AmneziaWG keypair.
    RegenWireguard {
        /// User id.
        id: String,
        /// Required to actually regenerate; otherwise dry-run.
        #[arg(long)]
        yes: bool,
    },

    /// Export ready-to-import WireGuard / AmneziaWG .conf configuration for a user on a server.
    WireguardConf {
        /// User id.
        user: String,
        /// Server id.
        server: String,
        /// Optional output file path. Defaults to printing to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// Format a secret field for `user show` text output. Redacts a present
/// secret to `<redacted>` unless `show_secrets`; a missing secret always
/// renders as `none_label` (so the operator can still tell "set but
/// hidden" from "not set").
fn render_secret_field(value: Option<&str>, show_secrets: bool, none_label: &str) -> String {
    match value {
        Some(v) if show_secrets => v.to_string(),
        Some(_) => "<redacted>".to_string(),
        None => none_label.to_string(),
    }
}

/// Build the `user` JSON object for `user show`. `User`'s `Serialize`
/// deliberately skips the secret fields (tuic_password, sub_token, …),
/// so the default (`show_secrets=false`) output is byte-identical to the
/// historical `json!({"user": user})`. When `show_secrets` is set, the
/// two operator-relevant secrets are re-inserted so `--show-secrets
/// --output json` actually carries them.
fn user_show_json(user: &User, show_secrets: bool) -> anyhow::Result<serde_json::Value> {
    let mut v = serde_json::to_value(user)?;
    if show_secrets && let Some(obj) = v.as_object_mut() {
        obj.insert("tuic_password".to_string(), json!(user.tuic_password));
        obj.insert("sub_token".to_string(), json!(user.sub_token));
    }
    Ok(v)
}

pub(crate) async fn run(
    cmd: UserCmd,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    match cmd {
        UserCmd::Add {
            id,
            uuid,
            tuic_password,
            wireguard_pubkey,
            gen_wireguard,
        } => {
            if !vpnctl_core::valid_user_id(&id) {
                anyhow::bail!(
                    "invalid user id '{id}' (allowed: 2-32 chars of a-z 0-9 . _ -; must start and end with a-z 0-9; no consecutive dots)"
                );
            }
            if let Some(ref pk) = wireguard_pubkey
                && !vpnctl_protocols::is_valid_wg_pubkey(pk)
            {
                anyhow::bail!(
                    "--wireguard-pubkey must be 44 base64 chars ending '=' (got {} chars)",
                    pk.len()
                );
            }
            let gen_wireguard = gen_wireguard || wireguard_pubkey.is_none();
            let (wg_pub, wg_priv) = if gen_wireguard {
                let (priv_b64, pub_b64) = gen_wireguard_keypair();
                (Some(pub_b64), Some(priv_b64))
            } else {
                (wireguard_pubkey, None)
            };
            let user = User {
                id: UserId(id.clone()),
                uuid: uuid.unwrap_or_else(gen_uuid),
                tuic_password: Some(tuic_password.unwrap_or(gen_password(TUIC_PASSWORD_BYTES)?)),
                wireguard_pubkey: wg_pub,
                wireguard_private: wg_priv,
                sub_token: None,
                vpn_router_device_id: Some(gen_vpn_router_device_id()?),
                disabled: false,
            };
            inv.add_user(&user).await?;
            inv.audit(
                "cli",
                "user.add",
                Some(&id),
                Some(&json!({
                    "uuid_set": true,
                    "wg_pubkey_set": user.wireguard_pubkey.is_some(),
                    "wg_keypair_provenance": if gen_wireguard { "server-generated" }
                        else if user.wireguard_pubkey.is_some() { "operator-provided" }
                        else { "absent" },
                })),
            )
            .await?;
            ui::print(format, &user, |u| {
                println!("user '{id}' added");
                println!("  uuid             : {}", u.uuid);
                if let Some(pw) = &u.tuic_password {
                    println!("  tuic_password    : {pw}");
                }
                if let Some(wpk) = &u.wireguard_pubkey {
                    println!("  wireguard_pubkey : {wpk}");
                }
                if let Some(wpriv) = &u.wireguard_private {
                    eprintln!("  wireguard_private: {wpriv}");
                    eprintln!("  ^^ secret material — only emitted now and via /sub/<token>");
                }
                Ok(())
            })
        }

        UserCmd::List => {
            let users = inv.list_users().await?;
            ui::print(format, &users, |u| {
                if u.is_empty() {
                    println!("(no users)");
                    return Ok(());
                }
                let rows = u.iter().map(|x| {
                    [
                        x.id.0.clone(),
                        x.uuid.clone(),
                        x.tuic_password
                            .as_ref()
                            .map_or("-".to_string(), |_| "yes".to_string()),
                    ]
                });
                println!("{}", ui::table(["id", "uuid", "tuic_pw?"], rows));
                Ok(())
            })
        }

        UserCmd::Show { id, show_secrets } => {
            let user = inv
                .get_user(&UserId(id.clone()))
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such user: {id}"))?;
            let servers: Vec<String> = inv
                .servers_for_user(&UserId(id.clone()))
                .await?
                .into_iter()
                .map(|s| s.id.0)
                .collect();
            let payload = json!({
                "user": user_show_json(&user, show_secrets)?,
                "granted_servers": servers,
            });
            ui::print(format, &payload, |_| {
                println!("id            : {}", user.id.0);
                println!("uuid          : {}", user.uuid);
                println!(
                    "tuic_password : {}",
                    render_secret_field(user.tuic_password.as_deref(), show_secrets, "(none)")
                );
                println!(
                    "sub_token     : {}",
                    render_secret_field(user.sub_token.as_deref(), show_secrets, "(missing — bug)")
                );
                println!(
                    "granted on    : {}",
                    if servers.is_empty() {
                        "(none)".to_string()
                    } else {
                        servers.join(", ")
                    }
                );
                if !show_secrets {
                    println!(
                        "(secrets redacted — pass --show-secrets to reveal tuic_password + sub_token)"
                    );
                }
                Ok(())
            })
        }

        UserCmd::Remove { id, yes } => {
            if !yes {
                println!("dry-run: pass --yes to actually remove user '{id}'");
                return Ok(());
            }
            inv.remove_user(&UserId(id.clone())).await?;
            inv.audit("cli", "user.remove", Some(&id), None).await?;
            println!("user '{id}' removed");
            Ok(())
        }

        UserCmd::RegenSub { id, yes } => {
            if !yes {
                println!(
                    "dry-run: would rotate sub_token for '{id}' — \
                     all existing subscription URLs will stop working. \
                     Pass --yes to confirm."
                );
                return Ok(());
            }
            let new_token = inv.regenerate_sub_token(&UserId(id.clone())).await?;
            inv.audit("cli", "user.sub_token.regen", Some(&id), None)
                .await?;
            println!("rotated sub_token for '{id}'");
            println!("  new token: {new_token}");
            Ok(())
        }

        UserCmd::Disable { id, deploy } => {
            let uid = UserId(id.clone());
            let changed = inv.set_user_disabled_audited(&uid, true, "cli").await?;
            if changed {
                println!("user '{id}' disabled in inventory");
            } else {
                println!("user '{id}' is already disabled in inventory");
            }
            handle_pending_deploys(&inv, &uid, deploy, &db_path).await?;
            Ok(())
        }

        UserCmd::Enable { id, deploy } => {
            let uid = UserId(id.clone());
            let changed = inv.set_user_disabled_audited(&uid, false, "cli").await?;
            if changed {
                println!("user '{id}' enabled in inventory");
            } else {
                println!("user '{id}' is already enabled in inventory");
            }
            handle_pending_deploys(&inv, &uid, deploy, &db_path).await?;
            Ok(())
        }

        UserCmd::TrafficLimit {
            id,
            limit_gib,
            threshold_pct,
            clear,
        } => {
            let uid = UserId(id.clone());
            if inv.get_user(&uid).await?.is_none() {
                anyhow::bail!("no such user: {id}");
            }
            let limit_gib_val: f64 = if clear { 0.0 } else { limit_gib.unwrap_or(0.0) };
            if !clear && (!limit_gib_val.is_finite() || limit_gib_val < 0.0) {
                anyhow::bail!("--limit-gib must be a finite non-negative number");
            }
            if !(1..=100).contains(&threshold_pct) {
                anyhow::bail!("--threshold-pct must be between 1 and 100");
            }
            let threshold_pct_val = threshold_pct;
            let limit_bytes =
                (limit_gib_val > 0.0).then_some((limit_gib_val * 1_073_741_824.0) as u64);

            let desired = (limit_bytes, Some(threshold_pct_val));
            if inv
                .set_user_traffic_limit(&uid, desired.0, desired.1)
                .await?
            {
                inv.audit(
                    "cli",
                    "user.traffic_limit.set",
                    Some(&id),
                    Some(&json!({
                        "limit_bytes": limit_bytes,
                        "limit_gib": limit_gib_val,
                        "threshold_pct": threshold_pct_val,
                    })),
                )
                .await?;
            }
            if let Some(bytes) = limit_bytes {
                println!(
                    "set traffic limit for '{id}': {limit_gib_val} GiB ({bytes} bytes), alert threshold: {threshold_pct_val}%"
                );
            } else {
                println!("cleared traffic limit for '{id}'");
            }
            Ok(())
        }

        UserCmd::RegenWireguard { id, yes } => {
            if !yes {
                println!(
                    "dry-run: would regenerate WireGuard keypair for '{id}' — \
                     all existing WireGuard connections for this user will stop working \
                     until configs are updated. Pass --yes to confirm."
                );
                return Ok(());
            }
            let uid = UserId(id.clone());
            if inv.get_user(&uid).await?.is_none() {
                anyhow::bail!("no such user: {id}");
            }
            let (priv_b64, pub_b64) = gen_wireguard_keypair();
            inv.set_user_wireguard_keypair(&uid, &pub_b64, &priv_b64)
                .await?;
            inv.audit(
                "cli",
                "user.wireguard.regen",
                Some(&id),
                Some(&json!({
                    "wg_keypair_provenance": "server-generated",
                    "new_pubkey": pub_b64,
                })),
            )
            .await?;
            println!("regenerated WireGuard keypair for '{id}'");
            println!("  wireguard_pubkey : {pub_b64}");
            eprintln!("  wireguard_private: {priv_b64}");
            eprintln!("  ^^ secret material — only emitted now and via /sub/<token>");
            Ok(())
        }

        UserCmd::WireguardConf { user, server, out } => {
            let uid = UserId(user.clone());
            let sid = ServerId(server.clone());

            let user_obj = inv
                .get_user(&uid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such user: {user}"))?;

            let server_obj = inv
                .get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {server}"))?;

            if !server_obj
                .enabled_protocols
                .iter()
                .any(|p| p.0 == "wireguard")
            {
                anyhow::bail!("server '{server}' does not enable the 'wireguard' protocol");
            }

            let peers = inv.users_for_server(&sid).await?;
            if !peers.iter().any(|p| p.id == uid) {
                anyhow::bail!("user '{user}' is not granted on server '{server}'");
            }

            let secrets = inv.list_server_secrets(&sid).await?;
            let ctx = vpnctl_core::RenderCtx::with_peers(&server_obj, &secrets, &peers)
                .with_wg_octets(inv.wg_octets_for_server(&sid).await?);
            let conf = vpnctl_protocols::render_client_conf_public(&ctx, &user_obj)?;

            if let Some(path) = out {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(conf.as_bytes())?;
                println!(
                    "wrote WireGuard configuration for '{user}' on '{server}' to {}",
                    path.display()
                );
            } else {
                print!("{conf}");
            }
            Ok(())
        }
    }
}

async fn handle_pending_deploys(
    inv: &SqliteInventory,
    uid: &UserId,
    deploy: bool,
    db_path: &Path,
) -> anyhow::Result<()> {
    let granted: Vec<ServerId> = inv
        .servers_for_user(uid)
        .await?
        .into_iter()
        .map(|server| server.id)
        .collect();
    let pending = inv.servers_pending_deploy_for_user(uid, &granted).await?;
    if !pending.is_empty() {
        println!("Node access changes require deploy on these servers:");
        for server in &pending {
            println!("  vpnctl deploy {server}");
        }
    }
    if deploy {
        let mut failures = Vec::new();
        for server in pending {
            if let Err(error) =
                super::deploy::run(&server.0, None, Some(db_path.to_path_buf())).await
            {
                failures.push(format!("{server}: {error:#}"));
            }
        }
        if !failures.is_empty() {
            anyhow::bail!("deploy failed: {}", failures.join("; "));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "user_tests.rs"]
mod tests;
