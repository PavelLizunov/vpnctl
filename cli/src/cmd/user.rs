use crate::{OutputFormat, ui};
use clap::Subcommand;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{User, UserId};
use vpnctl_crypto::{gen_password, gen_uuid};
use vpnctl_inventory::SqliteInventory;

const TUIC_PASSWORD_BYTES: usize = 24;

#[derive(Subcommand, Debug)]
pub(crate) enum UserCmd {
    /// Add a user. Auto-generates UUID v4 and a 24-byte URL-safe TUIC password
    /// unless they are passed explicitly.
    Add {
        /// Stable id, e.g. "alex-laptop".
        id: String,
        /// Use this UUID instead of generating a fresh one.
        #[arg(long)]
        uuid: Option<String>,
        /// Use this TUIC password instead of generating one.
        #[arg(long)]
        tuic_password: Option<String>,
        /// WireGuard PUBLIC key (44 base64 chars ending '='). The
        /// matching PRIVATE key stays on the operator's client
        /// device — vpnctl never sees it. Optional: omit if the
        /// user won't use WireGuard / AmneziaWG protocols.
        #[arg(long)]
        wireguard_pubkey: Option<String>,
    },

    /// List all users.
    List,

    /// Show user details.
    Show { id: String },

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
        } => {
            // Validate shape if provided so an obvious typo doesn't
            // sit in inventory until a `vpnctl deploy` tries to render
            // a wg config and fails (much later, much harder to
            // diagnose). **Reused from `vpnctl_protocols::wireguard`**
            // for a single source of truth (review-agent finding).
            if let Some(ref pk) = wireguard_pubkey
                && !vpnctl_protocols::is_valid_wg_pubkey(pk)
            {
                anyhow::bail!(
                    "--wireguard-pubkey must be 44 base64 chars ending '=' (got {} chars)",
                    pk.len()
                );
            }
            let user = User {
                id: UserId(id.clone()),
                uuid: uuid.unwrap_or_else(gen_uuid),
                tuic_password: Some(tuic_password.unwrap_or(gen_password(TUIC_PASSWORD_BYTES)?)),
                wireguard_pubkey,
                // None → inventory generates one. Don't pre-gen here so the
                // generation lives in one place (`SqliteInventory::add_user`).
                sub_token: None,
            };
            inv.add_user(&user).await?;
            inv.audit(
                "cli",
                "user.add",
                Some(&id),
                Some(&json!({
                    "uuid": user.uuid,
                    "wg_pubkey_set": user.wireguard_pubkey.is_some(),
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

        UserCmd::Show { id } => {
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
                "user": user,
                "granted_servers": servers,
            });
            ui::print(format, &payload, |_| {
                println!("id            : {}", user.id.0);
                println!("uuid          : {}", user.uuid);
                println!(
                    "tuic_password : {}",
                    user.tuic_password.as_deref().unwrap_or("(none)")
                );
                println!(
                    "sub_token     : {}",
                    user.sub_token.as_deref().unwrap_or("(missing — bug)")
                );
                println!(
                    "granted on    : {}",
                    if servers.is_empty() {
                        "(none)".to_string()
                    } else {
                        servers.join(", ")
                    }
                );
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
    }
}
