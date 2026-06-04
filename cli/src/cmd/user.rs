use crate::{OutputFormat, ui};
use clap::Subcommand;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{User, UserId};
use vpnctl_crypto::{gen_password, gen_uuid, gen_wireguard_keypair};
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
        /// device — vpnctl never sees it. Operator-paranoid flow.
        /// Mutually exclusive with `--gen-wireguard`.
        #[arg(long, conflicts_with = "gen_wireguard")]
        wireguard_pubkey: Option<String>,
        /// Generate a fresh WireGuard / AmneziaWG keypair server-side
        /// and store BOTH halves (per CLAUDE.md "users are assumed
        /// maximally low-tech" — the recipient gets a single
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
            // Either operator-provided pubkey, or server-generated
            // keypair, or neither. clap's `conflicts_with` already
            // rejects both-at-once at parse time.
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
                // None → inventory generates one. Don't pre-gen here so the
                // generation lives in one place (`SqliteInventory::add_user`).
                sub_token: None,
                vpn_router_device_id: None,
                // Migration 0026 default — CLI-created users start enabled.
                disabled: false,
            };
            inv.add_user(&user).await?;
            inv.audit(
                "cli",
                "user.add",
                Some(&id),
                Some(&json!({
                    "uuid": user.uuid,
                    "wg_pubkey_set": user.wireguard_pubkey.is_some(),
                    // pin which provenance the pubkey had — the value
                    // itself stays only in the row, not the audit log.
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
                    // Emitted to STDERR (not stdout) so:
                    //   * scripts redirecting `> log.txt` don't capture
                    //     the private into a plaintext file,
                    //   * `vpnctl user add ... --output json | jq` keeps
                    //     working without the secret poisoning the json
                    //     stream (json on stdout, advisory on stderr),
                    //   * terminal scrollback still shows it for the
                    //     operator to copy in the moment.
                    // (Review-agent finding on the wg-keygen commit.)
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
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! `vpnctl user show` redacts bearer credentials by default (#7).
    //! `user add` / `regen-sub` keep their one-time secret output — those
    //! are the moments the operator legitimately needs the value once.

    use super::*;

    fn user_with_secrets() -> User {
        User {
            id: UserId("alice".into()),
            uuid: "uuid-alice".into(),
            tuic_password: Some("supersecret-tuic".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("bearer-sub-token".into()),
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn render_secret_field_redacts_present_secret_by_default() {
        assert_eq!(
            render_secret_field(Some("supersecret"), false, "(none)"),
            "<redacted>"
        );
    }

    #[test]
    fn render_secret_field_reveals_with_show_secrets() {
        assert_eq!(
            render_secret_field(Some("supersecret"), true, "(none)"),
            "supersecret"
        );
    }

    #[test]
    fn render_secret_field_none_uses_label_regardless_of_flag() {
        assert_eq!(render_secret_field(None, false, "(none)"), "(none)");
        assert_eq!(
            render_secret_field(None, true, "(missing — bug)"),
            "(missing — bug)"
        );
    }

    #[test]
    fn user_show_json_omits_secrets_by_default() {
        let v = user_show_json(&user_with_secrets(), false).unwrap();
        assert!(
            v.get("tuic_password").is_none(),
            "default JSON must not carry tuic_password"
        );
        assert!(
            v.get("sub_token").is_none(),
            "default JSON must not carry the sub_token bearer credential"
        );
        // Non-secret fields still present (byte-identical to the old path).
        assert_eq!(v.get("uuid").and_then(|x| x.as_str()), Some("uuid-alice"));
    }

    #[test]
    fn user_show_json_includes_secrets_when_requested() {
        let v = user_show_json(&user_with_secrets(), true).unwrap();
        assert_eq!(
            v.get("tuic_password").and_then(|x| x.as_str()),
            Some("supersecret-tuic")
        );
        assert_eq!(
            v.get("sub_token").and_then(|x| x.as_str()),
            Some("bearer-sub-token")
        );
    }
}
