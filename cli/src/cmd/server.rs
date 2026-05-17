use crate::{OutputFormat, ui};
use clap::Subcommand;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

#[derive(Subcommand, Debug)]
pub(crate) enum ServerCmd {
    /// Add a server to the inventory.
    Add {
        /// Stable id, e.g. "fra-01".
        id: String,
        /// IP or hostname.
        #[arg(long)]
        address: String,
        /// SSH port (DigitalOcean must stay on 22; Cloudzy can move to 2222).
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// SSH user that has the deploy key in authorized_keys.
        #[arg(long, default_value = "root")]
        ssh_user: String,
        /// Kernel id (must be registered): "sing-box", future: "wgturn", "xray".
        #[arg(long, default_value = "sing-box")]
        kernel: String,
        /// Hoster: "digitalocean" / "cloudzy" / "generic".
        #[arg(long, default_value = "generic")]
        hoster: String,
        /// Comma-separated list of enabled protocols.
        #[arg(long, value_delimiter = ',', default_values_t = ["vless+reality".to_string(), "tuic-v5".to_string()])]
        protocols: Vec<String>,
        /// Optional jump host (server id; ProxyJump support lands in v0.3).
        #[arg(long)]
        jump_via: Option<String>,
        /// Trusted host SHA256 fingerprint. Empty → TOFU on first connect.
        #[arg(long)]
        trusted_fingerprint: Option<String>,
        /// Usage coefficient (traffic accounting multiplier).
        #[arg(long, default_value_t = 1.0)]
        usage_coefficient: f64,
    },

    /// List all servers.
    List,

    /// Show one server in detail (incl. enabled protocols and secrets keys).
    Show { id: String },

    /// Remove a server (and its protocols/secrets/grants — FK CASCADE).
    Remove {
        id: String,
        /// Required to actually delete; otherwise dry-run.
        #[arg(long)]
        yes: bool,
    },

    /// Set or upsert a server secret (e.g. vless.private_key, vless.short_id).
    Secret {
        server: String,
        key: String,
        value: String,
    },

    /// Set the trusted SSH host key fingerprint (TOFU pin).
    ///
    /// Format: `SHA256:<43-char-base64>` (no trailing `=`), as emitted
    /// by `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -`.
    ///
    /// Previously the operator had to run raw SQL (caught 2026-05-16
    /// during the vps-is-01 import — audit hash for the manual
    /// `UPDATE servers SET trusted_host_fingerprint=...` had to be
    /// constructed by hand). This subcommand wraps it +
    /// audit-logs the change.
    SetFingerprint {
        /// Server id (e.g. `vps-is-01`).
        id: String,
        /// `SHA256:<base64>` fingerprint. Use `--from-keyscan` to
        /// auto-fetch via `ssh-keyscan` instead of supplying this.
        #[arg(value_name = "FINGERPRINT", conflicts_with = "from_keyscan")]
        fingerprint: Option<String>,
        /// Auto-detect via `ssh-keyscan -t ed25519 <address> |
        /// ssh-keygen -lf -`. Requires `ssh-keyscan` + `ssh-keygen`
        /// on PATH (standard on every modern Linux). Convenience for
        /// the typical operator flow — equivalent to running the
        /// two commands by hand and pasting the SHA256:… result.
        #[arg(long, conflicts_with = "fingerprint")]
        from_keyscan: bool,
    },
}

pub(crate) async fn run(
    cmd: ServerCmd,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    match cmd {
        ServerCmd::Add {
            id,
            address,
            ssh_port,
            ssh_user,
            kernel,
            hoster,
            protocols,
            jump_via,
            trusted_fingerprint,
            usage_coefficient,
        } => {
            // Validate against the registry before writing — catches
            // unsupported kernel × protocol combos.
            let reg = crate::registry::build()?;
            let server = Server {
                id: ServerId(id.clone()),
                address,
                ssh_port,
                ssh_user,
                // `server add` keeps the single `--kernel` flag for
                // backward compat; multi-kernel additions go through
                // `vpnctl server kernel-add` (queued) or the admin UI.
                kernels: vec![KernelId(kernel)],
                enabled_protocols: protocols.into_iter().map(ProtocolId).collect(),
                trusted_host_fingerprint: trusted_fingerprint,
                hoster,
                jump_via: jump_via.map(ServerId),
                usage_coefficient,
            };
            reg.validate_server(&server)?;
            inv.add_server(&server).await?;
            // Whitelist what goes into audit_log — if Server ever gains a
            // sensitive field (api token, jump credentials), serializing
            // the whole struct would silently leak it. Be explicit.
            let audit_payload = json!({
                "id": server.id.0,
                "address": server.address,
                "ssh_port": server.ssh_port,
                "ssh_user": server.ssh_user,
                "kernels": server.kernels.iter().map(|k| &k.0).collect::<Vec<_>>(),
                "hoster": server.hoster,
                "protocols": server.enabled_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
            });
            inv.audit("cli", "server.add", Some(&id), Some(&audit_payload))
                .await?;
            ui::print(format, &json!({ "id": id, "added": true }), |_| {
                println!("server '{id}' added");
                Ok(())
            })
        }

        ServerCmd::List => {
            let servers = inv.list_servers().await?;
            ui::print(format, &servers, |srv| {
                if srv.is_empty() {
                    println!("(no servers)");
                    return Ok(());
                }
                let rows = srv.iter().map(|s| {
                    [
                        s.id.0.clone(),
                        s.address.clone(),
                        s.ssh_port.to_string(),
                        s.kernels
                            .iter()
                            .map(|k| k.0.clone())
                            .collect::<Vec<_>>()
                            .join(","),
                        s.hoster.clone(),
                        s.enabled_protocols
                            .iter()
                            .map(|p| p.0.clone())
                            .collect::<Vec<_>>()
                            .join(","),
                    ]
                });
                println!(
                    "{}",
                    ui::table(
                        ["id", "address", "port", "kernel", "hoster", "protocols"],
                        rows
                    )
                );
                Ok(())
            })
        }

        ServerCmd::Show { id } => {
            let sid = ServerId(id.clone());
            let server = inv
                .get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {id}"))?;
            let secrets_keys: Vec<String> =
                inv.list_server_secrets(&sid).await?.into_keys().collect();
            let payload = json!({
                "server": server,
                "secret_keys": secrets_keys,
            });
            ui::print(format, &payload, |_| {
                println!("id            : {}", server.id.0);
                println!("address       : {}:{}", server.address, server.ssh_port);
                println!("ssh_user      : {}", server.ssh_user);
                println!(
                    "kernels       : {}",
                    server
                        .kernels
                        .iter()
                        .map(|k| k.0.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("hoster        : {}", server.hoster);
                println!(
                    "protocols     : {}",
                    server
                        .enabled_protocols
                        .iter()
                        .map(|p| p.0.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!(
                    "host_fp       : {}",
                    server
                        .trusted_host_fingerprint
                        .as_deref()
                        .unwrap_or("(unset, TOFU)")
                );
                println!(
                    "jump_via      : {}",
                    server
                        .jump_via
                        .as_ref()
                        .map_or("(none)".to_string(), |v| v.0.clone())
                );
                println!("usage_coef    : {}", server.usage_coefficient);
                if !secrets_keys.is_empty() {
                    println!("secret_keys   : {}", secrets_keys.join(", "));
                }
                Ok(())
            })
        }

        ServerCmd::Remove { id, yes } => {
            if !yes {
                println!("dry-run: pass --yes to actually remove server '{id}'");
                return Ok(());
            }
            inv.remove_server(&ServerId(id.clone())).await?;
            inv.audit("cli", "server.remove", Some(&id), None).await?;
            println!("server '{id}' removed");
            Ok(())
        }

        ServerCmd::Secret { server, key, value } => {
            let sid = ServerId(server.clone());
            // Make sure the server exists (FK would have caught it on insert,
            // but this gives a clearer error).
            if inv.get_server(&sid).await?.is_none() {
                return Err(anyhow::anyhow!("no such server: {server}"));
            }
            inv.set_server_secret(&sid, &key, &value).await?;
            inv.audit(
                "cli",
                "server.secret.set",
                Some(&server),
                Some(&json!({ "key": key })),
            )
            .await?;
            println!("set secret '{key}' on server '{server}'");
            Ok(())
        }

        ServerCmd::SetFingerprint {
            id,
            fingerprint,
            from_keyscan,
        } => {
            let sid = ServerId(id.clone());
            let server = inv
                .get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {id}"))?;
            let fp = match (fingerprint, from_keyscan) {
                (Some(f), false) => f,
                (None, true) => {
                    println!(
                        "→ ssh-keyscan -t ed25519 -p {} {} ...",
                        server.ssh_port, server.address
                    );
                    fetch_fingerprint_via_keyscan(&server.address, server.ssh_port)?
                }
                _ => anyhow::bail!(
                    "supply either <FINGERPRINT> or --from-keyscan (not both, not neither)"
                ),
            };
            if !is_valid_sha256_fingerprint(&fp) {
                anyhow::bail!(
                    "fingerprint '{fp}' doesn't look like SHA256:<43-char-base64>; expected the \
                     output of `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -` (the 2nd column)"
                );
            }
            inv.update_trusted_fingerprint(&sid, &fp).await?;
            inv.audit(
                "cli",
                "server.set_fingerprint",
                Some(&id),
                Some(&json!({
                    "fingerprint": fp,
                    "source": if from_keyscan { "ssh-keyscan" } else { "operator-provided" },
                })),
            )
            .await?;
            println!("set trusted_host_fingerprint on server '{id}' to {fp}");
            Ok(())
        }
    }
}

/// Lightweight syntactic check for `SHA256:<base64>` — same shape
/// validation as in the existing inventory `is_valid_fingerprint`
/// (rejects shells of `SHA256:` with no body, MD5 prefixes, etc).
/// We deliberately don't decode the base64 — at the CLI layer
/// shape-equality is enough; the inventory layer applies the same
/// check at INSERT/UPDATE time as the actual gate.
fn is_valid_sha256_fingerprint(fp: &str) -> bool {
    let Some(rest) = fp.strip_prefix("SHA256:") else {
        return false;
    };
    // base64-url + base64 padding chars; allow a trailing `=` since
    // some emitters keep it. SHA-256 = 32 bytes = 43 base64 chars.
    if rest.is_empty() || rest.len() > 44 {
        return false;
    }
    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-' | '='))
}

/// Run `ssh-keyscan -t ed25519 -p <port> <host> | ssh-keygen -lf -`
/// in two stages via `std::process::Command` and return the SHA256
/// fingerprint (second whitespace-token of `ssh-keygen -lf -` output).
/// Errors map to `anyhow::Error` with the failing stage in the message
/// so the operator can re-run by hand if either tool is unhappy.
fn fetch_fingerprint_via_keyscan(host: &str, port: u16) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};
    // Stage 1: ssh-keyscan emits the public key on stdout.
    let scan = Command::new("ssh-keyscan")
        .args(["-t", "ed25519", "-p", &port.to_string(), host])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("ssh-keyscan failed to run: {e}"))?;
    if !scan.status.success() {
        anyhow::bail!(
            "ssh-keyscan exited {:?}; is the host reachable on port {port}?",
            scan.status.code()
        );
    }
    if scan.stdout.is_empty() {
        anyhow::bail!("ssh-keyscan returned empty output (host unreachable or no ed25519 key?)");
    }
    // Stage 2: pipe into ssh-keygen -lf -.
    let mut child = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("ssh-keygen failed to spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(&scan.stdout)?;
    }
    let keygen = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("ssh-keygen wait failed: {e}"))?;
    if !keygen.status.success() {
        anyhow::bail!("ssh-keygen -lf - exited {:?}", keygen.status.code());
    }
    // Output: `256 SHA256:+cuHezsj... root@host (ED25519)` — second
    // whitespace-token is the fingerprint.
    let text = String::from_utf8_lossy(&keygen.stdout);
    text.split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("ssh-keygen output had no fingerprint token: {text}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_sha256_fingerprint() {
        assert!(is_valid_sha256_fingerprint(
            "SHA256:+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
        ));
    }

    #[test]
    fn rejects_md5_or_missing_prefix() {
        assert!(!is_valid_sha256_fingerprint(
            "MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        ));
        assert!(!is_valid_sha256_fingerprint(
            "+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
        ));
        assert!(!is_valid_sha256_fingerprint(""));
        assert!(!is_valid_sha256_fingerprint("SHA256:"));
    }

    #[test]
    fn rejects_oversized_body() {
        let too_long = format!("SHA256:{}", "A".repeat(50));
        assert!(!is_valid_sha256_fingerprint(&too_long));
    }
}
