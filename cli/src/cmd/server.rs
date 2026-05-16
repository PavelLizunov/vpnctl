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
    }
}
