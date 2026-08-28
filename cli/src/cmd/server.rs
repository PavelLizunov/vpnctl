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
        /// Kernel id (must be registered): "sing-box", future: "xray".
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
        /// Opaque secret value. URL-safe base64 secrets (what
        /// `crypto::gen_password` emits) legitimately start with `-`/`_`, so
        /// allow a leading hyphen instead of mis-parsing it as a flag.
        #[arg(allow_hyphen_values = true)]
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

    /// Set the per-server reserved-ports list (migration 0028).
    ///
    /// Any port in this list will be REFUSED by the sing-box pre-
    /// apply guard, so `vpnctl deploy <id>` (and the equivalent
    /// web button) cannot accidentally overwrite a co-tenant
    /// service. Typical use: a host running both vpnctl-managed
    /// sing-box AND a legacy 3x-ui Docker container on :443 — pin
    /// `set-reserved-ports <id> 443,2053,2096` so vpnctl can never
    /// bind those ports.
    ///
    /// Pass an empty list (`set-reserved-ports <id> ""`) to clear.
    SetReservedPorts {
        /// Server id (e.g. `ru`).
        id: String,
        /// Comma-separated list of u16 port numbers
        /// (e.g. `443,2053,2096`). Empty string clears the list.
        ports: String,
    },

    /// Set server policy role: `vpn-exit` or `workload-only`.
    SetRole { id: String, role: String },

    /// Route management SSH through one inventory server; omit jump id to clear.
    SetJumpVia {
        id: String,
        #[arg(required_unless_present = "clear")]
        jump: Option<String>,
        #[arg(long, conflicts_with = "jump")]
        clear: bool,
    },

    /// Route client VPN traffic through an upstream entry server; omit upstream to clear with --clear.
    SetClientDetourVia {
        target: String,
        #[arg(required_unless_present = "clear")]
        upstream: Option<String>,
        #[arg(long, conflicts_with = "upstream")]
        clear: bool,
    },

    /// Hide a server protocol from client subscription / config generation.
    ProtocolHide {
        /// Server id (e.g. "fra-01").
        server: String,
        /// Protocol id (e.g. "vless+reality", "tuic-v5").
        protocol: String,
    },

    /// Unhide a server protocol so it appears in client configs again.
    ProtocolUnhide {
        /// Server id (e.g. "fra-01").
        server: String,
        /// Protocol id (e.g. "vless+reality", "tuic-v5").
        protocol: String,
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
            // Support-only validation: a freshly-added server has no
            // secrets yet (`vpnctl server secret` needs the existing id),
            // so the secret-aware port-conflict gate runs at deploy time,
            // where real secrets are available.
            reg.validate_server_support(&server)?;
            if let Some(existing) = inv.server_id_for_address(&server.address).await? {
                anyhow::bail!(
                    "address '{}' is already registered to server '{existing}' — one node = one server record; edit '{existing}' instead of adding a duplicate",
                    server.address
                );
            }
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
            let detour_via = inv.client_detour_via(&sid).await?;
            let payload = json!({
                "server": server,
                "secret_keys": secrets_keys,
                "client_detour_via": detour_via.as_ref().map(|v| &v.0),
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
                println!(
                    "client_detour : {}",
                    detour_via
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
                        "→ ssh-keyscan -t ed25519,rsa -p {} -- {} ...",
                        server.ssh_port, server.address
                    );
                    vpnctl_host_fingerprint::fetch_via_keyscan(&server.address, server.ssh_port)
                        .map_err(|e| anyhow::anyhow!("ssh-keyscan: {e}"))?
                }
                _ => anyhow::bail!(
                    "supply either <FINGERPRINT> or --from-keyscan (not both, not neither)"
                ),
            };
            if !vpnctl_host_fingerprint::validate_shape(&fp) {
                anyhow::bail!(
                    "fingerprint '{fp}' doesn't look like SHA256:<43-char-base64>; expected the \
                     output of `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -` (the 2nd column)"
                );
            }
            // Capture previous fingerprint BEFORE overwriting — a TOFU-pin
            // rotation has very different forensic implications depending on
            // whether the operator rebuilt the node (legit) or someone is
            // MITM-rotating the key (attack). Audit row keeps both halves
            // so future review can distinguish without grepping snapshots.
            let previous = server.trusted_host_fingerprint.clone();
            inv.update_trusted_fingerprint(&sid, &fp).await?;
            // Dot-convention name + NM-10 no-op gate, in lockstep with
            // the daemon handler (renamed there 2026-06-10): a same-
            // value re-pin writes nothing; a real change writes
            // `server.fingerprint.set` so `server.fingerprint.`-prefix
            // filtering sees BOTH entry points.
            if previous.as_deref() != Some(fp.as_str()) {
                inv.audit(
                    "cli",
                    "server.fingerprint.set",
                    Some(&id),
                    Some(&json!({
                        "fingerprint": fp,
                        "previous": previous,
                        "source": if from_keyscan { "ssh-keyscan" } else { "operator-provided" },
                    })),
                )
                .await?;
            }
            println!("set trusted_host_fingerprint on server '{id}' to {fp}");
            Ok(())
        }

        ServerCmd::SetReservedPorts { id, ports } => {
            let sid = ServerId(id.clone());
            // Confirm the server exists — clearer error than the
            // inventory's "no such server" which only fires inside
            // set_reserved_ports.
            inv.get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {id}"))?;
            let parsed = parse_reserved_ports(&ports)?;
            inv.set_reserved_ports(&sid, &parsed).await?;
            if parsed.is_empty() {
                println!("cleared reserved_ports on server '{id}'");
            } else {
                println!("set reserved_ports on server '{id}' to {parsed:?}");
            }
            Ok(())
        }

        ServerCmd::SetRole { id, role } => {
            let role: vpnctl_inventory::ServerRole = role.parse()?;
            let sid = ServerId(id.clone());
            let server = inv
                .get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {id}"))?;
            inv.set_server_routing_policy_as("cli", &sid, role, server.jump_via.as_ref())
                .await?;
            ui::print(format, &json!({"id": id, "role": role.as_str()}), |_| {
                println!("server '{id}' role set to {}", role.as_str());
                Ok(())
            })
        }
        ServerCmd::SetJumpVia { id, jump, clear: _ } => {
            let jump = jump.map(ServerId);
            let sid = ServerId(id.clone());
            let role = inv.get_server_role(&sid).await?;
            inv.set_server_routing_policy_as("cli", &sid, role, jump.as_ref())
                .await?;
            ui::print(
                format,
                &json!({"id": id, "jump_via": jump.as_ref().map(|v| &v.0)}),
                |_| {
                    println!("server '{id}' jump_via updated");
                    Ok(())
                },
            )
        }
        ServerCmd::SetClientDetourVia {
            target,
            upstream,
            clear: _,
        } => {
            let upstream = upstream.map(ServerId);
            let target_sid = ServerId(target.clone());
            inv.set_client_detour_via_as("cli", &target_sid, upstream.as_ref())
                .await?;
            ui::print(
                format,
                &json!({"target": target, "client_detour_via": upstream.as_ref().map(|v| &v.0)}),
                |_| {
                    println!("server '{target}' client_detour_via updated");
                    Ok(())
                },
            )
        }
        ServerCmd::ProtocolHide { server, protocol } => {
            let sid = ServerId(server.clone());
            let pid = ProtocolId(protocol.clone());
            inv.set_server_protocol_hidden(&sid, &pid, true).await?;
            println!("hid protocol '{protocol}' on server '{server}'");
            Ok(())
        }

        ServerCmd::ProtocolUnhide { server, protocol } => {
            let sid = ServerId(server.clone());
            let pid = ProtocolId(protocol.clone());
            inv.set_server_protocol_hidden(&sid, &pid, false).await?;
            println!("unhid protocol '{protocol}' on server '{server}'");
            Ok(())
        }
    }
}

/// Parse a comma-separated port list into a sorted-dedup Vec<u16>.
/// Empty string → empty vec (used to CLEAR a reservation). Caller
/// gets a friendly anyhow::Error on any malformed token, including
/// the offending value spelled out so the operator doesn't have to
/// guess which slot failed.
fn parse_reserved_ports(raw: &str) -> anyhow::Result<Vec<u16>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for tok in trimmed.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let port: u16 = t
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid port '{t}': {e}"))?;
        if port == 0 {
            anyhow::bail!("port 0 is not valid; allowed range 1..=65535");
        }
        out.push(port);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

// SHA256 shape validation + ssh-keyscan/-keygen fingerprint fetching live
// in `vpnctl-host-fingerprint`. Three call-sites used to inline near-
// duplicates of those routines — the wizard's copy was missing the `--`
// flag-injection defense and the validators had drifted on URL-safe
// base64 acceptance. The crate is the single source of truth; spec
// tests for both functions live there.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn server_add_duplicate_address_is_rejected_before_mutation() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");

        run(
            ServerCmd::Add {
                id: "fra-01".into(),
                address: "203.0.113.10".into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernel: "sing-box".into(),
                hoster: "generic".into(),
                protocols: vec!["vless+reality".into()],
                jump_via: None,
                trusted_fingerprint: None,
                usage_coefficient: 1.0,
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        let err = run(
            ServerCmd::Add {
                id: "fra-02".into(),
                address: "203.0.113.10".into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernel: "sing-box".into(),
                hoster: "generic".into(),
                protocols: vec!["vless+reality".into()],
                jump_via: None,
                trusted_fingerprint: None,
                usage_coefficient: 1.0,
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("address '203.0.113.10' is already registered to server 'fra-01'"),
            "unexpected error message: {err}"
        );

        let inv = SqliteInventory::open(&db_path).await.unwrap();
        assert!(
            inv.get_server(&ServerId("fra-02".into()))
                .await
                .unwrap()
                .is_none(),
            "duplicate server record must not be added"
        );
        let audit = inv.recent_audit(10).await.unwrap();
        assert!(
            audit.iter().all(|a| a.target.as_deref() != Some("fra-02")),
            "audit log must not contain entry for rejected duplicate server add"
        );
    }

    async fn setup_test_server(db_path: &std::path::Path) -> SqliteInventory {
        let inv = SqliteInventory::open(db_path).await.unwrap();
        let server = Server {
            id: ServerId("s1".into()),
            address: "203.0.113.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();
        inv
    }

    #[tokio::test]
    async fn server_protocol_hide_and_unhide() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let inv = setup_test_server(&db_path).await;

        let sid = ServerId("s1".into());
        let pid = ProtocolId("tuic-v5".into());

        assert!(
            !inv.is_server_protocol_hidden(&sid, &pid).await.unwrap(),
            "protocol must initially not be hidden"
        );

        run(
            ServerCmd::ProtocolHide {
                server: "s1".into(),
                protocol: "tuic-v5".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        assert!(
            inv.is_server_protocol_hidden(&sid, &pid).await.unwrap(),
            "protocol must be hidden after protocol-hide"
        );

        let audit = inv.recent_audit(10).await.unwrap();
        let hide_events: Vec<_> = audit
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .collect();
        assert_eq!(hide_events.len(), 1, "hide must write exactly 1 audit row");
        assert_eq!(hide_events[0].target.as_deref(), Some("s1"));
        let payload = hide_events[0].payload.as_ref().unwrap();
        assert_eq!(payload["protocol_id"], "tuic-v5");
        assert_eq!(payload["new_hidden"], true);

        run(
            ServerCmd::ProtocolUnhide {
                server: "s1".into(),
                protocol: "tuic-v5".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        assert!(
            !inv.is_server_protocol_hidden(&sid, &pid).await.unwrap(),
            "protocol must not be hidden after protocol-unhide"
        );

        let audit2 = inv.recent_audit(10).await.unwrap();
        let hide_events2: Vec<_> = audit2
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .collect();
        assert_eq!(hide_events2.len(), 2, "unhide must write 2nd audit row");
        let payload2 = hide_events2[0].payload.as_ref().unwrap();
        assert_eq!(payload2["protocol_id"], "tuic-v5");
        assert_eq!(payload2["new_hidden"], false);
    }

    #[tokio::test]
    async fn server_protocol_hide_unhide_noop_does_not_duplicate_audit() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let inv = setup_test_server(&db_path).await;

        // Hide first time -> 1 audit row
        run(
            ServerCmd::ProtocolHide {
                server: "s1".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        let audit1 = inv.recent_audit(10).await.unwrap();
        let count1 = audit1
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .count();
        assert_eq!(count1, 1, "first hide must produce 1 audit row");

        // Hide second time (no-op) -> still 1 audit row
        run(
            ServerCmd::ProtocolHide {
                server: "s1".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        let audit2 = inv.recent_audit(10).await.unwrap();
        let count2 = audit2
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .count();
        assert_eq!(count2, 1, "no-op hide must not duplicate audit log");

        // Unhide first time -> 2 audit rows
        run(
            ServerCmd::ProtocolUnhide {
                server: "s1".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        let audit3 = inv.recent_audit(10).await.unwrap();
        let count3 = audit3
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .count();
        assert_eq!(count3, 2, "first unhide must produce 2nd audit row");

        // Unhide second time (no-op) -> still 2 audit rows
        run(
            ServerCmd::ProtocolUnhide {
                server: "s1".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        let audit4 = inv.recent_audit(10).await.unwrap();
        let count4 = audit4
            .iter()
            .filter(|a| a.action == "server.protocol.set_hidden")
            .count();
        assert_eq!(count4, 2, "no-op unhide must not duplicate audit log");
    }

    #[tokio::test]
    async fn server_protocol_hide_unhide_missing_protocol_or_server_fails() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let inv = setup_test_server(&db_path).await;

        // Missing protocol on existing server
        let err_hide_proto = run(
            ServerCmd::ProtocolHide {
                server: "s1".into(),
                protocol: "wireguard".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(
            err_hide_proto
                .to_string()
                .contains("no such server_protocols row"),
            "unexpected error: {err_hide_proto}"
        );

        let err_unhide_proto = run(
            ServerCmd::ProtocolUnhide {
                server: "s1".into(),
                protocol: "wireguard".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(
            err_unhide_proto
                .to_string()
                .contains("no such server_protocols row"),
            "unexpected error: {err_unhide_proto}"
        );

        // Missing server
        let err_hide_srv = run(
            ServerCmd::ProtocolHide {
                server: "nonexistent".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(
            err_hide_srv
                .to_string()
                .contains("no such server_protocols row"),
            "unexpected error: {err_hide_srv}"
        );

        let err_unhide_srv = run(
            ServerCmd::ProtocolUnhide {
                server: "nonexistent".into(),
                protocol: "vless+reality".into(),
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(
            err_unhide_srv
                .to_string()
                .contains("no such server_protocols row"),
            "unexpected error: {err_unhide_srv}"
        );

        // Verify no audit log was created for failed calls
        let audit = inv.recent_audit(10).await.unwrap();
        assert!(
            audit
                .iter()
                .all(|a| a.action != "server.protocol.set_hidden"),
            "no audit log must be written on failure"
        );
    }

    #[tokio::test]
    async fn server_set_client_detour_via_and_show() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let inv = setup_test_server(&db_path).await;

        let s2 = Server {
            id: ServerId("s2".into()),
            address: "203.0.113.2".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&s2).await.unwrap();

        run(
            ServerCmd::SetClientDetourVia {
                target: "s1".into(),
                upstream: Some("s2".into()),
                clear: false,
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        assert_eq!(
            inv.client_detour_via(&ServerId("s1".into())).await.unwrap(),
            Some(ServerId("s2".into()))
        );

        run(
            ServerCmd::Show { id: "s1".into() },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        run(
            ServerCmd::SetClientDetourVia {
                target: "s1".into(),
                upstream: None,
                clear: true,
            },
            Some(db_path.clone()),
            OutputFormat::Text,
        )
        .await
        .unwrap();

        assert_eq!(
            inv.client_detour_via(&ServerId("s1".into())).await.unwrap(),
            None
        );
    }
}
