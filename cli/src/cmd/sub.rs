use crate::{OutputFormat, ui};
use anyhow::Context;
use qrcode::QrCode;
use qrcode::render::unicode;
use serde::Serialize;
use std::collections::HashSet;
use std::path::PathBuf;
use vpnctl_core::{ProtocolId, Registry, RenderCtx, Server, User, UserId};
use vpnctl_inventory::SqliteInventory;

#[derive(Serialize)]
struct LinkEntry {
    server: String,
    protocol: String,
    link: String,
}

pub(crate) async fn run(
    user_id: &str,
    qr: bool,
    ignore_policy: bool,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user_id.to_string());
    let user = inv
        .get_user(&uid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such user: {user_id}"))?;

    if ignore_policy {
        eprintln!(
            "note: --ignore-policy set — output may include links the live subscription \
             would suppress (disabled user, hidden/denied protocols, auto-suppressed servers)"
        );
    }

    let registry = crate::registry::build()?;
    let entries = collect_links(&inv, &registry, &user, ignore_policy).await?;

    let user_disabled = user.disabled;

    ui::print(format, &entries, |entries| {
        if entries.is_empty() {
            if user_disabled && !ignore_policy {
                println!("(user '{user_id}' is disabled — subscription is empty)");
            } else {
                println!(
                    "(no deliverable links for user '{user_id}' — no grants, or every \
                     granted server/protocol is hidden or auto-suppressed)"
                );
            }
            return Ok(());
        }
        for e in entries {
            println!("# {} via {}", e.server, e.protocol);
            println!("{}", e.link);
            if qr {
                render_qr(&e.link, &e.server, &e.protocol);
            }
            println!();
        }
        Ok(())
    })
}

async fn resolve_sub_targets(
    inv: &SqliteInventory,
    user: &User,
    ignore_policy: bool,
) -> anyhow::Result<Vec<(Server, Vec<ProtocolId>)>> {
    if user.disabled && !ignore_policy {
        return Ok(Vec::new());
    }

    let servers = inv.subscription_servers_for_user(&user.id).await?;
    let mut out: Vec<(Server, Vec<ProtocolId>)> = Vec::new();

    for server in servers {
        if !ignore_policy
            && inv
                .is_server_auto_suppressed(&server.id)
                .await
                .unwrap_or(false)
        {
            continue;
        }
        if !ignore_policy && inv.client_detour_via(&server.id).await?.is_some() {
            continue;
        }

        let visible: Option<HashSet<ProtocolId>> = if ignore_policy {
            None
        } else {
            Some(
                inv.visible_protocols_for_subscription(&user.id, &server.id)
                    .await?
                    .into_iter()
                    .collect(),
            )
        };

        let protocols: Vec<ProtocolId> = server
            .enabled_protocols
            .iter()
            .filter(|pid| visible.as_ref().is_none_or(|set| set.contains(*pid)))
            .cloned()
            .collect();
        out.push((server, protocols));
    }
    Ok(out)
}

async fn collect_links(
    inv: &SqliteInventory,
    registry: &Registry,
    user: &User,
    ignore_policy: bool,
) -> anyhow::Result<Vec<LinkEntry>> {
    let targets = resolve_sub_targets(inv, user, ignore_policy).await?;

    let mut entries: Vec<LinkEntry> = Vec::new();
    for (server, protocols) in &targets {
        if protocols.is_empty() {
            continue;
        }
        let secrets = inv.list_server_secrets(&server.id).await?;
        let peers = inv.users_for_server(&server.id).await?;
        let ctx = RenderCtx::with_peers(server, &secrets, &peers);

        let per_server_user = inv.user_with_per_server_uuid(user, &server.id).await?;

        for pid in protocols {
            let proto = registry
                .protocol(pid)
                .ok_or_else(|| anyhow::anyhow!("protocol '{pid}' not registered"))?;
            let link = proto
                .share_link(&ctx, &per_server_user)
                .with_context(|| format!("cannot build link for {}/{}", server.id.0, pid.0))?;
            entries.push(LinkEntry {
                server: server.id.0.clone(),
                protocol: pid.0.clone(),
                link,
            });
        }
    }
    Ok(entries)
}

fn render_qr(link: &str, server: &str, protocol: &str) {
    match QrCode::new(link.as_bytes()) {
        Ok(code) => {
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{image}");
        }
        Err(err) => {
            eprintln!("warn: QR generation failed for {server}/{protocol}: {err}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;
    use tempfile::TempDir;
    use vpnctl_core::{KernelId, ServerId};

    fn srv(id: &str, protocols: &[&str]) -> Server {
        Server {
            id: ServerId(id.into()),
            address: format!("{id}.example.com"),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: protocols.iter().map(|p| ProtocolId((*p).into())).collect(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn usr(id: &str) -> User {
        User {
            id: UserId(id.into()),
            uuid: format!("uuid-{id}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    async fn open(dir: &TempDir) -> SqliteInventory {
        SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .expect("open")
    }

    fn flatten(targets: &[(Server, Vec<ProtocolId>)]) -> Vec<String> {
        let mut out: Vec<String> = targets
            .iter()
            .flat_map(|(s, ps)| ps.iter().map(move |p| format!("{}/{}", s.id.0, p.0)))
            .collect();
        out.sort();
        out
    }

    async fn setup() -> (TempDir, SqliteInventory) {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        inv.add_server(&srv("de", &["vless+reality", "tuic-v5"]))
            .await
            .unwrap();
        inv.add_user(&usr("alice")).await.unwrap();
        inv.grant(&UserId("alice".into()), &ServerId("de".into()))
            .await
            .unwrap();
        (dir, inv)
    }

    async fn targets(inv: &SqliteInventory, who: &str, ignore_policy: bool) -> Vec<String> {
        let user = inv.get_user(&UserId(who.into())).await.unwrap().unwrap();
        let t = resolve_sub_targets(inv, &user, ignore_policy)
            .await
            .unwrap();
        flatten(&t)
    }

    #[tokio::test]
    async fn link_generation_errors_are_propagated() {
        let (_dir, inv) = setup().await;
        let user = inv
            .get_user(&UserId("alice".into()))
            .await
            .unwrap()
            .unwrap();
        let registry = crate::registry::build().unwrap();
        let error = collect_links(&inv, &registry, &user, false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("cannot build link for de/"));
        let empty_registry = Registry::new();
        let error = collect_links(&inv, &empty_registry, &user, false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("not registered"));
    }

    #[tokio::test]
    async fn default_policy_emits_all_visible_protocols() {
        let (_d, inv) = setup().await;
        assert_eq!(
            targets(&inv, "alice", false).await,
            vec!["de/tuic-v5", "de/vless+reality"]
        );
    }

    #[tokio::test]
    async fn hidden_protocol_is_excluded() {
        let (_d, inv) = setup().await;
        inv.set_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()), true)
            .await
            .unwrap();
        assert_eq!(
            targets(&inv, "alice", false).await,
            vec!["de/vless+reality"]
        );
    }

    #[tokio::test]
    async fn per_user_protocol_override_is_excluded() {
        let (_d, inv) = setup().await;
        inv.set_grant_protocol_override(
            &UserId("alice".into()),
            &ServerId("de".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
        assert_eq!(targets(&inv, "alice", false).await, vec!["de/tuic-v5"]);
    }

    #[tokio::test]
    async fn disabled_user_has_empty_subscription() {
        let (_d, inv) = setup().await;
        inv.set_user_disabled(&UserId("alice".into()), true)
            .await
            .unwrap();
        assert!(
            targets(&inv, "alice", false).await.is_empty(),
            "disabled user must get an empty subscription (parity with /sub)"
        );
    }

    #[tokio::test]
    async fn auto_suppressed_server_is_skipped() {
        let (_d, inv) = setup().await;
        inv.set_server_auto_suppress(&ServerId("de".into()), true)
            .await
            .unwrap();
        inv.set_server_suppressed(&ServerId("de".into()), true)
            .await
            .unwrap();
        assert!(
            targets(&inv, "alice", false).await.is_empty(),
            "auto-suppressed server must be skipped (parity with /sub)"
        );
    }

    #[tokio::test]
    async fn ignore_policy_bypasses_every_filter() {
        let (_d, inv) = setup().await;
        inv.set_user_disabled(&UserId("alice".into()), true)
            .await
            .unwrap();
        inv.set_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()), true)
            .await
            .unwrap();
        inv.set_server_auto_suppress(&ServerId("de".into()), true)
            .await
            .unwrap();
        inv.set_server_suppressed(&ServerId("de".into()), true)
            .await
            .unwrap();
        assert_eq!(
            targets(&inv, "alice", true).await,
            vec!["de/tuic-v5", "de/vless+reality"]
        );
    }
}
