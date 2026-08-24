//! `vpnctl sub <user>` — собирает share-link'и для всех серверов, на которые
//! у юзера есть grant. По одной строке на (server, protocol). С `--qr` —
//! ASCII QR-код под каждым линком, удобно сканировать с телефона.
//!
//! Subscription policy parity (2026-06-04): this command applies the SAME
//! policy the daemon's `/sub/<token>` + `/api/v1/app/config/<device_id>`
//! handlers apply (`daemon/src/handlers/sub.rs`) — a disabled user has an
//! empty subscription, auto-suppressed servers are skipped, and hidden /
//! per-user-denied protocols are filtered. Previously the CLI walked
//! `server.enabled_protocols` raw and leaked links the live endpoints
//! would never serve. `--ignore-policy` restores the old raw behaviour for
//! debugging.

use crate::{OutputFormat, ui};
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

    // Captured for the empty-state copy so the operator can tell a
    // policy-muted subscription apart from a genuinely un-granted user.
    let user_disabled = user.disabled;

    ui::print(format, &entries, |entries| {
        if entries.is_empty() {
            if user_disabled && !ignore_policy {
                println!("(user '{user_id}' is disabled — subscription is empty)");
            } else {
                // Could be no grants at all, OR grants whose every server
                // is auto-suppressed / every protocol hidden — don't claim
                // "no grants" definitively (operator would chase a ghost).
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

/// Resolve which `(server, protocols)` the user's subscription should
/// render, applying the SAME policy the daemon's `/sub` +
/// `/api/v1/app/config` handlers apply (`daemon/src/handlers/sub.rs`):
///
///   * a `disabled` user has an EMPTY subscription;
///   * an auto-suppressed server (health monitor flagged it unreachable,
///     per-server opt-in; migration 0030) is skipped;
///   * per-(user, server, protocol) visibility filters out hidden
///     protocols and per-user deny overrides (migration 0018).
///
/// `ignore_policy` bypasses ALL THREE — the operator then sees every raw
/// share-link regardless of subscription policy.
///
/// NOTE: this deliberately does NOT apply
/// [`vpnctl_core::Protocol::appears_in_sing_box_sub`] — the CLI emits raw
/// share-links, not a sing-box JSON envelope, so non-sing-box protocols
/// are intentionally still printed (unlike the daemon's JSON `/sub` path).
async fn resolve_sub_targets(
    inv: &SqliteInventory,
    user: &User,
    ignore_policy: bool,
) -> anyhow::Result<Vec<(Server, Vec<ProtocolId>)>> {
    // Disabled-user soft mute (B1.user, migration 0026) — empty sub.
    if user.disabled && !ignore_policy {
        return Ok(Vec::new());
    }

    let servers = inv.servers_for_user(&user.id).await?;
    let mut out: Vec<(Server, Vec<ProtocolId>)> = Vec::new();

    for server in servers {
        // Auto-suppress (migration 0030): skip a server the health monitor
        // flagged unreachable. DB error → don't suppress (keep it in the
        // sub), matching the daemon's `unwrap_or(false)`.
        if !ignore_policy
            && inv
                .is_server_auto_suppressed(&server.id)
                .await
                .unwrap_or(false)
        {
            continue;
        }

        // Visibility filter (migration 0018): hidden protocols +
        // per-(user, server) deny overrides. `None` under --ignore-policy
        // means "no filtering".
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

        // Preserve `server.enabled_protocols` order (matches the daemon's
        // per-server render loop), filtering through the visibility set.
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

/// Build the printable share-link entries for `user`, after the policy
/// filter in [`resolve_sub_targets`]. Render failures (e.g. a protocol
/// whose server secret isn't minted yet) warn to stderr and skip — the
/// rest of the subscription still prints.
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
        // WireGuard's share_link reads `ctx.peers` to assign the right
        // /32 per user — pass the granted-users list. Other protocols
        // ignore the field. `users_for_server` already overrides each
        // peer's `uuid` to the per-server `grants.client_uuid` value
        // (migration 0016) so this list matches what the server's
        // sing-box expects.
        let peers = inv.users_for_server(&server.id).await?;
        let ctx = RenderCtx::with_peers(server, &secrets, &peers);

        // Per-server UUID override for the user we're about to mint
        // share-links for (Phase 1 of the ninitux merge — see migration
        // `0016_grants_per_server_uuid.sql`). For grants that haven't had
        // their `client_uuid` overridden the helper returns the user
        // unchanged — byte-identical rendering to the pre-Phase-1 behaviour.
        let per_server_user = inv.user_with_per_server_uuid(user, &server.id).await?;

        for pid in protocols {
            let Some(proto) = registry.protocol(pid) else {
                eprintln!("warn: protocol '{pid}' not registered, skipping");
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
                Ok(link) => entries.push(LinkEntry {
                    server: server.id.0.clone(),
                    protocol: pid.0.clone(),
                    link,
                }),
                Err(e) => eprintln!("warn: cannot build link for {}/{}: {e}", server.id.0, pid.0),
            }
        }
    }
    Ok(entries)
}

/// Render the link as a Unicode-block QR sized to fit a normal terminal.
/// Best-effort: oversized URLs (>~2.5 KB) overflow QR capacity — we
/// warn but don't bail (the link itself is still printed above).
fn render_qr(link: &str, server: &str, protocol: &str) {
    match QrCode::new(link.as_bytes()) {
        Ok(code) => {
            // Dense1x2 packs one QR module into half a terminal cell —
            // good readability without dominating the screen. We invert
            // dark/light because most terminals are dark-on-light:
            // contrasting "filled" blocks make the camera scan reliably.
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
    //! Regression net for the subscription-policy drift: `vpnctl sub` must
    //! apply the SAME disabled-user / auto-suppress / per-protocol
    //! visibility policy the daemon's `/sub` handler does. The policy
    //! primitives themselves are pinned at the inventory layer
    //! (`crates/inventory/tests/spec_protocol_visibility.rs` etc.); these
    //! tests prove the CLI path actually CALLS them.

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

    /// `resolve_sub_targets` → sorted `"server/protocol"` strings.
    fn flatten(targets: &[(Server, Vec<ProtocolId>)]) -> Vec<String> {
        let mut out: Vec<String> = targets
            .iter()
            .flat_map(|(s, ps)| ps.iter().map(move |p| format!("{}/{}", s.id.0, p.0)))
            .collect();
        out.sort();
        out
    }

    /// Standard fixture: one server `de` with two protocols, granted to
    /// `alice`. Returns the TempDir (keep it alive) + the inventory.
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
        // Opt in to auto-suppress, then mark the server suppressed (the
        // health-monitor-driven runtime flag).
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
        // Pile every suppression on at once.
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
        // --ignore-policy → every raw (server, protocol) pair still emitted.
        assert_eq!(
            targets(&inv, "alice", true).await,
            vec!["de/tuic-v5", "de/vless+reality"]
        );
    }
}
