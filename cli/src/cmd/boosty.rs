//! `vpnctl boosty` — reconcile VPN access with Boosty subscription state,
//! plus link/configure helpers. Thin glue over `vpnctl-boosty-bridge`.

use std::path::PathBuf;

use clap::Subcommand;
use serde_json::json;
use vpnctl_boosty_bridge::{ApplyMode, SyncReport, sync_from_settings};
use vpnctl_core::UserId;
use vpnctl_inventory::SqliteInventory;

use crate::ui;

#[derive(Subcommand, Debug)]
pub(crate) enum BoostyCmd {
    /// Reconcile access with the Boosty roster. Dry-run unless `--apply`.
    Sync {
        /// Apply changes (default only prints the plan).
        #[arg(long)]
        apply: bool,
        /// Also auto-disable lapsed subscribers (otherwise they're listed
        /// but left enabled for you to confirm).
        #[arg(long)]
        disable_lapsed: bool,
    },
    /// Link a vpnctl user to a Boosty subscriber id.
    Link { user: String, subscriber_id: i64 },
    /// Remove a user's Boosty link.
    Unlink { user: String },
    /// Show bridge settings (secrets masked) and the link count.
    Status,
    /// Update bridge settings — only the flags you pass are changed.
    Configure {
        #[arg(long)]
        blog: Option<String>,
        #[arg(long)]
        access_token: Option<String>,
        #[arg(long)]
        refresh_token: Option<String>,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        interval_secs: Option<u64>,
        /// Enable the sync poller.
        #[arg(long)]
        enable: bool,
        /// Disable the sync poller.
        #[arg(long)]
        disable: bool,
    },
}

pub(crate) async fn run(cmd: BoostyCmd, db_flag: Option<PathBuf>) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    match cmd {
        BoostyCmd::Sync {
            apply,
            disable_lapsed,
        } => run_sync(&inv, apply, disable_lapsed).await,
        BoostyCmd::Link {
            user,
            subscriber_id,
        } => run_link(&inv, &user, subscriber_id).await,
        BoostyCmd::Unlink { user } => run_unlink(&inv, &user).await,
        BoostyCmd::Status => run_status(&inv).await,
        BoostyCmd::Configure {
            blog,
            access_token,
            refresh_token,
            device_id,
            interval_secs,
            enable,
            disable,
        } => {
            run_configure(
                &inv,
                blog,
                access_token,
                refresh_token,
                device_id,
                interval_secs,
                enable,
                disable,
            )
            .await
        }
    }
}

async fn run_sync(inv: &SqliteInventory, apply: bool, disable_lapsed: bool) -> anyhow::Result<()> {
    let settings = inv.get_boosty_settings().await?;
    let mode = match (apply, disable_lapsed) {
        (false, _) => ApplyMode::DryRun,
        (true, false) => ApplyMode::EnableOnly,
        (true, true) => ApplyMode::Full,
    };

    let report = sync_from_settings(inv, &settings, mode).await?;
    print_report(&report, mode);

    // Applied flips only touch inv.db — the nodes keep serving their old
    // `users[]` until a deploy re-renders their configs. (The daemon's
    // poller/buttons auto-deploy; the CLI is the automation surface, so
    // it prints the exact commands instead.)
    if apply {
        let flipped: Vec<&String> = report
            .enabled
            .iter()
            .chain(report.disabled.iter())
            .collect();
        if !flipped.is_empty() {
            let mut server_ids = std::collections::BTreeSet::new();
            for uid in flipped {
                for s in inv.servers_for_user(&UserId(uid.clone())).await? {
                    server_ids.insert(s.id.0);
                }
            }
            let ids: Vec<String> = server_ids.into_iter().collect();
            print!("{}", deploy_hint(&ids));
        }
    }
    Ok(())
}

/// The post-apply reminder: which servers still run the pre-flip config
/// and the exact command to push each one.
fn deploy_hint(server_ids: &[String]) -> String {
    if server_ids.is_empty() {
        return String::new();
    }
    let mut out = String::from("note: flips are not on the nodes yet — deploy to apply them:\n");
    for id in server_ids {
        out.push_str(&format!("  vpnctl deploy {id}\n"));
    }
    out
}

fn print_report(r: &SyncReport, mode: ApplyMode) {
    let verb = match mode {
        ApplyMode::DryRun => "would",
        _ => "did",
    };
    println!(
        "roster: {} subscribers ({} active), {} linked",
        r.total_subscribers, r.active_subscribers, r.linked
    );
    if !r.enabled.is_empty() {
        println!(
            "{verb} enable ({}): {}",
            r.enabled.len(),
            r.enabled.join(", ")
        );
    }
    if !r.disabled.is_empty() {
        println!(
            "{verb} disable ({}): {}",
            r.disabled.len(),
            r.disabled.join(", ")
        );
    }
    if !r.lapsed_pending.is_empty() {
        println!(
            "lapsed, awaiting confirm ({}): {}",
            r.lapsed_pending.len(),
            r.lapsed_pending.join(", ")
        );
    }
    if !r.new_subscribers.is_empty() {
        println!(
            "new unlinked active subscribers ({}):",
            r.new_subscribers.len()
        );
        for s in &r.new_subscribers {
            println!("  {} — {}", s.subscriber_id, s.name);
        }
    }
    if !r.suppressed_disables.is_empty() {
        eprintln!(
            "SUPPRESSED disables ({}): roster came back EMPTY — check blog_url. Untouched: {}",
            r.suppressed_disables.len(),
            r.suppressed_disables.join(", ")
        );
    }
    for e in &r.errors {
        eprintln!("error: {e}");
    }
    if r.enabled.is_empty()
        && r.disabled.is_empty()
        && r.lapsed_pending.is_empty()
        && r.new_subscribers.is_empty()
        && r.suppressed_disables.is_empty()
    {
        println!("nothing to do — access already matches subscriptions");
    }
}

async fn run_link(inv: &SqliteInventory, user: &str, subscriber_id: i64) -> anyhow::Result<()> {
    if inv.get_user(&UserId(user.to_string())).await?.is_none() {
        return Err(anyhow::anyhow!("no such user: {user}"));
    }
    // Audit-on-actual-mutation: a same-pair re-link writes nothing.
    let changed = inv
        .link_boosty_subscriber(&UserId(user.to_string()), subscriber_id)
        .await?;
    if changed {
        inv.audit(
            "cli",
            "boosty.link",
            Some(user),
            Some(&json!({ "subscriber_id": subscriber_id })),
        )
        .await?;
        println!("linked '{user}' to Boosty subscriber {subscriber_id}");
    } else {
        println!("'{user}' is already linked to Boosty subscriber {subscriber_id} — nothing to do");
    }
    Ok(())
}

async fn run_unlink(inv: &SqliteInventory, user: &str) -> anyhow::Result<()> {
    let changed = inv
        .unlink_boosty_subscriber(&UserId(user.to_string()))
        .await?;
    if changed {
        inv.audit("cli", "boosty.unlink", Some(user), None).await?;
        println!("unlinked '{user}'");
    } else {
        println!("'{user}' has no Boosty link — nothing to do");
    }
    Ok(())
}

async fn run_status(inv: &SqliteInventory) -> anyhow::Result<()> {
    let s = inv.get_boosty_settings().await?;
    let links = inv.list_boosty_links().await?;
    println!("enabled:             {}", s.enabled);
    println!(
        "blog:                {}",
        s.blog_url.as_deref().unwrap_or("(unset)")
    );
    println!("access_token:        {}", mask(s.access_token.as_deref()));
    println!("refresh_token:       {}", mask(s.refresh_token.as_deref()));
    println!("device_id:           {}", mask(s.device_id.as_deref()));
    println!("poll_interval_secs:  {}", s.poll_interval_secs);
    println!("auto_disable_lapsed: {}", s.auto_disable_lapsed);
    println!("linked users:        {}", links.len());
    Ok(())
}

/// Mask a secret to `••••<last4>` — never print full credential values.
fn mask(secret: Option<&str>) -> String {
    match secret {
        None => "(unset)".to_string(),
        Some(v) if v.chars().count() <= 4 => "••••".to_string(),
        Some(v) => {
            let last4: String = v
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("••••{last4}")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_configure(
    inv: &SqliteInventory,
    blog: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    device_id: Option<String>,
    interval_secs: Option<u64>,
    enable: bool,
    disable: bool,
) -> anyhow::Result<()> {
    if enable && disable {
        return Err(anyhow::anyhow!("pass only one of --enable / --disable"));
    }

    let mut s = inv.get_boosty_settings().await?;
    if let Some(b) = blog {
        s.blog_url = Some(b);
    }
    if let Some(t) = access_token {
        s.access_token = Some(t);
    }
    if let Some(t) = refresh_token {
        s.refresh_token = Some(t);
    }
    if let Some(d) = device_id {
        s.device_id = Some(d);
    }
    if let Some(i) = interval_secs {
        s.poll_interval_secs = i;
    }
    if enable {
        s.enabled = true;
    }
    if disable {
        s.enabled = false;
    }

    inv.set_boosty_settings(&s).await?;
    // Audit WITHOUT any secret values — only which non-secret fields changed.
    inv.audit(
        "cli",
        "boosty.configure",
        None,
        Some(&json!({
            "enabled": s.enabled,
            "blog_url": s.blog_url,
            "poll_interval_secs": s.poll_interval_secs,
        })),
    )
    .await?;
    println!("boosty settings updated");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::deploy_hint;

    #[test]
    fn deploy_hint_lists_each_server_and_the_command() {
        let hint = deploy_hint(&["de".to_string(), "is".to_string()]);
        assert!(hint.contains("vpnctl deploy de\n"), "{hint}");
        assert!(hint.contains("vpnctl deploy is\n"), "{hint}");
        assert!(hint.starts_with("note:"), "{hint}");
    }

    #[test]
    fn deploy_hint_is_empty_for_no_servers() {
        assert_eq!(deploy_hint(&[]), "");
    }
}
