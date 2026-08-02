//! `vpnctl boosty` — reconcile VPN access with Boosty subscription state,
//! plus link/configure helpers. Thin glue over `vpnctl-boosty-bridge`.

use std::path::PathBuf;

use clap::Subcommand;
use serde::Serialize;
use serde_json::json;
use vpnctl_boosty_bridge::{ApplyMode, SyncReport, sync_from_inventory};
use vpnctl_core::UserId;
use vpnctl_inventory::{BoostySettings, SqliteInventory};

use crate::{OutputFormat, ui};

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

pub(crate) async fn run(
    cmd: BoostyCmd,
    db_flag: Option<PathBuf>,
    output: OutputFormat,
) -> anyhow::Result<()> {
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
        BoostyCmd::Status => run_status(&inv, output).await,
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
    let mode = match (apply, disable_lapsed) {
        (false, _) => ApplyMode::DryRun,
        (true, false) => ApplyMode::EnableOnly,
        (true, true) => ApplyMode::Full,
    };

    let report = sync_from_inventory(inv, mode).await?;
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
            .chain(report.provisioned.iter())
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
        "roster: {} subscribers ({} paid-active, {} free excluded), {} linked",
        r.total_subscribers, r.active_subscribers, r.excluded_unpaid, r.linked
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
    if !r.grace_pending.is_empty() {
        println!(
            "inside grace period ({}): {}",
            r.grace_pending.len(),
            r.grace_pending.join(", ")
        );
    }
    if !r.provisioned.is_empty() {
        println!(
            "provisioned ({}): {}",
            r.provisioned.len(),
            r.provisioned.join(", ")
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

#[derive(Debug, Serialize, PartialEq, Eq)]
struct BoostyStatus {
    enabled: bool,
    blog: Option<String>,
    access_token: String,
    refresh_token: String,
    device_id: String,
    poll_interval_secs: u64,
    auto_disable_lapsed: bool,
    grace_days: u16,
    auto_create_users: bool,
    linked_users: usize,
}

impl BoostyStatus {
    fn from_settings(settings: &BoostySettings, linked_users: usize) -> Self {
        Self {
            enabled: settings.enabled,
            blog: settings.blog_url.clone(),
            access_token: mask(settings.access_token.as_deref()),
            refresh_token: mask(settings.refresh_token.as_deref()),
            device_id: mask(settings.device_id.as_deref()),
            poll_interval_secs: settings.poll_interval_secs,
            auto_disable_lapsed: settings.auto_disable_lapsed,
            grace_days: settings.grace_days,
            auto_create_users: settings.auto_create_users,
            linked_users,
        }
    }
}

async fn run_status(inv: &SqliteInventory, output: OutputFormat) -> anyhow::Result<()> {
    let s = inv.get_boosty_settings().await?;
    let links = inv.list_boosty_links().await?;
    let status = BoostyStatus::from_settings(&s, links.len());
    ui::print(output, &status, |status| {
        print!("{}", status_text(status));
        Ok(())
    })
}

fn status_text(status: &BoostyStatus) -> String {
    format!(
        "enabled:             {}\n\
         blog:                {}\n\
         access_token:        {}\n\
         refresh_token:       {}\n\
         device_id:           {}\n\
         poll_interval_secs:  {}\n\
         auto_disable_lapsed: {}\n\
         grace_days:          {}\n\
         auto_create_users:   {}\n\
         linked users:        {}\n",
        status.enabled,
        status.blog.as_deref().unwrap_or("(unset)"),
        status.access_token,
        status.refresh_token,
        status.device_id,
        status.poll_interval_secs,
        status.auto_disable_lapsed,
        status.grace_days,
        status.auto_create_users,
        status.linked_users,
    )
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
    use super::*;

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

    fn settings_with_secrets() -> BoostySettings {
        BoostySettings {
            enabled: true,
            blog_url: Some("creator".into()),
            access_token: Some("access-abcdef".into()),
            refresh_token: Some("refresh-123456".into()),
            device_id: Some("device-wxyz".into()),
            poll_interval_secs: 1800,
            auto_disable_lapsed: true,
            grace_days: 14,
            auto_create_users: true,
        }
    }

    #[test]
    fn status_json_contract_is_stable_and_masks_secrets() {
        let status = BoostyStatus::from_settings(&settings_with_secrets(), 3);
        let json = serde_json::to_string(&status).unwrap();

        assert_eq!(
            json,
            r#"{"enabled":true,"blog":"creator","access_token":"••••cdef","refresh_token":"••••3456","device_id":"••••wxyz","poll_interval_secs":1800,"auto_disable_lapsed":true,"grace_days":14,"auto_create_users":true,"linked_users":3}"#
        );
        assert!(!json.contains("access-abcdef"));
        assert!(!json.contains("refresh-123456"));
        assert!(!json.contains("device-wxyz"));
    }

    #[test]
    fn status_text_preserves_existing_output() {
        let status = BoostyStatus::from_settings(&settings_with_secrets(), 3);

        assert_eq!(
            status_text(&status),
            "enabled:             true\n\
             blog:                creator\n\
             access_token:        ••••cdef\n\
             refresh_token:       ••••3456\n\
             device_id:           ••••wxyz\n\
             poll_interval_secs:  1800\n\
             auto_disable_lapsed: true\n\
             grace_days:          14\n\
             auto_create_users:   true\n\
             linked users:        3\n"
        );
    }

    #[test]
    fn status_marks_unset_and_short_secrets_without_leaking_them() {
        let settings = BoostySettings {
            access_token: Some("tiny".into()),
            ..BoostySettings::default()
        };
        let status = BoostyStatus::from_settings(&settings, 0);

        assert_eq!(status.access_token, "••••");
        assert_eq!(status.refresh_token, "(unset)");
        assert_eq!(status.device_id, "(unset)");
        assert_eq!(status.blog, None);
    }
}
