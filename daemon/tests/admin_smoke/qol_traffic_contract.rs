//! Independent HTTP contract tests for the user Traffic tab's node filter.
//!
//! Contract under test:
//! `GET /admin/users/{uid}/traffic?vpn_window=7d&vpn_server={node}` returns a
//! usable page that keeps both parameters across period changes, names the
//! selected node, restricts the selected period totals to that node, and keeps
//! the monthly quota global for the user. Empty periods still expose both
//! controls. `vpn_server` empty is the browser's "all nodes" selection.
//!
//! The tests deliberately use only HTML/HTTP behaviour and the measured bytes
//! themselves, not new DOM class names or locale-dependent copy. Expected
//! humanized numbers tolerate one- or two-decimal binary formatting.

use std::time::Duration;

use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};
use vpnctld::router;

use crate::common::*;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Plausible binary renderings of `bytes`, including a bare integer form.
///
/// The current admin helper renders one decimal (`1.0 GiB`), but the contract
/// only fixes the byte value, so accept 0/1/2 decimals and the equivalent
/// MiB rendering to avoid pinning a presentational detail.
fn size_forms(bytes: u64) -> Vec<String> {
    let mut forms = Vec::new();
    for (unit, scale) in [("GiB", GIB), ("MiB", MIB)] {
        if bytes < scale {
            continue;
        }
        let value = bytes as f64 / scale as f64;
        if bytes.is_multiple_of(scale) {
            forms.push(format!("{value:.0} {unit}"));
        }
        forms.push(format!("{value:.1} {unit}"));
        forms.push(format!("{value:.2} {unit}"));
    }
    forms
}

fn contains_size(html: &str, bytes: u64) -> bool {
    size_forms(bytes).iter().any(|needle| {
        html.match_indices(needle.as_str()).any(|(at, _)| {
            // Reject a match that is only the tail of a larger number, e.g.
            // "1.0 GiB" inside "11.0 GiB".
            !matches!(
                html[..at].chars().next_back(),
                Some(c) if c.is_ascii_digit() || c == '.'
            )
        })
    })
}

fn assert_size(html: &str, bytes: u64, what: &str) {
    assert!(
        contains_size(html, bytes),
        "{what}: expected a rendering of {bytes} bytes ({:?}) anywhere on the page",
        size_forms(bytes)
    );
}

fn assert_no_size(html: &str, bytes: u64, what: &str) {
    assert!(
        !contains_size(html, bytes),
        "{what}: found a rendering of {bytes} bytes ({:?}) but it must be absent",
        size_forms(bytes)
    );
}

fn hrefs(html: &str) -> Vec<String> {
    html.split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(|href| href.replace("&amp;", "&"))
        .collect()
}

fn assert_period_links_keep_node(html: &str, uid: &str, server: &str) {
    let page = format!("/admin/users/{uid}/traffic");
    let node = format!("vpn_server={server}");
    let period_controls = html
        .split_once(r#"id="timeframe""#)
        .unwrap()
        .1
        .split_once("<form")
        .unwrap()
        .0;
    let traffic_links: Vec<String> = hrefs(period_controls)
        .into_iter()
        .filter(|href| href.contains(&page) && href.contains("vpn_window="))
        .collect();
    assert!(
        !traffic_links.is_empty(),
        "the traffic page must offer period controls"
    );
    assert!(
        traffic_links
            .iter()
            .any(|href| href.contains("vpn_window=30d")),
        "the documented 30d period control is missing: {traffic_links:?}"
    );
    for href in traffic_links {
        assert!(
            href.contains(&node),
            "a period change dropped vpn_server={server}: {href}"
        );
    }
}

fn assert_filter_controls(html: &str) {
    assert!(
        html.contains(r#"name="vpn_window""#),
        "the period control must stay available"
    );
    assert!(
        html.contains(r#"name="vpn_server""#),
        "the node control must stay available"
    );
}

/// True when the page contains an `<option value="{value}" selected>`.
///
/// The option value is the node identity used by the browser; the visible
/// label and the surrounding markup are deliberately not pinned.
fn selected_option(html: &str, value: &str) -> bool {
    let value_attr = format!("value=\"{value}\"");
    html.split("<option").skip(1).any(|rest| {
        let tag = rest.split('>').next().unwrap_or_default();
        tag.contains(&value_attr)
            && tag
                .split_whitespace()
                .any(|attr| attr == "selected" || attr.starts_with("selected="))
    })
}

/// The node filter control, so option checks cannot be confused by another
/// `<select>` elsewhere on the page.
fn node_control(html: &str) -> &str {
    let start = html
        .match_indices("<select")
        .find_map(|(at, _)| {
            html[at..]
                .split_once('>')
                .and_then(|(tag, _)| tag.contains(r#"name="vpn_server""#).then_some(at))
        })
        .expect("node selector");
    let end = html[start..]
        .find("</select>")
        .map(|offset| start + offset)
        .unwrap_or(html.len());
    &html[start..end]
}

fn has_all_nodes_option(html: &str) -> bool {
    html.split("<option").skip(1).any(|rest| {
        let tag = rest.split('>').next().unwrap_or_default();
        tag.contains("value=\"\"")
    })
}

async fn insert_stat(
    dir: &TempDir,
    ts: &str,
    server: &str,
    user: Option<&str>,
    upload: i64,
    download: i64,
    active: i64,
) {
    let dsn = format!("sqlite://{}", dir.path().join("inv.db").display());
    let pool = sqlx::SqlitePool::connect(&dsn).await.unwrap();
    sqlx::query(
        "INSERT INTO vpn_connection_stats
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(ts)
    .bind(server)
    .bind(user)
    .bind(upload)
    .bind(download)
    .bind(active)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

async fn set_coefficient(dir: &TempDir, server: &str, coefficient: f64) {
    let dsn = format!("sqlite://{}", dir.path().join("inv.db").display());
    let pool = sqlx::SqlitePool::connect(&dsn).await.unwrap();
    sqlx::query("UPDATE servers SET usage_coefficient = ?1 WHERE id = ?2")
        .bind(coefficient)
        .bind(server)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn record_user(
    inv: &SqliteInventory,
    server: &str,
    user: &str,
    upload: u64,
    download: u64,
    active: u32,
) {
    inv.record_vpn_stats(
        &ServerId(server.into()),
        &[VpnStatsDelta {
            user_id: Some(UserId(user.into())),
            upload_bytes: upload,
            download_bytes: download,
            active_connections: active,
        }],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_24h_selection_keeps_window_and_node_controls() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;

    let html = fetch_html(
        router(s),
        "/admin/users/u0/traffic?vpn_window=24h&vpn_server=s0",
    )
    .await;

    assert_filter_controls(&html);
    assert!(
        has_all_nodes_option(node_control(&html)),
        "the node selector must offer an empty value for all nodes"
    );
    assert!(
        selected_option(node_control(&html), "s0"),
        "the selected node s0 must be named and marked selected"
    );
    assert!(
        html.contains("No traffic samples for this selection"),
        "an empty 24h selection must keep its explicit empty state"
    );
    assert_period_links_keep_node(&html, "u0", "s0");
}

#[tokio::test]
async fn three_day_old_sample_enters_7d_but_not_24h() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let three_days_ago = chrono::Utc::now() - chrono::Duration::days(3);
    insert_stat(
        &dir,
        &three_days_ago.to_rfc3339(),
        "s0",
        Some("u0"),
        (3 * GIB / 2) as i64,
        (3 * GIB / 2) as i64,
        1,
    )
    .await;

    let app = router(s);
    let day = fetch_html(
        app.clone(),
        "/admin/users/u0/traffic?vpn_window=24h&vpn_server=s0",
    )
    .await;
    assert!(
        day.contains("No traffic samples for this selection") || day.contains("Aggregated from 0"),
        "the 24h selection must be empty while the 3-day-old sample is outside it"
    );
    assert_filter_controls(&day);
    assert!(
        selected_option(node_control(&day), "s0"),
        "the node selection must survive an empty 24h period"
    );

    let week = fetch_html(app, "/admin/users/u0/traffic?vpn_window=7d&vpn_server=s0").await;
    assert!(
        week.contains("Aggregated from 1"),
        "the 3-day-old sample must be aggregated in the 7d window"
    );
    assert_size(&week, 3 * GIB, "3-day-old sample in the 7d window");
}

#[tokio::test]
async fn selected_node_totals_are_scoped_while_monthly_quota_stays_global() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    set_coefficient(&dir, "s0", 2.0).await;
    s.inv
        .set_user_traffic_limit(&UserId("u0".into()), Some(100 * GIB), Some(80))
        .await
        .unwrap();

    // s0: 1 GiB measured, charged x2 = 2 GiB.
    record_user(&s.inv, "s0", "u0", 512 * MIB, 512 * MIB, 2).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    // s1: 4.5 GiB measured on a x1 node.
    record_user(&s.inv, "s1", "u0", 2304 * MIB, 2304 * MIB, 9).await;

    let app = router(s);
    let only_s0 = fetch_html(
        app.clone(),
        "/admin/users/u0/traffic?vpn_window=7d&vpn_server=s0",
    )
    .await;

    assert!(
        selected_option(node_control(&only_s0), "s0"),
        "the page must name s0 as the selected node"
    );
    assert!(
        !selected_option(node_control(&only_s0), ""),
        "the all-nodes option must not be selected while s0 is filtered"
    );
    assert_period_links_keep_node(&only_s0, "u0", "s0");

    // Measured attribution and coefficient-charged bytes are both visible and
    // deliberately different on a x2 node.
    assert_size(&only_s0, GIB, "measured s0 traffic");
    assert_size(&only_s0, 2 * GIB, "charged s0 traffic at coefficient 2");

    // The monthly quota is charged and global: 2 GiB on s0 + 4.5 GiB on s1.
    assert_size(
        &only_s0,
        6 * GIB + GIB / 2,
        "global monthly charged balance while s0 is selected",
    );

    // One snapshot belongs to the selected period; the second node's row must
    // not be folded into the selected totals.
    assert!(
        only_s0.contains("Aggregated from 1"),
        "the selected period must aggregate only s0's snapshot"
    );
    assert!(
        !only_s0.contains("Aggregated from 2"),
        "s1's snapshot leaked into the s0-filtered period"
    );

    let only_s1 = fetch_html(app, "/admin/users/u0/traffic?vpn_window=7d&vpn_server=s1").await;
    assert!(
        selected_option(node_control(&only_s1), "s1"),
        "the page must name s1 as the selected node"
    );
    assert_size(
        &only_s1,
        4 * GIB + GIB / 2,
        "measured and charged s1 traffic",
    );
    assert_size(
        &only_s1,
        6 * GIB + GIB / 2,
        "monthly balance stays global under the s1 filter",
    );
    assert!(
        only_s1.contains("Aggregated from 1") && !only_s1.contains("Aggregated from 2"),
        "the s1-filtered period must aggregate only s1's snapshot"
    );
}

#[tokio::test]
async fn empty_vpn_server_selects_all_nodes() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    record_user(&s.inv, "s0", "u0", 512 * MIB, 512 * MIB, 1).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    record_user(&s.inv, "s1", "u0", GIB, GIB, 1).await;

    let html = fetch_html(
        router(s),
        "/admin/users/u0/traffic?vpn_window=7d&vpn_server=",
    )
    .await;

    assert!(
        selected_option(node_control(&html), ""),
        "an empty vpn_server must select the all-nodes option"
    );
    assert!(
        !selected_option(node_control(&html), "s0") && !selected_option(node_control(&html), "s1"),
        "no single node may stay selected when vpn_server is empty"
    );
    assert!(
        html.contains("Aggregated from 2"),
        "the empty node filter must aggregate both nodes' snapshots"
    );
    assert_size(&html, 3 * GIB, "sum of both nodes in the all-nodes period");
}

#[tokio::test]
async fn other_users_traffic_never_enters_the_selected_totals() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[(0, 0), (1, 0)]).await;
    record_user(&s.inv, "s0", "u0", 3 * GIB / 4, 3 * GIB / 4, 1).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    record_user(&s.inv, "s0", "u1", 4 * GIB, 4 * GIB, 1).await;

    let app = router(s);
    let u0 = fetch_html(
        app.clone(),
        "/admin/users/u0/traffic?vpn_window=7d&vpn_server=s0",
    )
    .await;
    assert_size(&u0, 3 * GIB / 2, "u0's own measured traffic");
    assert_no_size(&u0, 8 * GIB, "u1's traffic");
    assert_no_size(&u0, 9 * GIB + GIB / 2, "u0 and u1 combined");
    assert!(
        u0.contains("Aggregated from 1") && !u0.contains("Aggregated from 2"),
        "u1's snapshot leaked into u0's selected totals"
    );

    let u1 = fetch_html(app, "/admin/users/u1/traffic?vpn_window=7d&vpn_server=s0").await;
    assert_size(&u1, 8 * GIB, "u1's own measured traffic");
    assert_no_size(&u1, 3 * GIB / 2, "u0's traffic");
}
