use tempfile::TempDir;

use vpnctl_core::{ServerId, UserId};
use vpnctld::router;

use crate::common::*;

/// abuse-origins — empty-state: a user with no external (non-egress)
/// fetches still renders the "Subscription origins" eyebrow + the
/// no-data copy, never a bare rule.
#[tokio::test]
async fn admin_user_detail_origins_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains(r#"id="origins""#),
        "origins anchor must always render"
    );
    assert!(
        html.contains("Subscription origins"),
        "origins eyebrow must render even when empty"
    );
    assert!(
        html.contains("No external subscription fetches recorded"),
        "origins empty-state copy missing"
    );
}

/// abuse-origins — a multi-ASN / multi-country / multi-IP pattern for a
/// user renders all three breakdown tables with the seeded values, the
/// device-count line, and the per-table sub-eyebrows.
#[tokio::test]
async fn admin_user_detail_origins_renders_country_isp_ip_breakdown() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Three countries, three ISPs, three IPs, two device classes.
    let rows = [
        (
            "203.0.113.10",
            "US",
            "AS8359 MTS PJSC",
            "Hiddify",
            "Hiddify/1",
        ),
        ("198.51.100.20", "DE", "AS3320 DTAG", "v2rayNG", "v2rayNG/2"),
        (
            "192.0.2.30",
            "RU",
            "AS12389 Rostelecom",
            "Hiddify",
            "Hiddify/3",
        ),
    ];
    for (ip, cc, asn, dev, ua) in rows {
        s.inv
            .log_sub_access_rich(
                &UserId("u0".into()),
                ip,
                Some(ua),
                200,
                512,
                None,
                Some("HTTP/2"),
                Some(dev),
                Some(cc),
                Some(asn),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;

    // Section + per-table sub-eyebrows.
    assert!(
        html.contains("Subscription origins"),
        "section eyebrow missing"
    );
    assert!(
        html.contains("By country"),
        "by-country sub-eyebrow missing"
    );
    assert!(html.contains("By ISP"), "by-ISP sub-eyebrow missing");
    assert!(html.contains("By IP"), "by-IP sub-eyebrow missing");

    // Country codes show in the by-country table.
    for cc in ["US", "DE", "RU"] {
        assert!(
            html.contains(cc),
            "country {cc} missing from origins breakdown"
        );
    }
    // ISP labels render verbatim (the descriptive geo_asn string).
    assert!(
        html.contains("AS8359 MTS PJSC"),
        "ISP label must render in the by-ISP table"
    );
    // Each IP renders in the by-IP table.
    for ip in ["203.0.113.10", "198.51.100.20", "192.0.2.30"] {
        assert!(html.contains(ip), "IP {ip} missing from by-IP table");
    }
    // Device-count line (TT-5): two distinct device_classes present →
    // leads with «client families» + a raw-UA breakout (was the
    // false-precision «≈N devices» + a dead «0 TLS-fingerprints» term).
    assert!(
        html.contains("client families"),
        "device-count line must lead with 'client families' when device_class is populated"
    );
    assert!(
        !html.contains("TLS-fingerprints") && !html.contains("0 TLS"),
        "dead JA4/TLS-fingerprint term must be gone from the device line"
    );
    // No empty-state when rows are present.
    assert!(
        !html.contains("No external subscription fetches recorded"),
        "empty-state must NOT render when origin rows exist"
    );
}

/// abuse-origins — egress-only history yields the empty-state (egress
/// rows are excluded from every breakdown).
#[tokio::test]
async fn admin_user_detail_origins_empty_state_when_only_egress() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // s0's address is 10.0.0.0 (see `seed`); a fetch from that IP is
    // flagged is_vpn_egress by the migration-0021 trigger.
    s.inv
        .log_sub_access_rich(
            &UserId("u0".into()),
            "10.0.0.0",
            Some("Hiddify/1"),
            200,
            512,
            None,
            None,
            Some("Hiddify"),
            Some("DE"),
            Some("AS1 Egress"),
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("No external subscription fetches recorded"),
        "egress-only history must render the origins empty-state"
    );
}

/// user#1 — with a snapshot seeded into the AppState's snapshot_cache
/// that attributes a live connection to the user, the presence badge
/// flips to the 🟢-online branch and names the server.
#[tokio::test]
async fn pr_user_online_badge_green_when_snapshot_attributes_connection() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0, granted

    // Seed a snapshot on s0 with one connection attributed to u0 via
    // metadata.user (the patched sing-box clash-api), which the online
    // badge reads directly.
    let mut conn = pr_user_conn("9.9.9.9", "40000");
    conn.metadata.user = Some("u0".into());
    let snap = vpnctld::clash_api::Snapshot {
        upload_total: conn.upload,
        download_total: conn.download,
        connections: vec![conn],
    };
    s.snapshot_cache.store(ServerId("s0".into()), snap);

    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Presence"), "presence eyebrow missing");
    assert!(
        html.contains(r#"class="ed-stat ed-stat--active""#),
        "online badge must use the active status marker"
    );
    assert!(html.contains("online"), "online badge must read 'online'");
    // The server the connection landed on is named.
    assert!(html.contains("s0"), "online badge must name the server");
    assert!(
        !html.contains("offline"),
        "must not show 'offline' when online"
    );
}

/// user#1 — with NO snapshot in the cache the badge degrades to the
/// offline branch. No panic on an empty cache.
#[tokio::test]
async fn pr_user_online_badge_offline_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // No snapshot stored — cache is empty.
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Presence"), "presence eyebrow missing");
    assert!(
        html.contains("offline"),
        "badge must read 'offline' with an empty snapshot cache"
    );
    // Never connected (no sub-access history) → explicit copy.
    assert!(
        html.contains("never connected"),
        "offline badge must say 'never connected' for a user with no history"
    );
    assert!(
        !html.contains("🟢"),
        "must not show the green dot when offline"
    );
}

/// user#4 — a high-ASN-spread access pattern flips the sharing verdict
/// to "likely shared".
#[tokio::test]
async fn pr_user_sharing_verdict_flags_likely_shared_on_asn_spread() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Three fetches, each from a distinct ASN + country + /16 — the
    // classic "subscription URL got shared across ISPs" pattern. The
    // enrichment columns are set directly via the richer logger.
    for (ip, cc, asn) in [
        ("192.0.2.1", "US", "AS111 Alpha"),
        ("203.0.113.7", "DE", "AS222 Beta"),
        ("198.51.100.5", "FR", "AS333 Gamma"),
    ] {
        s.inv
            .log_sub_access_rich(
                &UserId("u0".into()),
                ip,
                Some("Hiddify/Android/2.5.0"),
                200,
                100,
                None,
                None,
                None,
                Some(cc),
                Some(asn),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Sharing verdict"),
        "sharing-verdict eyebrow missing"
    );
    assert!(
        html.contains("likely shared"),
        "high-ASN-spread access must produce 'likely shared' verdict"
    );
    // The verdict line names the distinct counts.
    assert!(html.contains("ASNs"), "verdict must report the ASN count");
}
