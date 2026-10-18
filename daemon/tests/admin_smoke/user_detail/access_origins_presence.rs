use tempfile::TempDir;

use vpnctl_core::{ServerId, UserId};
use vpnctld::router;

use crate::common::*;

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

#[tokio::test]
async fn admin_user_detail_origins_renders_country_isp_ip_breakdown() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
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

    for cc in ["US", "DE", "RU"] {
        assert!(
            html.contains(cc),
            "country {cc} missing from origins breakdown"
        );
    }
    assert!(
        html.contains("AS8359 MTS PJSC"),
        "ISP label must render in the by-ISP table"
    );
    for ip in ["203.0.113.10", "198.51.100.20", "192.0.2.30"] {
        assert!(html.contains(ip), "IP {ip} missing from by-IP table");
    }
    assert!(
        html.contains("client families"),
        "device-count line must lead with 'client families' when device_class is populated"
    );
    assert!(
        !html.contains("TLS-fingerprints") && !html.contains("0 TLS"),
        "dead JA4/TLS-fingerprint term must be gone from the device line"
    );
    assert!(
        !html.contains("No external subscription fetches recorded"),
        "empty-state must NOT render when origin rows exist"
    );
}

#[tokio::test]
async fn admin_user_detail_origins_empty_state_when_only_egress() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
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

#[tokio::test]
async fn pr_user_online_badge_green_when_snapshot_attributes_connection() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;

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
    assert!(html.contains("s0"), "online badge must name the server");
    assert!(
        !html.contains("offline"),
        "must not show 'offline' when online"
    );
}

#[tokio::test]
async fn pr_user_online_badge_offline_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Presence"), "presence eyebrow missing");
    assert!(
        html.contains("offline"),
        "badge must read 'offline' with an empty snapshot cache"
    );
    assert!(
        html.contains("never connected"),
        "offline badge must say 'never connected' for a user with no history"
    );
    assert!(
        !html.contains("🟢"),
        "must not show the green dot when offline"
    );
}

#[tokio::test]
async fn pr_user_sharing_verdict_flags_likely_shared_on_asn_spread() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
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
    assert!(html.contains("ASNs"), "verdict must report the ASN count");
}
