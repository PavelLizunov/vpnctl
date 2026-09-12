//! Spec for server rental billing and renewal tracking.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{
    BillingCycle, ServerBillingInput, SqliteInventory, advance_date_by_cycle, validate_due_date,
};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

fn srv(id: &str, hoster: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: hoster.into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

#[tokio::test]
async fn default_server_billing_is_none() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s1", "hetzner");
    inv.add_server(&s).await.unwrap();

    let billing = inv.get_server_billing(&s.id).await.unwrap();
    assert!(
        billing.is_none(),
        "fresh server must have no billing record"
    );

    let fleet = inv.list_fleet_billing().await.unwrap();
    assert_eq!(fleet.len(), 1);
    assert_eq!(fleet[0].server_id, s.id);
    assert!(fleet[0].billing.is_none());
}

#[tokio::test]
async fn set_and_get_server_billing() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s1", "infomaniak");
    inv.add_server(&s).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-10-15".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 550,
        currency: "CHF".into(),
        auto_renew: true,
        billing_url: Some("https://manager.infomaniak.com/".into()),
        notes: Some("Contract #12345".into()),
    };

    let record = inv.set_server_billing(&s.id, &input).await.unwrap();
    assert_eq!(record.server_id, s.id);
    assert_eq!(record.due_date, "2026-10-15");
    assert_eq!(record.billing_cycle, BillingCycle::Monthly);
    assert_eq!(record.amount_cents, 550);
    assert_eq!(record.currency, "CHF");
    assert!(record.auto_renew);
    assert_eq!(
        record.billing_url.as_deref(),
        Some("https://manager.infomaniak.com/")
    );
    assert_eq!(record.notes.as_deref(), Some("Contract #12345"));

    // Check fetch
    let fetched = inv.get_server_billing(&s.id).await.unwrap().unwrap();
    assert_eq!(fetched, record);

    // Audit row was written
    let audits = inv.recent_audit(10).await.unwrap();
    assert!(
        audits
            .iter()
            .any(|a| a.action == "server.billing.set" && a.target.as_deref() == Some("s1"))
    );
}

#[tokio::test]
async fn server_billing_cascade_on_delete() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s1", "transip");
    inv.add_server(&s).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-11-01".into(),
        billing_cycle: BillingCycle::Annual,
        amount_cents: 6000,
        currency: "EUR".into(),
        auto_renew: false,
        billing_url: None,
        notes: None,
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();
    assert!(inv.get_server_billing(&s.id).await.unwrap().is_some());

    // Delete server -> billing record should cascade delete
    inv.remove_server(&s.id).await.unwrap();
    let billing = inv.get_server_billing(&s.id).await.unwrap();
    assert!(
        billing.is_none(),
        "billing record must cascade on server deletion"
    );
}

#[tokio::test]
async fn advance_billing_cycle_advances_date_and_audits() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s1", "hetzner");
    inv.add_server(&s).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-05-31".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 450,
        currency: "EUR".into(),
        auto_renew: true,
        billing_url: None,
        notes: None,
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();

    // Advance 1 month from May 31 -> June 30
    let adv1 = inv.advance_server_billing_cycle(&s.id).await.unwrap();
    assert_eq!(adv1.due_date, "2026-06-30");

    // Advance 1 month from June 30 -> July 30
    let adv2 = inv.advance_server_billing_cycle(&s.id).await.unwrap();
    assert_eq!(adv2.due_date, "2026-07-30");

    let audits = inv.recent_audit(10).await.unwrap();
    assert!(
        audits
            .iter()
            .any(|a| a.action == "server.billing.advance" && a.target.as_deref() == Some("s1"))
    );
}

#[tokio::test]
async fn list_fleet_billing_orders_earliest_due_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s_early = srv("a-early", "hetzner");
    let s_late = srv("b-late", "ovh");
    let s_none = srv("c-none", "generic");
    inv.add_server(&s_early).await.unwrap();
    inv.add_server(&s_late).await.unwrap();
    inv.add_server(&s_none).await.unwrap();

    inv.set_server_billing(
        &s_early.id,
        &ServerBillingInput {
            due_date: "2026-09-15".into(),
            billing_cycle: BillingCycle::Monthly,
            amount_cents: 500,
            currency: "EUR".into(),
            auto_renew: true,
            billing_url: None,
            notes: None,
        },
    )
    .await
    .unwrap();

    inv.set_server_billing(
        &s_late.id,
        &ServerBillingInput {
            due_date: "2026-10-01".into(),
            billing_cycle: BillingCycle::Monthly,
            amount_cents: 600,
            currency: "EUR".into(),
            auto_renew: false,
            billing_url: None,
            notes: None,
        },
    )
    .await
    .unwrap();

    let fleet = inv.list_fleet_billing().await.unwrap();
    assert_eq!(fleet.len(), 3);
    assert_eq!(fleet[0].server_id, s_early.id);
    assert_eq!(fleet[1].server_id, s_late.id);
    assert_eq!(fleet[2].server_id, s_none.id);
    assert!(fleet[2].billing.is_none());
}

#[test]
fn test_date_helpers() {
    assert!(validate_due_date("2026-09-15").is_ok());
    assert!(validate_due_date("2026-02-29").is_err()); // 2026 is not a leap year
    assert!(validate_due_date("invalid").is_err());

    assert_eq!(
        advance_date_by_cycle("2026-01-31", BillingCycle::Monthly).unwrap(),
        "2026-02-28"
    );
    assert_eq!(
        advance_date_by_cycle("2026-01-31", BillingCycle::Quarterly).unwrap(),
        "2026-04-30"
    );
    assert_eq!(
        advance_date_by_cycle("2026-01-31", BillingCycle::SemiAnnual).unwrap(),
        "2026-07-31"
    );
    assert_eq!(
        advance_date_by_cycle("2026-01-31", BillingCycle::Annual).unwrap(),
        "2027-01-31"
    );
}

#[tokio::test]
async fn server_billing_error_paths() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // 1. Set billing on non-existent server
    let missing_sid = ServerId("non-existent".into());
    let valid_input = ServerBillingInput {
        due_date: "2026-10-15".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 500,
        currency: "EUR".into(),
        auto_renew: false,
        billing_url: None,
        notes: None,
    };
    let err_missing = inv.set_server_billing(&missing_sid, &valid_input).await;
    assert!(err_missing.is_err(), "cannot set billing on missing server");

    // 2. Set billing with invalid date format
    let s = srv("s1", "transip");
    inv.add_server(&s).await.unwrap();
    let invalid_date_input = ServerBillingInput {
        due_date: "2026-13-45".into(),
        ..valid_input.clone()
    };
    let err_date = inv.set_server_billing(&s.id, &invalid_date_input).await;
    assert!(err_date.is_err(), "cannot set billing with malformed date");

    // 3. Advance billing on unconfigured server
    let err_adv_unconf = inv.advance_server_billing_cycle(&s.id).await;
    assert!(
        err_adv_unconf.is_err(),
        "cannot advance billing when unconfigured"
    );

    // 4. Advance billing on non-existent server
    let err_adv_missing = inv.advance_server_billing_cycle(&missing_sid).await;
    assert!(
        err_adv_missing.is_err(),
        "cannot advance billing on missing server"
    );
}
