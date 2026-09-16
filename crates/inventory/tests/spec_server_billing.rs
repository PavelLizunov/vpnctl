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
        initial_payments_count: None,
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
        initial_payments_count: None,
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
        initial_payments_count: None,
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
            initial_payments_count: None,
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
            initial_payments_count: None,
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
        initial_payments_count: None,
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

#[tokio::test]
async fn server_billing_initial_payments_and_advance_snapshot() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s1", "transip");
    inv.add_server(&s).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-10-10".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 700,
        currency: "EUR".into(),
        auto_renew: true,
        billing_url: None,
        notes: None,
        initial_payments_count: Some(3),
    };

    inv.set_server_billing(&s.id, &input).await.unwrap();

    // Verify 3 payments were recorded
    let payments = inv.list_server_payments(&s.id).await.unwrap();
    assert_eq!(payments.len(), 3);
    assert_eq!(payments[0].amount_minor, 700);
    assert_eq!(payments[0].currency, "EUR");

    let (spend, count) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count, 3);
    assert_eq!(spend, 2100);

    // Advance 1 cycle -> advances due_date AND records 4th payment
    let advanced = inv.advance_server_billing_cycle(&s.id).await.unwrap();
    assert_eq!(advanced.due_date, "2026-11-10");

    let (spend4, count4) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count4, 4);
    assert_eq!(spend4, 2800);
}

#[tokio::test]
async fn server_spend_and_count_dynamically_converts_across_currency_switch() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s2", "hetzner");
    inv.add_server(&s).await.unwrap();

    // Insert 1 EUR = 100 RUB rate (1 EUR = 100_000_000 micros)
    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 100_000_000,
        source: "test".into(),
        fetched_at: "2026-09-16T12:00:00Z".into(),
    })
    .await
    .unwrap();

    let input = ServerBillingInput {
        due_date: "2026-10-10".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 1000, // 10.00 EUR
        currency: "EUR".into(),
        auto_renew: false,
        billing_url: None,
        notes: None,
        initial_payments_count: Some(2),
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();

    // Spend in EUR: 2 payments of 10.00 EUR = 2000 cents
    let (spend_eur, count_eur) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count_eur, 2);
    assert_eq!(spend_eur, 2000);

    // Operator switches display currency to RUB: payments must not vanish!
    let (spend_rub, count_rub) = inv.server_spend_and_count(&s.id, "RUB").await.unwrap();
    assert_eq!(
        count_rub, 2,
        "count must never drop to 0 on currency switch"
    );
    assert!(spend_rub > 0, "spend must dynamically convert to RUB");
}

#[tokio::test]
async fn advance_auto_renew_servers_advances_due_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s3", "aeza");
    inv.add_server(&s).await.unwrap();

    // Set server due yesterday with auto_renew = true
    let input = ServerBillingInput {
        due_date: "2026-01-01".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 500,
        currency: "EUR".into(),
        auto_renew: true,
        billing_url: None,
        notes: None,
        initial_payments_count: None,
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();

    let advanced = inv.advance_auto_renew_servers().await.unwrap();
    assert_eq!(advanced.len(), 1);
    assert_eq!(advanced[0].0, s.id);
    assert_eq!(advanced[0].1, "2026-02-01");

    let updated = inv.get_server_billing(&s.id).await.unwrap().unwrap();
    assert_eq!(updated.due_date, "2026-02-01");
}

#[tokio::test]
async fn advance_server_billing_cycle_guarded_prevents_duplicate_billing() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s_guarded", "hetzner");
    inv.add_server(&s).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-05-01".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 1000,
        currency: "EUR".into(),
        auto_renew: true,
        billing_url: None,
        notes: None,
        initial_payments_count: None,
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();

    // First call matches expected_due ("2026-05-01") -> succeeds
    let first = inv
        .advance_server_billing_cycle_guarded(&s.id, "2026-05-01", true)
        .await
        .unwrap();
    assert!(first.is_some());
    assert_eq!(first.unwrap().due_date, "2026-06-01");

    // Second call with stale expected_due ("2026-05-01") -> returns None (CAS mismatch)
    let second = inv
        .advance_server_billing_cycle_guarded(&s.id, "2026-05-01", true)
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "CAS mismatch must prevent duplicate advancement"
    );

    // Payments count must be exactly 1
    let payments = inv.list_server_payments(&s.id).await.unwrap();
    assert_eq!(
        payments.len(),
        1,
        "exactly one payment snapshot must be recorded"
    );

    // Third call with require_auto_renew=true on server with auto_renew=false -> returns None
    let input_no_renew = ServerBillingInput {
        due_date: "2026-06-01".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 1000,
        currency: "EUR".into(),
        auto_renew: false,
        billing_url: None,
        notes: None,
        initial_payments_count: None,
    };
    inv.set_server_billing(&s.id, &input_no_renew)
        .await
        .unwrap();

    let third = inv
        .advance_server_billing_cycle_guarded(&s.id, "2026-06-01", true)
        .await
        .unwrap();
    assert!(
        third.is_none(),
        "auto_renew = false must reject auto advancement"
    );
}

#[tokio::test]
async fn convert_amount_spot_does_not_inflate_with_markup() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Set up settings with 15% default markup (+1500 bps = 11500)
    let settings_input = vpnctl_inventory::CurrencySettingsInput {
        display_currency: Some("EUR".into()),
        default_markup_bps: Some(11500),
        markup_overrides: None,
        rate_overrides: None,
        auto_refresh: Some(false),
    };
    inv.set_currency_settings(&settings_input).await.unwrap();

    // Rate: 1 EUR = 100 RUB
    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 100_000_000,
        source: "test".into(),
        fetched_at: "2026-09-16T12:00:00Z".into(),
    })
    .await
    .unwrap();

    // 1000 RUB -> EUR at spot rate
    let spot = inv
        .convert_amount_spot(100_000, "RUB", "EUR")
        .await
        .unwrap()
        .unwrap();
    let with_markup = inv
        .convert_amount(100_000, "RUB", "EUR")
        .await
        .unwrap()
        .unwrap();

    assert!(
        spot.amount_minor < with_markup.amount_minor,
        "spot conversion must not apply fee markup multiplier"
    );
    assert_eq!(spot.markup_bps, 10_000);
}
