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

    let fetched = inv.get_server_billing(&s.id).await.unwrap().unwrap();
    assert_eq!(fetched, record);

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

    let adv1 = inv.advance_server_billing_cycle(&s.id).await.unwrap();
    assert_eq!(adv1.due_date, "2026-06-30");

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
    assert!(validate_due_date("2026-02-29").is_err());
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

#[test]
fn advance_date_rejects_out_of_range_year() {
    let last_date = chrono::NaiveDate::MAX.format("%Y-%m-%d").to_string();
    assert_eq!(
        validate_due_date(&last_date).unwrap(),
        chrono::NaiveDate::MAX
    );
    for cycle in [
        BillingCycle::Monthly,
        BillingCycle::Quarterly,
        BillingCycle::SemiAnnual,
        BillingCycle::Annual,
    ] {
        assert!(advance_date_by_cycle(&last_date, cycle).is_err());
    }
    assert_eq!(
        advance_date_by_cycle("2024-01-31", BillingCycle::Monthly).unwrap(),
        "2024-02-29"
    );
}

#[tokio::test]
async fn server_billing_error_paths() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

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

    let s = srv("s1", "transip");
    inv.add_server(&s).await.unwrap();
    let invalid_date_input = ServerBillingInput {
        due_date: "2026-13-45".into(),
        ..valid_input.clone()
    };
    let err_date = inv.set_server_billing(&s.id, &invalid_date_input).await;
    assert!(err_date.is_err(), "cannot set billing with malformed date");

    let err_adv_unconf = inv.advance_server_billing_cycle(&s.id).await;
    assert!(
        err_adv_unconf.is_err(),
        "cannot advance billing when unconfigured"
    );

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

    let payments = inv.list_server_payments(&s.id).await.unwrap();
    assert_eq!(payments.len(), 3);
    assert_eq!(payments[0].amount_minor, 700);
    assert_eq!(payments[0].currency, "EUR");

    let (spend, count) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count, 3);
    assert_eq!(spend, 2100);

    let advanced = inv.advance_server_billing_cycle(&s.id).await.unwrap();
    assert_eq!(advanced.due_date, "2026-11-10");

    let (spend4, count4) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count4, 4);
    assert_eq!(spend4, 2800);
}

#[tokio::test]
async fn server_spend_and_count_uses_only_snapshots_for_display_currency() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s2", "hetzner");
    inv.add_server(&s).await.unwrap();

    let mut rate = vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 100_000_000,
        source: "test".into(),
        fetched_at: "2026-09-16T12:00:00Z".into(),
    };
    inv.upsert_currency_rate(&rate).await.unwrap();

    let input = ServerBillingInput {
        due_date: "2026-10-10".into(),
        billing_cycle: BillingCycle::Monthly,
        amount_cents: 1000,
        currency: "EUR".into(),
        auto_renew: false,
        billing_url: None,
        notes: None,
        initial_payments_count: Some(2),
    };
    inv.set_server_billing(&s.id, &input).await.unwrap();

    let (spend_eur, count_eur) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!(count_eur, 2);
    assert_eq!(spend_eur, 2000);

    let (spend_rub, count_rub) = inv.server_spend_and_count(&s.id, "RUB").await.unwrap();
    assert_eq!(
        count_rub, 2,
        "count must never drop to 0 on currency switch"
    );
    assert_eq!(spend_rub, 0, "EUR snapshots must not be re-converted");

    let mut settings = vpnctl_inventory::CurrencySettingsInput {
        display_currency: Some("RUB".into()),
        default_markup_bps: None,
        markup_overrides: None,
        rate_overrides: None,
        auto_refresh: None,
    };
    inv.set_currency_settings(&settings).await.unwrap();
    let summary = inv.get_fleet_billing_summary().await.unwrap();
    assert_eq!(summary.total_spend_minor, spend_rub);
    assert_eq!(summary.servers[0].payment_count, count_rub);

    inv.advance_server_billing_cycle(&s.id).await.unwrap();
    let payments = inv.list_server_payments(&s.id).await.unwrap();
    let rub_snapshot = payments
        .iter()
        .find(|p| p.display_currency.as_deref() == Some("RUB"))
        .unwrap()
        .converted_minor
        .unwrap();
    assert_eq!(rub_snapshot, 107_000);

    rate.rate_micros = 200_000_000;
    inv.upsert_currency_rate(&rate).await.unwrap();
    let (spend, count) = inv.server_spend_and_count(&s.id, "RUB").await.unwrap();
    assert_eq!((spend, count), (rub_snapshot, 3));
    assert_eq!(inv.server_total_spend(&s.id, "RUB").await.unwrap(), spend);
    let summary = inv.get_fleet_billing_summary().await.unwrap();
    assert_eq!(summary.total_spend_minor, spend);
    assert_eq!(summary.servers[0].total_spend_minor, spend);
    assert_eq!(summary.servers[0].payment_count, count);
    assert_eq!(summary.monthly_burn_minor, 214_000);

    settings.display_currency = Some("EUR".into());
    inv.set_currency_settings(&settings).await.unwrap();
    // The RUB-snapshotted payment was paid in EUR, so it counts at its EUR
    // amount; nothing is converted at today's rates.
    let (spend, count) = inv.server_spend_and_count(&s.id, "EUR").await.unwrap();
    assert_eq!((spend, count), (3000, 3));
    let summary = inv.get_fleet_billing_summary().await.unwrap();
    assert_eq!(summary.total_spend_minor, spend);
    assert_eq!(summary.servers[0].payment_count, count);
}

#[tokio::test]
async fn server_spend_does_not_backfill_missing_snapshots_when_rates_appear() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("missing-snapshot", "generic");
    inv.add_server(&s).await.unwrap();
    let payment = inv
        .record_server_payment(
            &s.id,
            &vpnctl_inventory::ServerPaymentInput {
                amount_minor: 1234,
                currency: "USD".into(),
                cycle: BillingCycle::Monthly,
                notes: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(payment.converted_minor, None);
    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "USD".into(),
        target_currency: "EUR".into(),
        rate_micros: 900_000,
        source: "test".into(),
        fetched_at: "2026-10-25T00:00:00Z".into(),
    })
    .await
    .unwrap();

    assert_eq!(
        inv.server_spend_and_count(&s.id, "EUR").await.unwrap(),
        (0, 1)
    );
    assert_eq!(
        inv.server_spend_and_count(&s.id, "USD").await.unwrap(),
        (1234, 1),
        "a payment made in the display currency counts at its paid amount"
    );
    let summary = inv.get_fleet_billing_summary().await.unwrap();
    assert_eq!(summary.total_spend_minor, 0);
    assert_eq!(summary.servers[0].total_spend_minor, 0);
    assert_eq!(summary.servers[0].payment_count, 1);
    assert_eq!(
        inv.list_server_payments(&s.id).await.unwrap(),
        vec![payment]
    );
}

#[tokio::test]
async fn payment_storage_uses_hundredths_for_zero_decimal_currencies() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("hundredths", "generic");
    inv.add_server(&s).await.unwrap();

    for currency in ["JPY", "KRW"] {
        inv.set_currency_settings(&vpnctl_inventory::CurrencySettingsInput {
            display_currency: Some(currency.into()),
            default_markup_bps: None,
            markup_overrides: None,
            rate_overrides: None,
            auto_refresh: None,
        })
        .await
        .unwrap();
        let payment = inv
            .record_server_payment(
                &s.id,
                &vpnctl_inventory::ServerPaymentInput {
                    amount_minor: 10_000,
                    currency: currency.into(),
                    cycle: BillingCycle::Monthly,
                    notes: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(payment.amount_minor, 10_000);
        assert_eq!(payment.converted_minor, Some(10_000));
        inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
            base_currency: currency.into(),
            target_currency: "EUR".into(),
            rate_micros: 10_000,
            source: "test".into(),
            fetched_at: "2026-10-25T00:00:00Z".into(),
        })
        .await
        .unwrap();
        let converted = inv
            .convert_amount_spot(payment.amount_minor, currency, "EUR")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(converted.amount_minor, 100);
        assert!(
            inv.list_server_payments(&s.id)
                .await
                .unwrap()
                .contains(&payment)
        );
    }
}

#[tokio::test]
async fn advance_auto_renew_servers_advances_due_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("s3", "aeza");
    inv.add_server(&s).await.unwrap();

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

    let first = inv
        .advance_server_billing_cycle_guarded(&s.id, "2026-05-01", true)
        .await
        .unwrap();
    assert!(first.is_some());
    assert_eq!(first.unwrap().due_date, "2026-06-01");

    let second = inv
        .advance_server_billing_cycle_guarded(&s.id, "2026-05-01", true)
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "CAS mismatch must prevent duplicate advancement"
    );

    let payments = inv.list_server_payments(&s.id).await.unwrap();
    assert_eq!(
        payments.len(),
        1,
        "exactly one payment snapshot must be recorded"
    );

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

    let settings_input = vpnctl_inventory::CurrencySettingsInput {
        display_currency: Some("EUR".into()),
        default_markup_bps: Some(11500),
        markup_overrides: None,
        rate_overrides: None,
        auto_refresh: Some(false),
    };
    inv.set_currency_settings(&settings_input).await.unwrap();

    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 100_000_000,
        source: "test".into(),
        fetched_at: "2026-09-16T12:00:00Z".into(),
    })
    .await
    .unwrap();

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
