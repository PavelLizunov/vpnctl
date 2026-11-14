#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use tempfile::TempDir;
use vpnctl_inventory::{BoostySettings, SqliteInventory};

fn initial_settings() -> BoostySettings {
    BoostySettings {
        blog_url: Some("https://boosty.to/spec-session-blog".to_owned()),
        access_token: Some("spec-original-access-credential".to_owned()),
        refresh_token: Some("spec-original-refresh-credential".to_owned()),
        device_id: Some("spec-original-device-credential".to_owned()),
        enabled: true,
        ..Default::default()
    }
}

async fn fixture() -> (TempDir, PathBuf, SqliteInventory, BoostySettings) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inventory.db");
    let inventory = SqliteInventory::open(&path).await.unwrap();
    let expected = initial_settings();
    inventory.set_boosty_settings(&expected).await.unwrap();
    (directory, path, inventory, expected)
}

async fn audit_count(inventory: &SqliteInventory) -> usize {
    inventory.recent_audit(1_000).await.unwrap().len()
}

fn assert_same_settings(actual: &BoostySettings, expected: &BoostySettings) {
    assert_eq!(actual.blog_url, expected.blog_url);
    assert_eq!(actual.access_token, expected.access_token);
    assert_eq!(actual.refresh_token, expected.refresh_token);
    assert_eq!(actual.device_id, expected.device_id);
    assert_eq!(actual.enabled, expected.enabled);
}

#[tokio::test]
async fn saves_both_tokens_and_one_audit_without_credentials() {
    let (_directory, _path, inventory, expected) = fixture().await;
    let previous_audit_count = audit_count(&inventory).await;
    let new_access = "spec-replacement-access-credential";
    let new_refresh = "spec-replacement-refresh-credential";

    assert!(
        inventory
            .save_boosty_session(&expected, new_access, new_refresh)
            .await
            .unwrap()
    );

    let saved = inventory.get_boosty_settings().await.unwrap();
    assert_eq!(saved.access_token.as_deref(), Some(new_access));
    assert_eq!(saved.refresh_token.as_deref(), Some(new_refresh));
    assert_eq!(saved.blog_url, expected.blog_url);
    assert_eq!(saved.device_id, expected.device_id);
    assert_eq!(saved.enabled, expected.enabled);

    let audit = inventory.recent_audit(1_000).await.unwrap();
    assert_eq!(audit.len(), previous_audit_count + 1);
    let session_entries: Vec<_> = audit
        .iter()
        .filter(|entry| entry.action == "boosty.session.refreshed")
        .collect();
    assert_eq!(session_entries.len(), 1);
    let payload = serde_json::to_string(&session_entries[0].payload).unwrap();
    for credential in [
        new_access,
        new_refresh,
        expected.access_token.as_deref().unwrap(),
        expected.refresh_token.as_deref().unwrap(),
        expected.device_id.as_deref().unwrap(),
    ] {
        assert!(!payload.contains(credential), "audit exposed a credential");
    }
}

async fn assert_stale_settings_are_rejected(stale: BoostySettings) {
    let (_directory, _path, inventory, current) = fixture().await;
    let previous_audit_count = audit_count(&inventory).await;

    assert!(
        !inventory
            .save_boosty_session(
                &stale,
                "spec-stale-attempt-access",
                "spec-stale-attempt-refresh",
            )
            .await
            .unwrap()
    );

    assert_same_settings(&inventory.get_boosty_settings().await.unwrap(), &current);
    assert_eq!(audit_count(&inventory).await, previous_audit_count);
}

#[tokio::test]
async fn rejects_a_stale_blog_url_without_changes_or_audit() {
    let mut stale = initial_settings();
    stale.blog_url = Some("https://boosty.to/spec-other-blog".to_owned());
    assert_stale_settings_are_rejected(stale).await;
}

#[tokio::test]
async fn rejects_a_stale_access_token_without_changes_or_audit() {
    let mut stale = initial_settings();
    stale.access_token = Some("spec-stale-access-credential".to_owned());
    assert_stale_settings_are_rejected(stale).await;
}

#[tokio::test]
async fn rejects_a_stale_refresh_token_without_changes_or_audit() {
    let mut stale = initial_settings();
    stale.refresh_token = Some("spec-stale-refresh-credential".to_owned());
    assert_stale_settings_are_rejected(stale).await;
}

#[tokio::test]
async fn rejects_a_stale_device_id_without_changes_or_audit() {
    let mut stale = initial_settings();
    stale.device_id = Some("spec-stale-device-credential".to_owned());
    assert_stale_settings_are_rejected(stale).await;
}

#[tokio::test]
async fn rejects_missing_expected_credential_fields_without_changes_or_audit() {
    for field in 0..4 {
        let mut stale = initial_settings();
        match field {
            0 => stale.blog_url = None,
            1 => stale.access_token = None,
            2 => stale.refresh_token = None,
            _ => stale.device_id = None,
        }
        assert_stale_settings_are_rejected(stale).await;
    }
}

#[tokio::test]
async fn identical_token_pair_succeeds_without_audit() {
    let (_directory, _path, inventory, expected) = fixture().await;
    let previous_audit_count = audit_count(&inventory).await;

    assert!(
        inventory
            .save_boosty_session(
                &expected,
                expected.access_token.as_deref().unwrap(),
                expected.refresh_token.as_deref().unwrap(),
            )
            .await
            .unwrap()
    );

    assert_same_settings(&inventory.get_boosty_settings().await.unwrap(), &expected);
    assert_eq!(audit_count(&inventory).await, previous_audit_count);
}

#[tokio::test]
async fn rejects_empty_and_whitespace_only_tokens_without_mutation_or_audit() {
    let (_directory, _path, inventory, expected) = fixture().await;
    let previous_audit_count = audit_count(&inventory).await;

    for invalid in ["", " ", "\t\r\n"] {
        for (access, refresh) in [
            (invalid, "spec-valid-new-refresh"),
            ("spec-valid-new-access", invalid),
        ] {
            assert!(
                inventory
                    .save_boosty_session(&expected, access, refresh)
                    .await
                    .is_err()
            );
            assert_same_settings(&inventory.get_boosty_settings().await.unwrap(), &expected);
            assert_eq!(audit_count(&inventory).await, previous_audit_count);
        }
    }
}

#[tokio::test]
async fn audit_failure_rolls_back_both_tokens() {
    let (_directory, path, inventory, expected) = fixture().await;
    let previous_audit_count = audit_count(&inventory).await;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_boosty_session_audit BEFORE INSERT ON audit_log \
         WHEN NEW.action = 'boosty.session.refreshed' \
         BEGIN SELECT RAISE(ABORT, 'test audit failure'); END",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        inventory
            .save_boosty_session(
                &expected,
                "spec-rolled-back-access",
                "spec-rolled-back-refresh",
            )
            .await
            .is_err()
    );

    assert_same_settings(&inventory.get_boosty_settings().await.unwrap(), &expected);
    assert_eq!(audit_count(&inventory).await, previous_audit_count);
    pool.close().await;
}

#[tokio::test]
async fn enabled_changes_do_not_invalidate_or_get_overwritten_by_a_session_save() {
    let (_directory, _path, inventory, expected) = fixture().await;
    let mut current = initial_settings();
    current.enabled = false;
    inventory.set_boosty_settings(&current).await.unwrap();
    let previous_audit_count = audit_count(&inventory).await;

    assert!(
        inventory
            .save_boosty_session(
                &expected,
                "spec-disabled-new-access",
                "spec-disabled-new-refresh",
            )
            .await
            .unwrap()
    );

    let saved = inventory.get_boosty_settings().await.unwrap();
    assert!(!saved.enabled);
    assert_eq!(saved.blog_url, current.blog_url);
    assert_eq!(saved.device_id, current.device_id);
    assert_eq!(
        saved.access_token.as_deref(),
        Some("spec-disabled-new-access")
    );
    assert_eq!(
        saved.refresh_token.as_deref(),
        Some("spec-disabled-new-refresh")
    );
    assert_eq!(audit_count(&inventory).await, previous_audit_count + 1);
}
