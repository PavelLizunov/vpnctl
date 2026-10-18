#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_inventory::{SqliteInventory, TelegramConfig};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
}

#[tokio::test]
async fn notification_language_round_trips_and_is_independent_of_telegram() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    assert_eq!(
        inv.get_telegram_config().await.unwrap().unwrap().language,
        None
    );
    inv.set_notification_language(Some("ru")).await.unwrap();
    assert_eq!(
        inv.get_telegram_config()
            .await
            .unwrap()
            .unwrap()
            .language
            .as_deref(),
        Some("ru")
    );
    inv.set_telegram_config(Some("123:abcdefghijklmno"), Some("42"), None)
        .await
        .unwrap();
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(
        cfg.language.as_deref(),
        Some("ru"),
        "language preserved across telegram save"
    );
    assert_eq!(cfg.token.as_deref(), Some("123:abcdefghijklmno"));
    inv.set_notification_language(None).await.unwrap();
    assert_eq!(
        inv.get_telegram_config().await.unwrap().unwrap().language,
        None
    );
}

#[tokio::test]
async fn get_on_fresh_db_returns_some_with_both_halves_none() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let cfg = inv
        .get_telegram_config()
        .await
        .expect("get_telegram_config must not error on fresh DB");
    assert_eq!(
        cfg,
        Some(TelegramConfig {
            token: None,
            chat_id: None,
            proxy_via_server_id: None,
            language: None,
        }),
        "migration 0014 seed must insert singleton row with both halves NULL"
    );
}

#[tokio::test]
async fn proxy_via_server_id_is_seeded_null_on_fresh_db() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(cfg.proxy_via_server_id, None);
}

#[tokio::test]
async fn proxy_via_server_id_round_trip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("t"), Some("c"), Some("vps-de1"))
        .await
        .unwrap();
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(cfg.proxy_via_server_id.as_deref(), Some("vps-de1"));
}

#[tokio::test]
async fn proxy_via_server_id_clears_independently_of_other_fields() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("t"), Some("c"), Some("vps-de1"))
        .await
        .unwrap();
    inv.set_telegram_config(Some("t"), Some("c"), None)
        .await
        .unwrap();
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(cfg.token.as_deref(), Some("t"), "token preserved");
    assert_eq!(cfg.chat_id.as_deref(), Some("c"), "chat_id preserved");
    assert_eq!(
        cfg.proxy_via_server_id, None,
        "proxy_via_server_id cleared back to direct"
    );
}

#[tokio::test]
async fn proxy_via_server_id_does_not_gate_is_enabled() {
    let cfg = TelegramConfig {
        token: Some("t".into()),
        chat_id: Some("c".into()),
        proxy_via_server_id: None,
        language: None,
    };
    assert!(cfg.is_enabled(), "direct mode with both halves → enabled");

    let cfg = TelegramConfig {
        token: Some("t".into()),
        chat_id: Some("c".into()),
        proxy_via_server_id: Some("vps-de1".into()),
        language: None,
    };
    assert!(
        cfg.is_enabled(),
        "via-proxy mode with both halves → enabled"
    );

    let cfg = TelegramConfig {
        token: None,
        chat_id: Some("c".into()),
        proxy_via_server_id: Some("vps-de1".into()),
        language: None,
    };
    assert!(
        !cfg.is_enabled(),
        "missing token disables regardless of proxy"
    );
}

#[tokio::test]
async fn set_both_some_then_get_returns_both() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("t"), Some("c"), None)
        .await
        .expect("set must not error");
    let cfg = inv.get_telegram_config().await.unwrap();
    assert_eq!(
        cfg,
        Some(TelegramConfig {
            token: Some("t".into()),
            chat_id: Some("c".into()),
            proxy_via_server_id: None,
            language: None,
        }),
        "round-trip must return exactly what was set"
    );
}

#[tokio::test]
async fn set_both_none_clears_but_singleton_remains() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("t"), Some("c"), None)
        .await
        .unwrap();
    inv.set_telegram_config(None, None, None)
        .await
        .expect("clear must not error");
    let cfg = inv.get_telegram_config().await.unwrap();
    assert_eq!(
        cfg,
        Some(TelegramConfig {
            token: None,
            chat_id: None,
            proxy_via_server_id: None,
            language: None,
        }),
        "clear must leave singleton row in place with both halves NULL"
    );
}

#[tokio::test]
async fn set_partial_token_only_is_accepted_and_persisted() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("a"), None, None)
        .await
        .expect("partial config must be accepted at storage layer");
    let cfg = inv
        .get_telegram_config()
        .await
        .unwrap()
        .expect("singleton row must exist");
    assert_eq!(
        cfg.token.as_deref(),
        Some("a"),
        "token must be persisted as Some"
    );
    assert_eq!(cfg.chat_id, None, "chat_id must remain None");
    assert!(
        !cfg.is_enabled(),
        "is_enabled must be false when one half is None"
    );
}

#[tokio::test]
async fn successive_set_calls_overwrite_only_one_row() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.set_telegram_config(Some("first-token"), Some("first-chat"), None)
        .await
        .unwrap();
    inv.set_telegram_config(Some("second-token"), Some("second-chat"), None)
        .await
        .unwrap();
    inv.set_telegram_config(Some("third-token"), Some("third-chat"), None)
        .await
        .unwrap();
    let cfg = inv.get_telegram_config().await.unwrap();
    assert_eq!(
        cfg,
        Some(TelegramConfig {
            token: Some("third-token".into()),
            chat_id: Some("third-chat".into()),
            proxy_via_server_id: None,
            language: None,
        }),
        "only the LAST set must be observable — proves singleton, not append"
    );

    inv.set_telegram_config(None, None, None).await.unwrap();
    let cleared = inv.get_telegram_config().await.unwrap();
    assert_eq!(
        cleared,
        Some(TelegramConfig {
            token: None,
            chat_id: None,
            proxy_via_server_id: None,
            language: None,
        }),
        "clear after multiple writes still ends in single empty row"
    );
}

#[tokio::test]
async fn is_enabled_true_when_both_halves_some() {
    let cfg = TelegramConfig {
        token: Some("hello123".into()),
        chat_id: Some("@me".into()),
        proxy_via_server_id: None,
        language: None,
    };
    assert!(cfg.is_enabled(), "both Some(_) must be enabled");
}

#[tokio::test]
async fn is_enabled_false_when_token_missing() {
    let cfg = TelegramConfig {
        token: None,
        chat_id: Some("@me".into()),
        proxy_via_server_id: None,
        language: None,
    };
    assert!(!cfg.is_enabled(), "missing token must disable");
}

#[tokio::test]
async fn is_enabled_false_when_chat_id_missing() {
    let cfg = TelegramConfig {
        token: Some("abc".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert!(!cfg.is_enabled(), "missing chat_id must disable");
}

#[tokio::test]
async fn is_enabled_false_when_both_none() {
    let cfg = TelegramConfig {
        token: None,
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert!(!cfg.is_enabled(), "both None must be disabled");
}

#[tokio::test]
async fn token_last4_returns_last_four_chars_for_long_token() {
    let cfg = TelegramConfig {
        token: Some("1234567890:ABCDEF".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg.token_last4(),
        "CDEF",
        "must return literal last 4 chars of token"
    );
}

#[tokio::test]
async fn token_last4_returns_full_token_when_shorter_than_4() {
    let cfg = TelegramConfig {
        token: Some("abc".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg.token_last4(),
        "abc",
        "tokens shorter than 4 chars must be returned whole, not panic"
    );
}

#[tokio::test]
async fn token_last4_handles_exactly_four_chars() {
    let cfg = TelegramConfig {
        token: Some("abcd".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg.token_last4(),
        "abcd",
        "4-char token must return all 4 chars"
    );
}

#[tokio::test]
async fn token_last4_returns_empty_string_when_token_none() {
    let cfg = TelegramConfig {
        token: None,
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(cfg.token_last4(), "", "None token must yield empty string");
}

#[tokio::test]
async fn token_last4_handles_non_ascii_long_token() {
    let cfg = TelegramConfig {
        token: Some("123тест".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg.token_last4(),
        "тест",
        "must return last 4 unicode chars from mixed/non-ascii token"
    );

    let cfg_emoji = TelegramConfig {
        token: Some("bot_secret_🦀🎉🔥🚀".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg_emoji.token_last4(),
        "🦀🎉🔥🚀",
        "must correctly extract last 4 multi-byte emoji characters"
    );
}

#[tokio::test]
async fn token_last4_handles_non_ascii_short_token() {
    let cfg_cjk = TelegramConfig {
        token: Some("абв".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg_cjk.token_last4(),
        "абв",
        "short multi-byte token must return whole token"
    );

    let cfg_emoji = TelegramConfig {
        token: Some("🦀".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg_emoji.token_last4(),
        "🦀",
        "single multi-byte character must return whole token"
    );
}

#[tokio::test]
async fn token_last4_handles_non_ascii_exact_four_chars() {
    let cfg = TelegramConfig {
        token: Some("тест".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg.token_last4(),
        "тест",
        "exact 4-char non-ascii token must return all 4 chars"
    );

    let cfg_emoji = TelegramConfig {
        token: Some("🦀🎉🔥🚀".into()),
        chat_id: None,
        proxy_via_server_id: None,
        language: None,
    };
    assert_eq!(
        cfg_emoji.token_last4(),
        "🦀🎉🔥🚀",
        "exact 4 emoji token must return all 4 chars"
    );
}
