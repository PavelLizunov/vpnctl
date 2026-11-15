#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{borrow::Cow, path::Path};

use sqlx::{
    SqlitePool,
    migrate::{Migration, MigrationType, Migrator},
};

// Frozen from docs/specs/corp-live-base-integration.md, independently of migrations 70+.
const LIVE_70_SQL: &str = "\
-- Optional hoster quotas; do not assign an allowance to existing servers.
CREATE TABLE server_traffic_limits (
    server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    limit_bytes INTEGER NOT NULL CHECK(limit_bytes > 0),
    direction TEXT NOT NULL CHECK(direction IN ('rx', 'tx', 'both')),
    reset_day INTEGER NOT NULL CHECK(reset_day BETWEEN 1 AND 31),
    warning_pct INTEGER NOT NULL CHECK(warning_pct BETWEEN 1 AND 100)
);
";
const LIVE_70_SHA384: &str = "0825cd86fedec2dc342689a78d69d6ba6181c5a3c6adc281f5863566c92c07c0f0d008bc84109a071a9b0efd6c0916de";

pub(super) fn frozen_checksum() -> Vec<u8> {
    LIVE_70_SHA384
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(super) async fn install_legacy_70(pool: &SqlitePool) {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations = Vec::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((version, description)) = name.split_once('_') else {
            continue;
        };
        let Ok(version) = version.parse::<i64>() else {
            continue;
        };
        // Filter BEFORE reading: only unchanged legacy fixtures may be read.
        if !(1..=69).contains(&version) || !description.ends_with(".sql") {
            continue;
        }
        migrations.push(Migration::new(
            version,
            Cow::Owned(description.trim_end_matches(".sql").replace('_', " ")),
            MigrationType::Simple,
            Cow::Owned(std::fs::read_to_string(path).unwrap()),
            false,
        ));
    }
    migrations.sort_by_key(|migration| migration.version);
    assert_eq!(
        migrations.iter().map(|m| m.version).collect::<Vec<_>>(),
        (1..=69).collect::<Vec<_>>()
    );
    let migrator = Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    };
    migrator.run(pool).await.unwrap();

    let frozen = Migration::new(
        70,
        Cow::Borrowed("server traffic limits"),
        MigrationType::Simple,
        Cow::Borrowed(LIVE_70_SQL),
        false,
    );
    assert_eq!(frozen.checksum.as_ref(), frozen_checksum().as_slice());
    sqlx::raw_sql(LIVE_70_SQL).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES (70, 'server traffic limits', 1, ?, 0)",
    )
    .bind(frozen_checksum())
    .execute(pool)
    .await
    .unwrap();
}
