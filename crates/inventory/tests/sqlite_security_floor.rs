use sqlx::{Connection, SqliteConnection};

#[tokio::test]
async fn sqlite_runtime_meets_security_floor() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = SqliteConnection::connect(":memory:").await?;
    let actual: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&mut connection)
        .await?;
    let components: Vec<u64> = actual
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("invalid SQLite runtime version {actual:?}: {error}"))?;
    let [major, minor, patch] = components.as_slice() else {
        return Err(format!("unexpected SQLite runtime version {actual:?}").into());
    };

    assert!(
        (*major, *minor, *patch) >= (3, 54, 1),
        "SQLite runtime {actual} is below the required security floor 3.54.1"
    );
    Ok(())
}
