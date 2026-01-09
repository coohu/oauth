use sqlx::AnyPool;

pub async fn init(pool: &AnyPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS access_token (
            token_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            user_id TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_access_token(
    pool: &AnyPool,
    token_hash: &str,
    client_id: &str,
    expires_at: i64, // unix timestamp (seconds)
    user_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO access_token (token_hash, client_id, expires_at, user_id)
        VALUES (?, ?, ?, ?)
        "#
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(expires_at)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_access_token(pool: &AnyPool, token_hash: &str) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT client_id, user_id FROM access_token WHERE token_hash = ? AND expires_at > ?"
    )
    .bind(token_hash)
    .bind(chrono::Utc::now().timestamp())
    .fetch_optional(pool)
    .await
}
