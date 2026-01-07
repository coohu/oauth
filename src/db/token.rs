use chrono::{Duration, Utc};
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

use crate::error::AppError;
use crate::util::hash_token;

pub async fn init(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS access_token (
            token_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn issue(
    pool: &Pool<Sqlite>,
    client_id: &str,
    ttl: i64,
) -> Result<String, AppError> {
    let raw = Uuid::new_v4().to_string();
    let hash = hash_token(&raw);

    let expires = (Utc::now() + Duration::seconds(ttl)).timestamp();

    sqlx::query(
        "INSERT INTO access_token (token_hash, client_id, expires_at) VALUES (?, ?, ?)"
    ).bind(hash).bind(client_id).bind(expires)
    .execute(pool)
    .await?;

    Ok(raw)
}
