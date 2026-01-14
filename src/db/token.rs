use sqlx::AnyPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub expires_at: i64,
    pub user_id: Option<String>,
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

pub async fn load_valid_tokens(pool: &AnyPool) -> Result<Vec<AccessToken>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query_as::<_, AccessToken>(
        "SELECT token_hash, client_id, expires_at, user_id FROM access_token WHERE expires_at > ? AND user_id IS NOT NULL"
    )
    .bind(now)
    .fetch_all(pool)
    .await
}
