use sqlx::AnyPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshToken {
    pub token_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: i64,
    pub revoked: bool,
}

pub async fn create_refresh_token(
    pool: &AnyPool,
    token_hash: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
        (token_hash, client_id, user_id, scope, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(scope)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_refresh_token(
    pool: &AnyPool,
    token_hash: &str,
) -> Result<Option<RefreshToken>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query_as(
        "SELECT token_hash, client_id, user_id, scope, expires_at, revoked FROM refresh_tokens WHERE token_hash = ? AND expires_at > ? AND revoked = 0"
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
}

pub async fn revoke_refresh_token(
    pool: &AnyPool,
    token_hash: &str,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[allow(dead_code)]
pub async fn revoke_all_for_user(
    pool: &AnyPool,
    user_id: &str,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn cleanup_expired(pool: &AnyPool) -> Result<u64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
