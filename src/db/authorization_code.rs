use sqlx::AnyPool;
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: i64,
    pub used: i16,
}

pub async fn create_authorization_code(
    pool: &AnyPool,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    user_id: &str,
    scope: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        r#"
        INSERT INTO authorization_codes 
        (code, client_id, redirect_uri, user_id, scope, code_challenge, code_challenge_method, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(code)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(user_id)
    .bind(scope)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await
    .inspect_err(|e| {
        error!("Database error occurred while creating auth code: {}", e);
    })?;
    Ok(())
}

pub async fn get_and_mark_used(
    pool: &AnyPool,
    code: &str,
) -> Result<Option<AuthorizationCode>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    
    // Start transaction
    let mut tx = pool.begin().await?;
    
    let auth_code: Option<AuthorizationCode> = sqlx::query_as(
        "SELECT code, client_id, redirect_uri, user_id, scope, code_challenge, code_challenge_method, expires_at, used FROM authorization_codes WHERE code = ? AND expires_at > ? AND used = 0"
    )
        .bind(code)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await.inspect_err(|e|{error!("get_and_mark_used(){}",e)})?;
    
    if let Some(ref ac) = auth_code {
        // Mark as used
        sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code = ?")
            .bind(&ac.code)
            .execute(&mut *tx)
            .await?;
    }
    
    tx.commit().await?;
    Ok(auth_code)
}

pub async fn cleanup_expired(pool: &AnyPool) -> Result<u64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query("DELETE FROM authorization_codes WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Load all valid (non-expired, non-used) authorization codes from the database
pub async fn load_valid_codes(pool: &AnyPool) -> Result<Vec<AuthorizationCode>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query_as::<_, AuthorizationCode>(
        "SELECT code, client_id, redirect_uri, user_id, scope, code_challenge, code_challenge_method, expires_at, used FROM authorization_codes WHERE expires_at > ? AND used = 0"
    )
    .bind(now)
    .fetch_all(pool)
    .await
}
