use bcrypt::{hash, verify as bcrypt_verify};
use sqlx::{Row, AnyPool};
use crate::error::AppError;

pub async fn create_client(
    pool: &AnyPool,
    client_id: &str,
    client_secret: Option<&str>,
    client_type: &str,
    redirect_uris: &str,
    allowed_scopes: &str,
    bcrypt_cost: u32,
) -> Result<(), sqlx::Error> {
    let secret_hash = client_secret.map(|secret| {
        hash(secret, bcrypt_cost).expect("bcrypt failed")
    });
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO oauth_client (id, secret_hash, client_type, redirect_uris, allowed_scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(client_id)
    .bind(secret_hash)
    .bind(client_type)
    .bind(redirect_uris)
    .bind(allowed_scopes)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn verify_client(pool: &AnyPool, id: &str, secret: Option<&str>) -> Result<String, AppError> {
    if id.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let row = sqlx::query("SELECT secret_hash, client_type FROM oauth_client WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let row = match row {
        Some(r) => r,
        None => {
            // 为了防止针对 client_id 的枚举攻击,即使 client 不存在也进行一次模拟验证
            if let Some(secret_val) = secret {
                let dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LqCF7u56qEKn4zueWLSad7zTV9NjjK9OmNS0q";
                let _ = bcrypt_verify(secret_val, dummy_hash);
            }
            return Err(AppError::Unauthorized);
        }
    };

    let secret_hash: Option<String> = row.try_get("secret_hash").unwrap_or(None);
    let client_type: String = row.get("client_type");

    // Public clients don't have secrets
    if client_type == "public" {
        if secret.is_some() {
            return Err(AppError::Unauthorized);
        }
        return Ok(client_type);
    }

    // Confidential clients must provide a secret
    let secret = secret.ok_or(AppError::Unauthorized)?;
    let secret_hash = secret_hash.ok_or(AppError::Unauthorized)?;

    if bcrypt_verify(secret, &secret_hash).unwrap_or(false) {
        Ok(client_type)
    } else {
        Err(AppError::Unauthorized)
    }
}

pub async fn delete_client(pool: &AnyPool,client_id: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("DELETE FROM oauth_client WHERE id = ?")
        .bind(client_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn update_client_secret(
    pool: &AnyPool,
    client_id: &str,
    new_secret: Option<&str>,
    bcrypt_cost: u32,
) -> Result<u64, sqlx::Error> {
    let secret_hash = new_secret.map(|secret| {
        hash(secret, bcrypt_cost).expect("bcrypt failed")
    });

    let res = sqlx::query("UPDATE oauth_client SET secret_hash = ? WHERE id = ?")
        .bind(secret_hash)
        .bind(client_id)
        .execute(pool)
        .await?;

    Ok(res.rows_affected())
}

pub async fn get_client(pool: &AnyPool, client_id: &str) -> Result<Option<ClientInfo>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, client_type, redirect_uris, allowed_scopes FROM oauth_client WHERE id = ?"
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
}

pub async fn validate_redirect_uri(
    pool: &AnyPool,
    client_id: &str,
    redirect_uri: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT redirect_uris FROM oauth_client WHERE id = ?")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    if let Some((redirect_uris,)) = row {
        // redirect_uris is stored as comma-separated list
        let valid = redirect_uris.split(',')
            .any(|uri| uri.trim() == redirect_uri);
        Ok(valid)
    } else {
        Ok(false)
    }
}

pub async fn validate_scope( pool: &AnyPool, client_id: &str, requested_scope: &str ) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT allowed_scopes FROM oauth_client WHERE id = ?")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    if let Some((allowed_scopes,)) = row {
        // Check if all requested scopes are in allowed_scopes
        let allowed: Vec<&str> = allowed_scopes.split(',').map(|s| s.trim()).collect();
        let requested: Vec<&str> = requested_scope.split(',').map(|s| s.trim()).collect();

        let valid = requested.iter().all(|scope| allowed.contains(scope));
        Ok(valid)
    } else {
        Ok(false)
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ClientInfo {
    pub id: String,
    pub client_type: String,
    pub redirect_uris: String,
    pub allowed_scopes: String,
}
