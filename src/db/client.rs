use bcrypt::{hash, verify as bcrypt_verify};
use sqlx::{Row, AnyPool};
use crate::error::AppError;

pub async fn init(pool: &AnyPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_client (
            id TEXT PRIMARY KEY,
            secret_hash TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_client(pool: &AnyPool,client_id: &str,client_secret: &str,bcrypt_cost: u32) -> Result<(), sqlx::Error> {
    let secret_hash = hash(client_secret, bcrypt_cost)
        .expect("bcrypt failed");

    sqlx::query(
        "INSERT INTO oauth_client (id, secret_hash) VALUES (?, ?)"
    )
    .bind(client_id)
    .bind(secret_hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn verify_client(pool: &AnyPool, id: &str, secret: &str) -> Result<(), AppError> {
    if id.is_empty() || secret.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let row = sqlx::query("SELECT secret_hash FROM oauth_client WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let row = match row {
        Some(r) => r,
        None => {
            // 为了防止针对 client_id 的枚举攻击，即使 client 不存在也进行一次模拟验证
            // 这里使用一个固定的 dummy hash
            let dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LqCF7u56qEKn4zueWLSad7zTV9NjjK9OmNS0q";
            let _ = bcrypt_verify(secret, dummy_hash);
            return Err(AppError::Unauthorized);
        }
    };

    let secret_hash: String = row.get("secret_hash");

    if bcrypt_verify(secret, &secret_hash).unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

pub async fn delete_client(pool: &AnyPool,client_id: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM oauth_client WHERE id = ?"
    )
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

pub async fn update_client_secret(
    pool: &AnyPool,
    client_id: &str,
    new_secret: &str,
    bcrypt_cost: u32,
) -> Result<u64, sqlx::Error> {
    let secret_hash = hash(new_secret, bcrypt_cost)
        .expect("bcrypt failed");

    let res = sqlx::query(
        "UPDATE oauth_client SET secret_hash = ? WHERE id = ?"
    )
    .bind(secret_hash)
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}
