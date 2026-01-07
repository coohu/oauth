use bcrypt::{hash, verify as bcrypt_verify};
use sqlx::{Pool, Row, Sqlite, SqlitePool};
use crate::error::AppError;

pub async fn init(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
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

pub async fn create_client(
    pool: &Pool<Sqlite>,
    id: &str,
    secret: &str,
    cost: u32,
) -> Result<(), AppError> {
    let hash = hash(secret, cost).map_err(|_| AppError::Internal)?;

    sqlx::query(
        "INSERT INTO oauth_client (id, secret_hash) VALUES (?, ?)",
    )
    .bind(id)
    .bind(hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn verify_client(
    pool: &Pool<Sqlite>,
    id: &str,
    secret: &str,
) -> Result<(), AppError> {
    let row = sqlx::query(
        "SELECT secret_hash FROM oauth_client WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let row = row.ok_or(AppError::Unauthorized)?;
    let secret_hash: String = row.get("secret_hash");

    if bcrypt_verify(secret, &secret_hash).unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

pub async fn delete_client(
    pool: &SqlitePool,
    client_id: &str,
) -> Result<u64, AppError> {
    let res = sqlx::query(
        "DELETE FROM oauth_client WHERE id = ?"
    )
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

pub async fn update_client_secret(
    pool: &SqlitePool,
    client_id: &str,
    new_secret: &str,
    cost: u32,
) -> Result<u64, AppError> {
    let hash = hash(new_secret, cost).map_err(|_| AppError::Internal)?;

    let res = sqlx::query(
        "UPDATE oauth_client SET secret_hash = ? WHERE id = ?"
    )
    .bind(hash)
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}
