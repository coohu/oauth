use sqlx::{AnyPool, Row};
use serde::{Deserialize, Serialize};
use crate::db::user::{User, get_user_by_id};

#[derive(Debug, Serialize, Deserialize)]
pub struct Pat {
    pub id: i64,
    pub user_id: String,
    pub name: String,
    pub token: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

impl<'r> sqlx::FromRow<'r, sqlx::any::AnyRow> for Pat {
    fn from_row(row: &'r sqlx::any::AnyRow) -> Result<Self, sqlx::Error> {
        let scopes_str: Option<String> = row.try_get("scopes").ok();
        let scopes = scopes_str.and_then(|s| serde_json::from_str(&s).ok());

        Ok(Pat {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            name: row.try_get("name")?,
            token: row.try_get("token")?,
            scopes,
            expires_at: row.try_get("expires_at").ok().flatten(),
            last_used_at: row.try_get("last_used_at").ok().flatten(),
            created_at: row.try_get("created_at")?,
            deleted_at: row.try_get("deleted_at").ok().flatten(),
        })
    }
}

pub async fn create_pat(
    pool: &AnyPool,
    user_id: &str,
    name: Option<&str>,
    token: &str,
    scopes: Option<Vec<String>>,
    expires_at: Option<i64>,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let scopes_json = serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".to_string());
    sqlx::query(
        "INSERT INTO personal_access_tokens (user_id, name, token, scopes, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(name.unwrap_or("default"))
    .bind(token)
    .bind(scopes_json)
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_pats(
    pool: &AnyPool,
    user_id: &str,
) -> Result<Vec<Pat>, sqlx::Error> {
    sqlx::query_as::<_, Pat>(
        "SELECT * FROM personal_access_tokens WHERE user_id = ? AND deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn get_user_by_pat(
    pool: &AnyPool,
    token: &str,
) -> Result<Option<User>, sqlx::Error> {
    let pat = sqlx::query_as::<_, Pat>(
        "SELECT * FROM personal_access_tokens WHERE token = ? AND (expires_at IS NULL OR expires_at > ?)",
    )
        .bind(token)
        .bind(chrono::Utc::now().timestamp())
        .fetch_optional(pool)
        .await?;

    match pat {
        Some(p) => get_user_by_id(pool, &p.user_id).await,
        None => Ok(None),
    }
}

pub async fn update_pat(
    pool: &AnyPool,
    id: &str,
    user_id: Option<&str>,
    name: Option<&str>,
    token: Option<&str>,
    scopes: Option<Vec<String>>,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
    deleted_at: Option<i64>
) -> Result<(), sqlx::Error> {
    let scopes_json = scopes.and_then(|s| serde_json::to_string(&s).ok());

    sqlx::query(
        r#"
        UPDATE personal_access_tokens
        SET
            user_id = COALESCE(?, user_id),
            name = COALESCE(?, name),
            token = COALESCE(?, token),
            scopes = COALESCE(?, scopes),
            expires_at = COALESCE(?, expires_at),
            last_used_at = COALESCE(?, last_used_at),
            deleted_at = COALESCE(?, deleted_at)
        WHERE id = ?
        "#
    )
    .bind(user_id)
    .bind(name)
    .bind(token)
    .bind(scopes_json)
    .bind(expires_at)
    .bind(last_used_at)
    .bind(deleted_at)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn drop_pat(
    pool: &AnyPool,
    id: &str,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("DELETE FROM personal_access_tokens WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(res.rows_affected())
}
