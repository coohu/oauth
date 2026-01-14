use sqlx::{AnyPool, Row};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub tel: Option<String>,
    pub username: Option<String>,
    pub password_hash: String,
    pub roles: Option<Vec<String>>,
    pub created_at: i64,
}

impl<'r> sqlx::FromRow<'r, sqlx::any::AnyRow> for User {
    fn from_row(row: &'r sqlx::any::AnyRow) -> Result<Self, sqlx::Error> {
        let roles_str: Option<String> = row.try_get("roles").ok();
        let roles = roles_str.and_then(|s| serde_json::from_str(&s).ok());

        Ok(User {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            tel: row.try_get::<Option<String>, _>("tel").unwrap_or(None),
            username: row.try_get::<Option<String>, _>("username").unwrap_or(None),
            password_hash: row.try_get("password_hash")?,
            roles,
            created_at: row.try_get("created_at")?,
        })
    }
}

pub async fn create_user(
    pool: &AnyPool,
    id: &str,
    email: &str,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_user_by_email(
    pool: &AnyPool,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, tel, username, password_hash, roles, created_at FROM users WHERE email = ?"
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}
#[allow(dead_code)]
pub async fn get_user_by_username(
    pool: &AnyPool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, tel, username, password_hash, roles, created_at FROM users WHERE username = ?"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

pub async fn get_user_by_id(pool: &AnyPool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, tel, username, password_hash, roles, created_at FROM users WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn update_user(
    pool: &AnyPool,
    id: &str,
    email: Option<&str>,
    tel: Option<&str>,
    username: Option<&str>,
    password_hash: Option<&str>,
    roles: Option<Vec<String>>,
) -> Result<(), sqlx::Error> {
    let roles_json = roles.and_then(|r| serde_json::to_string(&r).ok());

    sqlx::query(
        r#"
        UPDATE users 
        SET 
            email = COALESCE(?, email),
            tel = COALESCE(?, tel),
            username = COALESCE(?, username),
            password_hash = COALESCE(?, password_hash),
            roles = COALESCE(?, roles)
        WHERE id = ?
        "#
    )
    .bind(email)
    .bind(tel)
    .bind(username)
    .bind(password_hash)
    .bind(roles_json)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}
