use sqlx::{AnyPool, any::AnyPoolOptions};
pub mod client;
pub mod token;
pub mod user;
pub mod rate_limit;

#[derive(Clone)]
pub struct Database {
    pool: AnyPool,
}

impl Database {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<(), sqlx::Error> {
        client::init(&self.pool).await?;
        token::init(&self.pool).await?;
        user::init(&self.pool).await?;
        rate_limit::init(&self.pool).await?;
        Ok(())
    }

    pub async fn verify_client(
        &self,
        id: &str,
        secret: &str,
    ) -> Result<(), crate::error::AppError> {
        client::verify_client(&self.pool, id, secret).await
    }

    pub async fn issue_token(
        &self,
        token_hash: &str,
        client_id: &str,
        expires_at: i64,
        user_id: Option<&str>,
    ) -> Result<(), crate::error::AppError> {
        token::insert_access_token(&self.pool, token_hash, client_id, expires_at, user_id)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn get_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, Option<String>)>, crate::error::AppError> {
        token::get_access_token(&self.pool, token_hash)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn create_client(
        &self,
        id: &str,
        secret: &str,
        cost: u32,
    ) -> Result<(), crate::error::AppError> {
        client::create_client(&self.pool, id, secret, cost)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn delete_client(
        &self,
        id: &str,
    ) -> Result<u64, crate::error::AppError> {
        client::delete_client(&self.pool, id)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn update_client_secret(
        &self,
        id: &str,
        secret: &str,
        cost: u32,
    ) -> Result<u64, crate::error::AppError> {
        client::update_client_secret(&self.pool, id, secret, cost)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<String, crate::error::AppError> {
        let id = uuid::Uuid::new_v4().to_string();
        user::create_user(&self.pool, &id, username, password_hash)
            .await
            .map_err(crate::error::AppError::Database)?;
        Ok(id)
    }

    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<user::User>, crate::error::AppError> {
        user::get_user_by_username(&self.pool, username)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn get_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<user::User>, crate::error::AppError> {
        user::get_user_by_id(&self.pool, id)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn check_rate_limit(
        &self,
        key: &str,
        limit: i64,
        window_secs: i64,
    ) -> Result<bool, crate::error::AppError> {
        rate_limit::check_rate_limit(&self.pool, key, limit, window_secs)
            .await
            .map_err(crate::error::AppError::Database)
    }
}
