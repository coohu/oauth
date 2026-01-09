use sqlx::{AnyPool, any::AnyPoolOptions};
pub mod client;
pub mod token;
pub mod user;
pub mod rate_limit;
pub mod authorization_code;
pub mod refresh_token;

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
        authorization_code::init(&self.pool).await?;
        refresh_token::init(&self.pool).await?;
        Ok(())
    }

    pub async fn verify_client(
        &self,
        id: &str,
        secret: Option<&str>,
    ) -> Result<String, crate::error::AppError> {
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
        secret: Option<&str>,
        client_type: &str,
        redirect_uris: &str,
        allowed_scopes: &str,
        cost: u32,
    ) -> Result<(), crate::error::AppError> {
        client::create_client(&self.pool, id, secret, client_type, redirect_uris, allowed_scopes, cost)
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
        secret: Option<&str>,
        cost: u32,
    ) -> Result<u64, crate::error::AppError> {
        client::update_client_secret(&self.pool, id, secret, cost)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<client::ClientInfo>, crate::error::AppError> {
        client::get_client(&self.pool, client_id)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn validate_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<bool, crate::error::AppError> {
        client::validate_redirect_uri(&self.pool, client_id, redirect_uri)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn validate_scope(
        &self,
        client_id: &str,
        scope: &str,
    ) -> Result<bool, crate::error::AppError> {
        client::validate_scope(&self.pool, client_id, scope)
            .await
            .map_err(crate::error::AppError::Database)
    }

    // Authorization code methods
    pub async fn create_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        user_id: &str,
        scope: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        expires_at: i64,
    ) -> Result<(), crate::error::AppError> {
        authorization_code::create_authorization_code(
            &self.pool,
            code,
            client_id,
            redirect_uri,
            user_id,
            scope,
            code_challenge,
            code_challenge_method,
            expires_at,
        )
        .await
        .map_err(crate::error::AppError::Database)
    }

    pub async fn get_and_mark_authorization_code_used(
        &self,
        code: &str,
    ) -> Result<Option<authorization_code::AuthorizationCode>, crate::error::AppError> {
        authorization_code::get_and_mark_used(&self.pool, code)
            .await
            .map_err(crate::error::AppError::Database)
    }

    // Refresh token methods
    pub async fn create_refresh_token(
        &self,
        token_hash: &str,
        client_id: &str,
        user_id: &str,
        scope: &str,
        expires_at: i64,
    ) -> Result<(), crate::error::AppError> {
        refresh_token::create_refresh_token(&self.pool, token_hash, client_id, user_id, scope, expires_at)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<refresh_token::RefreshToken>, crate::error::AppError> {
        refresh_token::get_refresh_token(&self.pool, token_hash)
            .await
            .map_err(crate::error::AppError::Database)
    }

    #[allow(dead_code)]
    pub async fn revoke_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<u64, crate::error::AppError> {
        refresh_token::revoke_refresh_token(&self.pool, token_hash)
            .await
            .map_err(crate::error::AppError::Database)
    }

    #[allow(dead_code)]
    pub async fn cleanup_expired_tokens(&self) -> Result<(), crate::error::AppError> {
        authorization_code::cleanup_expired(&self.pool)
            .await
            .map_err(crate::error::AppError::Database)?;
        refresh_token::cleanup_expired(&self.pool)
            .await
            .map_err(crate::error::AppError::Database)?;
        Ok(())
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
