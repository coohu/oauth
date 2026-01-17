use sqlx::{AnyPool, any::AnyPoolOptions};
pub mod client;
pub mod token;
pub mod user;
pub mod rate_limit;
pub mod authorization_code;
pub mod refresh_token;
pub mod pat;
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
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await?;
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
        ).await
        .map_err(crate::error::AppError::Database)
    }

    pub async fn mark_authorization_code(
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
        email: &str,
        password_hash: &str,
    ) -> Result<String, crate::error::AppError> {
        let id = uuid::Uuid::new_v4().to_string();
        user::create_user(&self.pool, &id, email, password_hash)
            .await
            .map_err(crate::error::AppError::Database)?;
        Ok(id)
    }

    pub async fn get_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<user::User>, crate::error::AppError> {
        user::get_user_by_email(&self.pool, email)
            .await
            .map_err(crate::error::AppError::Database)
    }
    #[allow(dead_code)]
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

    pub async fn update_user(
        &self,
        id: &str,
        email: Option<&str>,
        tel: Option<&str>,
        username: Option<&str>,
        password_hash: Option<&str>,
        roles: Option<Vec<String>>,
    ) -> Result<(), crate::error::AppError> {
        user::update_user(&self.pool, id, email, tel, username, password_hash, roles)
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
    #[allow(dead_code)]
    pub async fn reset_rate_limit(
        &self,
        key: &str,
    ) -> Result<(), crate::error::AppError> {
        rate_limit::reset_rate_limit(&self.pool, key)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn load_valid_authorization_codes(
        &self,
    ) -> Result<Vec<authorization_code::AuthorizationCode>, crate::error::AppError> {
        authorization_code::load_valid_codes(&self.pool)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn load_valid_tokens(
        &self,
    ) -> Result<Vec<token::AccessToken>, crate::error::AppError> {
        token::load_valid_tokens(&self.pool)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn create_pat(
        &self,
        user_id: &str,
        name: Option<&str>,
        token: &str,
        scopes: Option<Vec<String>>,
        expires_at: Option<i64>,
    ) -> Result<(), crate::error::AppError> {
        pat::create_pat(&self.pool, user_id, name, token, scopes, expires_at)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn get_pats(&self, user_id: &str) -> Result<Vec<pat::Pat>, crate::error::AppError> {
        pat::get_pats(&self.pool, user_id)
            .await
            .map_err(crate::error::AppError::Database)
    }

    pub async fn update_pat(
        &self,
        id: &str,
        user_id: Option<&str>,
        name: Option<&str>,
        token: Option<&str>,
        scopes: Option<Vec<String>>,
        expires_at: Option<i64>,
        last_used_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<(), crate::error::AppError> {
        pat::update_pat(
            &self.pool,
            id,
            user_id,
            name,
            token,
            scopes,
            expires_at,
            last_used_at,
            deleted_at,
        )
        .await
        .map_err(crate::error::AppError::Database)
    }

    pub async fn delete_pat(&self, id: i64) -> Result<u64, crate::error::AppError> {
        let now = chrono::Utc::now().timestamp();
        pat::update_pat(
            &self.pool,
            &id.to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(now),
        )
        .await
        .map_err(crate::error::AppError::Database)?;
        Ok(1)
    }

    pub async fn get_user_by_pat(
        &self,
        pat: &str,
    ) -> Result<Option<user::User>, crate::error::AppError> {
        pat::get_user_by_pat(&self.pool, pat)
            .await
            .map_err(crate::error::AppError::Database)
    }
}
