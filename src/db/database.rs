use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};

use super::{client, token};

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<(), sqlx::Error> {
        client::init(&self.pool).await?;
        token::init(&self.pool).await?;
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
        client_id: &str,
        ttl: i64,
    ) -> Result<String, crate::error::AppError> {
        token::issue(&self.pool, client_id, ttl).await
    }

    pub async fn create_client(
        &self,
        id: &str,
        secret: &str,
        cost: u32,
    ) -> Result<(), crate::error::AppError> {
        client::create_client(&self.pool, id, secret, cost).await
    }

}
