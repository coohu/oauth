use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub bcrypt_cost: u32,
    pub token_ttl_secs: i64,
    pub admin_token: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL is required");

        let bind = std::env::var("BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .expect("Invalid BIND");

        let bcrypt_cost = std::env::var("BCRYPT_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12);

        let token_ttl_secs = std::env::var("TOKEN_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        let admin_token = std::env::var("ADMIN_TOKEN")
            .expect("ADMIN_TOKEN missing");

        Self {
            database_url,
            bind,
            bcrypt_cost,
            token_ttl_secs,
            admin_token,
        }
    }
}
