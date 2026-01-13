use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::{config::Config, router::build_router, state::AppState};
use tokio::{signal,net::TcpListener};
use anyhow::Result;
use tracing::info;

mod cache;
mod middleware;
mod config;
mod db;
mod error;
mod oauth_error;
mod handlers;
mod router;
mod state;
mod util;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db = db::Database::connect(&config.database_url).await?;
    db.init().await?;
    let auth_code_cache = cache::authorization_code_cache::AuthorizationCodeCache::new();
    
    // Load valid authorization codes from database into cache
    match db.load_valid_authorization_codes().await {
        Ok(codes) => {
            let cached_codes: Vec<cache::authorization_code_cache::CachedAuthorizationCode> = codes
                .into_iter()
                .map(|code| cache::authorization_code_cache::CachedAuthorizationCode {
                    code: code.code,
                    client_id: code.client_id,
                    redirect_uri: code.redirect_uri,
                    user_id: code.user_id,
                    scope: code.scope,
                    code_challenge: code.code_challenge,
                    code_challenge_method: code.code_challenge_method,
                    expires_at: code.expires_at,
                })
                .collect();
            let count = cached_codes.len();
            auth_code_cache.load_codes(cached_codes).await;
            info!("Loaded {} valid authorization codes into cache", count);
        }
        Err(e) => {
            tracing::error!("Failed to load authorization codes from database: {}", e);
            tracing::warn!("Starting with empty authorization code cache");
        }
    }

    // Start background task to cleanup expired codes every 60 seconds
    let cache_cleanup = auth_code_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cache_cleanup.cleanup_expired().await;
        }
    });

    let state = AppState { config, db, auth_code_cache };
    let app = build_router(state.clone());

    let listener = TcpListener::bind(state.config.bind).await?;
    info!("Listening on {}", state.config.bind);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = signal::ctrl_c().await;
            tracing::info!("Shutdown signal received");
        })
        .await?;
    Ok(())
}
