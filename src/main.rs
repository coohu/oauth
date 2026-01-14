use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::{config::Config, router::build_router, state::AppState};
use tokio::{signal,net::TcpListener};
use anyhow::Result;
use tracing::{error, info, debug};

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
    
    match db.load_valid_authorization_codes().await {
        Ok(codes) => {
            let count = codes.len();
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
            auth_code_cache.load_codes(cached_codes).await;
            info!("Loaded {} valid authorization codes into cache", count);
        }
        Err(e) => {
            error!("Failed to load authorization codes from database: {}", e);
            tracing::warn!("Starting with empty authorization code cache");
        }
    }

    let auth_cache_cleanup = auth_code_cache.clone();
    let token_cache = cache::token_cache::TokenCache::new();

    match db.load_valid_tokens().await {
        Ok(tokens) => {
            let count = tokens.len();
            let cached_tokens: Vec<(String, cache::token_cache::CachedAccessToken)> = tokens
                .into_iter()
                .map(|t| (t.token_hash, cache::token_cache::CachedAccessToken {
                    user_id: t.user_id,
                    expires_at: t.expires_at,
                }))
                .collect();
            token_cache.load_tokens(cached_tokens).await;
            info!("Loaded {} valid access tokens into cache", count);
        }
        Err(e) => {
            error!("Failed to load access tokens from database: {}", e);
            tracing::warn!("Starting with empty access token cache");
        }
    }

    let token_cache_cleanup = token_cache.clone();

    tokio::spawn(async move {
        // 每 2 分钟执行一次
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120)); 
        loop {
            interval.tick().await;
            tokio::join!(
                auth_cache_cleanup.cleanup_expired(),
                token_cache_cleanup.cleanup_expired()
            );
            debug!("Scheduled cleanup task completed");
        }
    });
    let state = AppState { config, db, auth_code_cache, token_cache };
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
