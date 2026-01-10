use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::{config::Config, router::build_router, state::AppState};
use tokio::{signal,net::TcpListener};
use anyhow::Result;
use tracing::info;

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

    let state = AppState { config, db };
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
