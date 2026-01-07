use crate::{config::Config, router::build_router, state::AppState};
use anyhow::Result;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod db;
mod error;
mod handlers;
mod router;
mod state;
mod util;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env();
    let db = db::Database::connect(&config.database_url).await?;
    db.init().await?;

    let state = AppState { config, db };

    let app = build_router(state.clone());

    let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind(state.config.bind).await?;
    info!("Listening on {}", state.config.bind);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    tracing::info!("Shutdown signal received");
}
