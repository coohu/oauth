use axum::{
    routing::{delete, get, post},
    middleware as axum_middleware,
    Router,
};

use crate::{
    handlers,
    middleware::admin_auth,
    state::AppState,
};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/admin/client/:id",
            delete(handlers::admin::delete_client)
                .put(handlers::admin::update_client),
        )
        .route("/admin/client", post(handlers::admin::create_client))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            admin_auth,
        ))
        .route("/health", get(handlers::health::health))
        .route("/oauth/token", post(handlers::oauth::issue_token))
        .with_state(state)
}
