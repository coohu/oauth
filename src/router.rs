use axum::{
    routing::{delete, get, post},
    middleware as axum_middleware,
    Router,
};
use hyper::Method;
use tower_http::cors::{Any, CorsLayer};
use crate::{ handlers, middleware, state::AppState};

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any) 
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);

    Router::new()
        .route("/admin/client/:id",
            delete(handlers::admin::delete_client)
            .put(handlers::admin::update_client),
        )
        .route("/admin/client", post(handlers::admin::create_client))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_auth,
        ))
        .route("/health", get(handlers::health::health))
        .route("/oauth/authorize", get(handlers::oauth::authorize))
        .route("/oauth/token", post(handlers::oauth::token))
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .nest("/auth",
            Router::new()
                .route("/pats", get(handlers::auth::pats))
                .route("/pat", post(handlers::auth::create_pat))
                .route("/pat/:id",
                    post(handlers::auth::update_pat)
                    .delete(handlers::auth::delete_pat),
                )
                .route("/user", get(handlers::auth::user))
                .route("/user/:id", post(handlers::auth::update_user))
                .layer(axum_middleware::from_fn_with_state(
                    state.clone(),
                    middleware::token_auth,
                )),
        )
        .route("/auth/pat_auth", post(handlers::auth::auth_pat))
        .layer(cors)
        .with_state(state)
}
