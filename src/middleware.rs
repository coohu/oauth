use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::info;
use crate::state::AppState;

pub async fn admin_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(auth) = req.headers().get("authorization") else {
        info!("authorization header not found!");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let auth = auth.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let Some(token) = auth.strip_prefix("Bearer ") else {
        info!("Bearer prefix not found!");
        return Err(StatusCode::UNAUTHORIZED);
    };

    if token != state.config.admin_token {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}
