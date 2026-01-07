use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

pub async fn admin_auth<B>(
    state: AppState,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let Some(auth) = req.headers().get("authorization") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let auth = auth.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if token != state.config.admin_token {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}
