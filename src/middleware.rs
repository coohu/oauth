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

pub async fn token_auth(
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

    let token_hash = crate::util::hash_token(token);

    let user_id = if let Some(uid) = state.token_cache.get_user_id_by_access_token(&token_hash).await {
        Some(uid)
    } else {
        match state.db.get_access_token(&token_hash).await {
            Ok(Some((_client_id, user_id))) => {
                if let Some(ref uid) = user_id {
                    let expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;
                    state.token_cache.insert_access_token(token_hash, Some(uid.clone()), expires_at).await;
                }
                user_id
            }
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
    };

    let Some(user_id) = user_id else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let mut req = req;
    req.extensions_mut().insert(user_id);
    Ok(next.run(req).await)
}
