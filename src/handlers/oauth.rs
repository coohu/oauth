use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use crate::{error::AppError, state::AppState};

#[derive(Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

pub async fn issue_token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    if req.client_id.is_empty() || req.client_secret.is_empty() {
        return Err(AppError::BadRequest(
            "client_id or client_secret is empty".into(),
        ));
    }
    state.db.verify_client(&req.client_id, &req.client_secret).await?;
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = crate::util::hash_token(&raw_token);
    let expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;
    state.db.issue_token(&token_hash, &req.client_id, expires_at, None).await?;

    let token = raw_token;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "bearer",
        expires_in: state.config.token_ttl_secs,
    }))
}
