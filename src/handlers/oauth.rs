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
    state
        .db
        .verify_client(&req.client_id, &req.client_secret)
        .await?;

    let token = state
        .db
        .issue_token(&req.client_id, state.config.token_ttl_secs)
        .await?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "bearer",
        expires_in: state.config.token_ttl_secs,
    }))
}
