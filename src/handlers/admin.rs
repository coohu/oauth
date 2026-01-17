use axum::{extract::{Path, State}, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use crate::{error::AppError, state::AppState};
use tracing::info;

#[derive(Deserialize)]
pub struct CreateClientReq {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_type: String, // "public" or "confidential"
    pub redirect_uris: String,
    pub allowed_scopes: String, 
}

#[derive(Serialize)]
pub struct CreateClientResp {
    pub client_id: String,
    pub client_type: String,
}

pub async fn create_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientReq>,
) -> Result<Json<CreateClientResp>, AppError> {
    if req.client_type != "public" && req.client_type != "confidential" {
        return Err(AppError::BadRequest("client_type must be 'public' or 'confidential'".into()));
    }

    if req.client_type == "confidential" && req.client_secret.is_none() {
        return Err(AppError::BadRequest("confidential clients must have a client_secret".into()));
    }

    if req.client_type == "public" && req.client_secret.is_some() {
        return Err(AppError::BadRequest("public clients must not have a client_secret".into()));
    }
    info!("client_id :{}", &req.client_id);
    state.db.create_client(
        &req.client_id,
        req.client_secret.as_deref(),
        &req.client_type,
        &req.redirect_uris,
        &req.allowed_scopes,
        state.config.bcrypt_cost,
    ).await?;

    Ok(Json(CreateClientResp {
        client_id: req.client_id,
        client_type: req.client_type,
    }))
}

pub async fn delete_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let affected = state.db
        .delete_client(&client_id)
        .await?;

    if affected == 0 {
        return Err(AppError::NotFound("client not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct UpdateClientReq {
    pub new_secret: Option<String>,
}

pub async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(req): Json<UpdateClientReq>,
) -> Result<(), AppError> {
    let affected = state.db
        .update_client_secret(&client_id, req.new_secret.as_deref(), state.config.bcrypt_cost)
        .await?;

    if affected == 0 {
        return Err(AppError::NotFound("client not found".into()));
    }

    Ok(())
}
