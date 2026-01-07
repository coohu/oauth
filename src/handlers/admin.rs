use axum::{extract::{Path, State}, Json, http::StatusCode};
use serde::Deserialize;
use crate::{error::AppError, state::AppState};

#[derive(Deserialize)]
pub struct CreateClientReq {
    pub client_id: String,
    pub client_secret: String,
}

pub async fn create_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientReq>,
) -> Result<(), AppError> {
    state
        .db
        .create_client(
            &req.client_id,
            &req.client_secret,
            state.config.bcrypt_cost,
        )
        .await?;

    Ok(())
}

pub async fn delete_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let affected = state
        .db
        .delete_client(&client_id)
        .await?;

    if affected == 0 {
        return Err(AppError::NotFound("client not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}



#[derive(Deserialize)]
pub struct UpdateClientReq {
    pub new_secret: String,
}

pub async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(req): Json<UpdateClientReq>,
) -> Result<(), AppError> {
    let affected = state
        .db
        .update_client_secret(
            &client_id,
            &req.new_secret,
            state.config.bcrypt_cost,
        )
        .await?;

    if affected == 0 {
        return Err(AppError::NotFound("client not found".into()));
    }

    Ok(())
}
