use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use crate::{error::AppError, state::AppState};
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub captcha: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub username: String,
}

pub async fn register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let username_len = payload.username.chars().count();
    let password_len = payload.password.chars().count();

    if username_len < 4 {
        return Err(AppError::BadRequest("Username must be at least 4 characters long".into()));
    }
    if password_len < 6 {
        return Err(AppError::BadRequest("Password must be at least 6 characters long".into()));
    }
    let ip = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    let rate_limit_key = format!("register:{}", ip);

    // Limit to 5 registrations per hour per IP
    let allowed = state.db.check_rate_limit(&rate_limit_key, 5, 3600).await?;
    if !allowed {
        let captcha_token = payload.captcha.as_deref()
            .ok_or_else(|| AppError::BadRequest("CAPTCHA required due to high frequency".into()))?;
        
        let valid = crate::util::verify_turnstile(&state.config.cf_secret_key, captcha_token, Some(ip))
            .await
            .map_err(|_| AppError::Internal)?;
            
        if !valid {
            return Err(AppError::BadRequest("Invalid CAPTCHA".into()));
        }
    }

    let password_hash = hash(payload.password, DEFAULT_COST)
        .map_err(|_| AppError::Internal)?;

    let id = state.db.create_user(&payload.username, &password_hash).await?;
    Ok(Json(RegisterResponse {id,username: payload.username}))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub captcha: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let ip = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    let rate_limit_key = format!("login:{}", ip);

    // Limit to 10 logins per minute per IP
    let allowed = state.db.check_rate_limit(&rate_limit_key, 10, 60).await?;
    if !allowed {
        let captcha_token = payload.captcha.as_deref()
            .ok_or_else(|| AppError::BadRequest("CAPTCHA required due to high frequency".into()))?;
        
        let valid = crate::util::verify_turnstile(&state.config.cf_secret_key, captcha_token, Some(ip))
            .await
            .map_err(|_| AppError::Internal)?;
            
        if !valid {
            return Err(AppError::BadRequest("Invalid CAPTCHA".into()));
        }
    }

    let user = state.db.get_user_by_username(&payload.username).await?
        .ok_or_else(|| AppError::Unauthorized)?;

    let valid = verify(payload.password, &user.password_hash)
        .map_err(|_| AppError::Internal)?;

    if !valid {
        return Err(AppError::Unauthorized);
    }

    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = crate::util::hash_token(&raw_token);
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    
    state.db.issue_token(&token_hash, "user_login", expires_at, Some(&user.id)).await?;

    Ok(Json(LoginResponse {
        token: raw_token,
    }))
}

#[derive(Serialize)]
pub struct MeResponse {
    pub id: String,
    pub username: String,
}

pub async fn me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MeResponse>, AppError> {
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let token_hash = crate::util::hash_token(auth_header);
    let (_client_id, user_id) = state.db.get_access_token(&token_hash).await?
        .ok_or(AppError::Unauthorized)?;

    let user_id = user_id.ok_or(AppError::Unauthorized)?;
    let user = state.db.get_user_by_id(&user_id).await?
        .ok_or(AppError::Unauthorized)?;

    Ok(Json(MeResponse {
        id: user.id,
        username: user.username,
    }))
}
