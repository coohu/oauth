use axum::{extract::{State}, Json };
use serde::{Deserialize, Serialize};
use crate::{error::AppError, state::AppState};
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub captcha: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub email: String,
}

pub async fn register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let password_len = payload.password.chars().count();
    if !crate::util::is_valid_email(&payload.email) {
        return Err(AppError::BadRequest("Invalid email format".into()));
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
        // Reset rate limit after successful CAPTCHA
        // state.db.reset_rate_limit(&rate_limit_key).await?;
    }

    let password_hash = hash(payload.password, DEFAULT_COST)
        .map_err(|_| AppError::Internal)?;

    let id = state.db.create_user(&payload.email, &password_hash).await?;
    Ok(Json(RegisterResponse {
        id,
        email: payload.email,
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
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

    let user = state.db.get_user_by_email(&payload.email).await?
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

#[derive(Serialize, Deserialize)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub roles: Option<Vec<String>>,
    pub tel: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub tel: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub roles: Option<Vec<String>>,
}

use base64::{engine::general_purpose, Engine as _};
pub async fn me(
    State(state): State<AppState>,
    headers:axum::http::HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<MeResponse>), AppError> {
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let token_hash = crate::util::hash_token(auth_header);

    let user_id = if let Some(uid) = state.token_cache.get_user_id_by_access_token(&token_hash).await {
        uid
    } else {
        let (_client_id, user_id) = state.db.get_access_token(&token_hash).await?
            .ok_or(AppError::Unauthorized)?;
        let user_id = user_id.ok_or(AppError::Unauthorized)?;

        let expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;
        state.token_cache.insert_access_token(token_hash, Some(user_id.clone()), expires_at).await;
        user_id
    };

    let user = state.db.get_user_by_id(&user_id).await?
        .ok_or(AppError::Unauthorized)?;

    let response_data = MeResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        roles: user.roles,
        tel: user.tel,
    };
    let mpack_bytes = rmp_serde::to_vec(&response_data).map_err(|_| AppError::Internal)?;
    let b64_str = general_purpose::URL_SAFE_NO_PAD.encode(mpack_bytes);

    let mut headers = axum::http::HeaderMap::new();
    let header_value = axum::http::HeaderValue::from_str(&b64_str)
        .map_err(|_| AppError::Internal)?;
    headers.insert("X-User-Data-Base64", header_value); 
    Ok((headers, Json(response_data)))
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(target_user_id): axum::extract::Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<()>, AppError> {
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let token_hash = crate::util::hash_token(auth_header);

    // Get current user ID from cache or DB
    let current_user_id = if let Some(uid) = state.token_cache.get_user_id_by_access_token(&token_hash).await {
        uid
    } else {
        let (_client_id, user_id) = state.db.get_access_token(&token_hash).await?
            .ok_or(AppError::Unauthorized)?;
        user_id.ok_or(AppError::Unauthorized)?
    };

    let current_user = state.db.get_user_by_id(&current_user_id).await?
        .ok_or(AppError::Unauthorized)?;

    let is_admin = current_user.roles.as_ref()
        .map(|r| r.contains(&"admin".to_string()))
        .unwrap_or(false);

    let is_self = current_user_id == target_user_id;

    if !is_admin && !is_self {
        return Err(AppError::Forbidden);
    }

    // Only admin can update roles
    if payload.roles.is_some() && !is_admin {
        return Err(AppError::Forbidden);
    }

    let password_hash = if let Some(p) = payload.password {
        if p.chars().count() < 6 {
            return Err(AppError::BadRequest("Password must be at least 6 characters long".into()));
        }
        Some(hash(p, DEFAULT_COST).map_err(|_| AppError::Internal)?)
    } else {
        None
    };

    state.db.update_user(
        &target_user_id,
        payload.email.as_deref(),
        payload.tel.as_deref(),
        payload.username.as_deref(),
        password_hash.as_deref(),
        payload.roles,
    ).await?;

    Ok(Json(()))
}

// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
// use serde::Deserialize;

// #[derive(Deserialize, Debug)]
// pub struct MeResponse {
//     pub id: String,
//     pub username: String,
// }

// fn decode_user_data(header_value: &str) -> Result<MeResponse, Box<dyn std::error::Error>> {
//     // 1. Base64URL 解码
//     let decoded_bytes = URL_SAFE_NO_PAD.decode(header_value)?;

//     // 2. MessagePack 反序列化
//     let user_data: MeResponse = rmp_serde::from_slice(&decoded_bytes)?;

//     Ok(user_data)
// }

// // 在 Axum 中间件或处理函数中使用
// async fn business_handler(headers: axum::http::HeaderMap) {
//     if let Some(user_data_b64) = headers.get("X-User-Data-Base64").and_then(|h| h.to_str().ok()) {
//         match decode_user_data(user_data_b64) {
//             Ok(user) => println!("当前用户 ID: {}, 用户名: {}", user.id, user.username),
//             Err(e) => eprintln!("解码失败: {}", e),
//         }
//     }
// }
