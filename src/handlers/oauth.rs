use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use axum_extra::extract::CookieJar; 
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use crate::{oauth_error::OAuthError, state::AppState, util};

#[derive(Deserialize, Serialize)] 
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

pub async fn authorize(
    jar: CookieJar, 
    Query(params): Query<AuthorizationRequest>,
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let user_id = match jar.get("user_id").map(|c| c.value().to_string()) {
        Some(uid) => uid,
        None => {
            let current_query = serde_urlencoded::to_string(&params)
                .map_err(|_| OAuthError::ServerError.into_response())?;
            let return_to = format!("/oauth/authorize?{}", current_query);
            let login_url = format!("/login?return_to={}", urlencoding::encode(&return_to));
            return Ok(Redirect::to(&login_url).into_response());
        }
    };

    if params.response_type != "code" {
        return Err(OAuthError::UnsupportedResponseType
            .to_redirect(&params.redirect_uri, params.state.as_deref()));
    }

    if params.code_challenge.is_empty() {
        return Err(OAuthError::InvalidRequest("code_challenge is required".to_string())
            .to_redirect(&params.redirect_uri, params.state.as_deref()));
    }

    if params.code_challenge_method != "S256" && params.code_challenge_method != "plain" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be S256 or plain".to_string()
        ).to_redirect(&params.redirect_uri, params.state.as_deref()));
    }
    
    let _client = state.db.get_client(&params.client_id).await
        .map_err(|_| OAuthError::ServerError.into_response())? 
        .ok_or_else(|| OAuthError::InvalidClient.into_response())?;

    let redirect_valid = state.db.validate_redirect_uri(&params.client_id, &params.redirect_uri).await
        .map_err(|_| OAuthError::ServerError.into_response())?;
        
    if !redirect_valid {
        return Err(OAuthError::InvalidRequest("Invalid redirect_uri".to_string()).into_response());
    }
    
    let scope = params.scope.as_deref().unwrap_or("default");
    let scope_valid = state.db.validate_scope(&params.client_id, scope).await
        .map_err(|_| OAuthError::ServerError
        .to_redirect(&params.redirect_uri, params.state.as_deref()))?;
    
    if !scope_valid {
        return Err(
            OAuthError::InvalidScope.to_redirect(&params.redirect_uri, params.state.as_deref())
        );
    }

    let code = util::generate_secure_token(32);
    let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes
    let cached_code = crate::cache::authorization_code_cache::CachedAuthorizationCode {
        code: code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        user_id: user_id.clone(),
        scope: scope.to_string(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        expires_at,
    };
    state.auth_code_cache.insert(cached_code).await;

    let db = state.db.clone();
    let code_for_db = code.clone();
    let client_id_for_db = params.client_id.clone();
    let redirect_uri_for_db = params.redirect_uri.clone();
    let user_id_for_db = user_id.clone();
    let scope_for_db = scope.to_string();
    let challenge_for_db = params.code_challenge.clone();
    let challenge_method_for_db = params.code_challenge_method.clone();
    
    tokio::spawn(async move {
        if let Err(e) = db.create_authorization_code(
            &code_for_db,
            &client_id_for_db,
            &redirect_uri_for_db,
            &user_id_for_db,
            &scope_for_db,
            &challenge_for_db,
            &challenge_method_for_db,
            expires_at,
        ).await {
            error!("Failed to save authorization code to database: {}", e);
        }
    });

    let mut redirect_url = params.redirect_uri.clone();
    redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
    redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
    if let Some(state_param) = params.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state_param)));
    }
    Ok(Redirect::to(&redirect_url).into_response())
}

#[derive(Deserialize, Debug)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub async fn token(State(state): State<AppState>, Form(req): Form<TokenRequest>) 
    -> Result<Json<TokenResponse>, OAuthError> {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, req).await,
        "refresh_token" => handle_refresh_token_grant(state, req).await,
        "client_credentials" => handle_client_credentials_grant(state, req).await,
        _ => Err(OAuthError::UnsupportedGrantType),
    }
}

async fn handle_authorization_code_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let code = req.code.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code is required".to_string()))?;
    let redirect_uri = req.redirect_uri.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri is required".to_string()))?;
    let code_verifier = req.code_verifier.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code_verifier is required".to_string()))?;

    let auth_code = state.auth_code_cache.get_and_remove(code).await
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired authorization code".to_string()))?;

    if auth_code.client_id != req.client_id {
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }
    if &auth_code.redirect_uri != redirect_uri {
        return Err(OAuthError::InvalidGrant("redirect_uri mismatch".to_string()));
    }
    if !util::verify_pkce(code_verifier, &auth_code.code_challenge, &auth_code.code_challenge_method) {
        return Err(OAuthError::InvalidGrant("Invalid code_verifier".to_string()));
    }

    let _client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref())
        .await.map_err(|_| OAuthError::InvalidClient)?;
    
    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let access_expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;
    
    let refresh_token = util::generate_secure_token(32);
    let refresh_token_hash = util::hash_token(&refresh_token);
    let refresh_expires_at = chrono::Utc::now().timestamp() + (30 * 24 * 3600);

    state.token_cache.insert_access_token(
        access_token_hash.clone(), 
        Some(auth_code.user_id.clone()), 
        access_expires_at
    ).await;

    let db = state.db.clone();
    let client_id = req.client_id.clone();
    let user_id = auth_code.user_id.clone();
    let scope = auth_code.scope.clone();
    let access_token_hash_db = access_token_hash.clone();
    let refresh_token_hash_db = refresh_token_hash.clone();
    let coderef = code.clone();
    
    tokio::spawn(async move {
        if let Err(e) = db.issue_token(
            &access_token_hash_db,
            &client_id,
            access_expires_at,
            Some(&user_id),
        ).await {
            error!("Database error occurred while issue_token: {}", e);
        }
        
        if let Err(e) = db.create_refresh_token(
            &refresh_token_hash_db,
            &client_id,
            &user_id,
            &scope,
            refresh_expires_at,
        ).await {
            error!("Database error occurred while create_refresh_token: {}", e);
        }

        if let Err(e) = db.mark_authorization_code(&coderef).await {
            error!("Failed to mark authorization code as used in database: {}", e);
        }
    });
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.token_ttl_secs,
        refresh_token: Some(refresh_token),
        scope: Some(auth_code.scope),
    }))
}

async fn handle_refresh_token_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let old_refresh_token_str = req.refresh_token.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

    let _client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref()).await
        .map_err(|_| OAuthError::InvalidClient)?;

    let old_refresh_token_hash = util::hash_token(old_refresh_token_str);
    
    let refresh_token_info = state.db.get_refresh_token(&old_refresh_token_hash).await
        .map_err(|_| OAuthError::ServerError)?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired refresh token".to_string()))?;

    if refresh_token_info.client_id != req.client_id {
        // 安全警告：可能是令牌被窃取后在错误的客户端使用，建议记录安全审计日志
        warn!("Refresh token client mismatch. Expected: {}, Got: {}", refresh_token_info.client_id, req.client_id);
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }

    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let access_expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;

    let new_refresh_token = util::generate_secure_token(32);
    let new_refresh_token_hash = util::hash_token(&new_refresh_token);
    let refresh_expires_at = chrono::Utc::now().timestamp() + (30 * 24 * 3600);

    state.db.revoke_refresh_token(&old_refresh_token_hash).await
        .map_err(|e| {
            error!("Failed to revoke old refresh token: {}", e);
            OAuthError::ServerError
        })?;

    state.db.issue_token(
        &access_token_hash,
        &req.client_id,
        access_expires_at,
        Some(&refresh_token_info.user_id),
    ).await.map_err(|e| {
        error!("Failed to issue access token: {}", e);
        OAuthError::ServerError
    })?;

    state.db.create_refresh_token(
        &new_refresh_token_hash,
        &req.client_id,
        &refresh_token_info.user_id,
        &refresh_token_info.scope,
        refresh_expires_at,
    ).await.map_err(|e| {
        error!("Failed to create new refresh token: {}", e);
        OAuthError::ServerError
    })?;

    state.token_cache.insert_access_token(
        access_token_hash, 
        Some(refresh_token_info.user_id.clone()), 
        access_expires_at
    ).await;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.token_ttl_secs,
        refresh_token: Some(new_refresh_token), 
        scope: Some(refresh_token_info.scope),
    }))
}

async fn handle_client_credentials_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref())
        .await.map_err(|_| OAuthError::InvalidClient)?;

    if client_type != "confidential" {
        return Err(OAuthError::UnauthorizedClient);
    }

    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;

    state.db.issue_token(&access_token_hash, &req.client_id, expires_at, None)
        .await
        .map_err(|e| {
            error!("Database error issue_token: {}", e);
            OAuthError::ServerError
        })?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.token_ttl_secs,
        refresh_token: None,
        scope: None,
    }))
}
