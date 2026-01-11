use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};
use tracing::{ error};
use crate::{oauth_error::OAuthError, state::AppState, util};

#[derive(Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    // In a real implementation, you'd need user authentication/consent here
    // For now, we'll assume the user_id is provided (in production, get from session)
    pub user_id: String,
}

pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Result<Response, Response> {
    // Validate response_type (OAuth 2.1 only supports 'code')
    if params.response_type != "code" {
        return Err(OAuthError::UnsupportedResponseType
            .to_redirect(&params.redirect_uri, params.state.as_deref()));
    }

    // Validate PKCE parameters (REQUIRED in OAuth 2.1)
    if params.code_challenge.is_empty() {
        return Err(OAuthError::InvalidRequest("code_challenge is required".to_string())
            .to_redirect(&params.redirect_uri, params.state.as_deref()));
    }

    // Only S256 is recommended in OAuth 2.1, but we support plain for compatibility
    if params.code_challenge_method != "S256" && params.code_challenge_method != "plain" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be S256 or plain".to_string()
        ).to_redirect(&params.redirect_uri, params.state.as_deref()));
    }
    
    let _client = state.db.get_client(&params.client_id).await
        .map_err(|_| OAuthError::ServerError.into_response())? // 数据库异常返回 Body
        .ok_or_else(|| OAuthError::InvalidClient.into_response())?; // ClientID 不存在返回 Body

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
        return Err(OAuthError::InvalidScope
            .to_redirect(&params.redirect_uri, params.state.as_deref()));
    }

    // Generate authorization code
    let code = util::generate_secure_token(32);
    let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes

    state.db.create_authorization_code(
        &code,
        &params.client_id,
        &params.redirect_uri,
        &params.user_id,
        scope,
        &params.code_challenge,
        &params.code_challenge_method,
        expires_at,
    ).await
    .inspect_err(|e| {
        error!("Database error occurred while creating auth code: {}", e);
    })
    .map_err(|_| OAuthError::ServerError
    .to_redirect(&params.redirect_uri, params.state.as_deref()))?;

    // Build redirect URL with authorization code
    let mut redirect_url = params.redirect_uri.clone();
    redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
    redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
    if let Some(state_param) = params.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state_param)));
    }
    Ok(Redirect::to(&redirect_url).into_response())
}

#[derive(Deserialize,Debug)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    
    // For authorization_code grant
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    
    // For refresh_token grant
    pub refresh_token: Option<String>,
    
    // For client_credentials grant (legacy, kept for compatibility)
    // OAuth 2.1 recommends against this for public clients
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

pub async fn token(State(state): State<AppState>,Form(req): Form<TokenRequest>) 
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
    // Validate required parameters
    let code = req.code.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code is required".to_string()))?;
    let redirect_uri = req.redirect_uri.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri is required".to_string()))?;
    let code_verifier = req.code_verifier.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code_verifier is required (PKCE)".to_string()))?;
    // info!("-------------------{:?}", req);
    // Retrieve and mark authorization code as used
    let auth_code = state.db.get_and_mark_authorization_code_used(code).await
        .inspect_err(|e|{error!("get_and_mark_authorization_code_used {}",e)})
        .map_err(|_| OAuthError::ServerError)?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired authorization code".to_string()))?;

    // Verify client_id matches
    if auth_code.client_id != req.client_id {
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }

    // Verify redirect_uri matches
    if &auth_code.redirect_uri != redirect_uri {
        return Err(OAuthError::InvalidGrant("redirect_uri mismatch".to_string()));
    }

    // Verify PKCE code_verifier
    if !util::verify_pkce(code_verifier, &auth_code.code_challenge, &auth_code.code_challenge_method) {
        return Err(OAuthError::InvalidGrant("Invalid code_verifier".to_string()));
    }

    // Authenticate client (public clients don't need secret)
    let _client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref()).await
        .map_err(|_| OAuthError::InvalidClient)?;
    
    // Generate access token
    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let access_expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;

    
    state.db.issue_token(
        &access_token_hash,
        &req.client_id,
        access_expires_at,
        Some(&auth_code.user_id),
    ).await.inspect_err(|e|{
        error!("Database error occurred while issue_token: {}", e);
    })
    .map_err(|_| OAuthError::ServerError)?;

    // Generate refresh token
    let refresh_token = util::generate_secure_token(32);
    let refresh_token_hash = util::hash_token(&refresh_token);
    let refresh_expires_at = chrono::Utc::now().timestamp() + (30 * 24 * 3600); // 30 days

    state.db.create_refresh_token(
        &refresh_token_hash,
        &req.client_id,
        &auth_code.user_id,
        &auth_code.scope,
        refresh_expires_at,
    ).await.inspect_err(|e|{
        error!("Database error occurred while create_refresh_token: {}", e);
    }).map_err(|_| OAuthError::ServerError)?;

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
    // Validate required parameters
    let refresh_token_str = req.refresh_token.as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

    // Authenticate client
    let _client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref()).await
        .map_err(|_| OAuthError::InvalidClient)?;

    // Verify refresh token
    let refresh_token_hash = util::hash_token(refresh_token_str);
    let refresh_token = state.db.get_refresh_token(&refresh_token_hash).await
        .map_err(|_| OAuthError::ServerError)?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired refresh token".to_string()))?;

    // Verify client_id matches
    if refresh_token.client_id != req.client_id {
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }

    // Generate new access token
    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let access_expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;

    state.db.issue_token(
        &access_token_hash,
        &req.client_id,
        access_expires_at,
        Some(&refresh_token.user_id),
    ).await.map_err(|_| OAuthError::ServerError)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.token_ttl_secs,
        refresh_token: None, // Refresh token rotation could be implemented here
        scope: Some(refresh_token.scope),
    }))
}

async fn handle_client_credentials_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    // OAuth 2.1 discourages client_credentials for public clients
    // This is kept for backward compatibility with confidential clients only
    
    // Authenticate client (must be confidential)
    let client_type = state.db.verify_client(&req.client_id, req.client_secret.as_deref())
        .await.map_err(|_| OAuthError::InvalidClient)?;

    if client_type != "confidential" {
        return Err(OAuthError::UnauthorizedClient);
    }

    // Generate access token (no user context)
    let access_token = util::generate_secure_token(32);
    let access_token_hash = util::hash_token(&access_token);
    let expires_at = chrono::Utc::now().timestamp() + state.config.token_ttl_secs;

    state.db.issue_token(&access_token_hash, &req.client_id, expires_at, None)
        .await.map_err(|_| OAuthError::ServerError)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.token_ttl_secs,
        refresh_token: None,
        scope: None,
    }))
}
