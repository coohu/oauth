use axum::{
    http::StatusCode,
    response::{IntoResponse, Response, Redirect},
    Json,
};
use serde_json::json;

/// OAuth 2.1 Error Codes as per RFC 6749
#[derive(Debug)]
pub enum OAuthError {
    /// The request is missing a required parameter, includes an invalid parameter value,
    /// includes a parameter more than once, or is otherwise malformed.
    InvalidRequest(String),
    
    /// Client authentication failed (e.g., unknown client, no client authentication included,
    /// or unsupported authentication method).
    InvalidClient,
    
    /// The provided authorization grant (e.g., authorization code, resource owner credentials)
    /// or refresh token is invalid, expired, revoked, does not match the redirection URI used
    /// in the authorization request, or was issued to another client.
    InvalidGrant(String),
    
    /// The authenticated client is not authorized to use this authorization grant type.
    UnauthorizedClient,
    
    /// The authorization grant type is not supported by the authorization server.
    UnsupportedGrantType,
    
    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,
    
    /// The resource owner or authorization server denied the request.
    #[allow(dead_code)]
    AccessDenied,
    
    /// The authorization server does not support obtaining an authorization code using this method.
    UnsupportedResponseType,
    
    /// The authorization server encountered an unexpected condition that prevented it from
    /// fulfilling the request.
    ServerError,
    
    /// The authorization server is currently unable to handle the request due to a temporary
    /// overloading or maintenance of the server.
    #[allow(dead_code)]
    TemporarilyUnavailable,
}

impl OAuthError {
    pub fn error_code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidClient => "invalid_client",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::UnauthorizedClient => "unauthorized_client",
            OAuthError::UnsupportedGrantType => "unsupported_grant_type",
            OAuthError::InvalidScope => "invalid_scope",
            OAuthError::AccessDenied => "access_denied",
            OAuthError::UnsupportedResponseType => "unsupported_response_type",
            OAuthError::ServerError => "server_error",
            OAuthError::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    pub fn description(&self) -> String {
        match self {
            OAuthError::InvalidRequest(msg) => msg.clone(),
            OAuthError::InvalidGrant(msg) => msg.clone(),
            OAuthError::InvalidClient => "Client authentication failed".to_string(),
            OAuthError::UnauthorizedClient => "Client not authorized for this grant type".to_string(),
            OAuthError::UnsupportedGrantType => "Grant type not supported".to_string(),
            OAuthError::InvalidScope => "Invalid or unknown scope".to_string(),
            OAuthError::AccessDenied => "Access denied".to_string(),
            OAuthError::UnsupportedResponseType => "Response type not supported".to_string(),
            OAuthError::ServerError => "Internal server error".to_string(),
            OAuthError::TemporarilyUnavailable => "Service temporarily unavailable".to_string(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            OAuthError::InvalidClient => StatusCode::UNAUTHORIZED,
            OAuthError::InvalidRequest(_) |
            OAuthError::InvalidGrant(_) |
            OAuthError::UnauthorizedClient |
            OAuthError::UnsupportedGrantType |
            OAuthError::InvalidScope |
            OAuthError::UnsupportedResponseType => StatusCode::BAD_REQUEST,
            OAuthError::AccessDenied => StatusCode::FORBIDDEN,
            OAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthError::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Create a redirect response with error for authorization endpoint
    pub fn to_redirect(&self, redirect_uri: &str, state: Option<&str>) -> Response {
        let mut url = redirect_uri.to_string();
        url.push_str(if redirect_uri.contains('?') { "&" } else { "?" });
        url.push_str(&format!("error={}", self.error_code()));
        url.push_str(&format!("&error_description={}", urlencoding::encode(&self.description())));
        if let Some(state) = state {
            url.push_str(&format!("&state={}", urlencoding::encode(state)));
        }
        Redirect::to(&url).into_response()
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = json!({
            "error": self.error_code(),
            "error_description": self.description(),
        });
        let mut response = (status, Json(body)).into_response();
        // Add WWW-Authenticate header for 401 responses
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer".parse().unwrap(),
            );
        }
        response
    }
}
