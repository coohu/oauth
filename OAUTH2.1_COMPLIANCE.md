# OAuth 2.1 Compliance Documentation

This document outlines how this OAuth server implementation complies with the OAuth 2.1 specification.

## Overview

This implementation has been refactored to fully comply with OAuth 2.1 standards, which is a consolidation and simplification of OAuth 2.0 with current best practices.

## Key OAuth 2.1 Features Implemented

### 1. ✅ PKCE (Proof Key for Code Exchange) - REQUIRED

**Standard**: RFC 7636, made mandatory in OAuth 2.1

- **Implementation**: All authorization code flows MUST include PKCE parameters
- **Code Challenge Methods**:
  - `S256` (SHA-256, recommended)
  - `plain` (for compatibility, but S256 is preferred)
- **Validation**: Server verifies `code_verifier` against stored `code_challenge`

**Files**:
- `src/util.rs`: `verify_pkce()` function
- `src/handlers/oauth.rs`: Authorization and token endpoints enforce PKCE
- `src/db/authorization_code.rs`: Stores code_challenge and method

### 2. ✅ Authorization Code Flow with Refresh Tokens

**Standard**: Primary grant type in OAuth 2.1

- **Authorization Endpoint**: `/oauth/authorize` (GET)
  - Validates client, redirect_uri, scope
  - Requires PKCE parameters
  - Generates short-lived authorization code (10 minutes)

- **Token Endpoint**: `/oauth/token` (POST)
  - Exchange authorization code for tokens
  - Returns access_token and refresh_token
  - One-time use authorization codes

**Files**:
- `src/handlers/oauth.rs`: Full authorization code flow implementation
- `src/db/authorization_code.rs`: Authorization code storage with expiry
- `src/db/refresh_token.rs`: Refresh token management

### 3. ✅ Public and Confidential Clients

**Standard**: OAuth 2.1 differentiates client types

- **Public Clients**:
  - No client_secret (e.g., mobile apps, SPAs)
  - MUST use PKCE
  - Cannot use client_credentials grant

- **Confidential Clients**:
  - Have client_secret (e.g., server-side apps)
  - MUST authenticate with secret
  - Can use client_credentials grant

**Files**:
- `src/db/client.rs`: Client type validation in `verify_client()`
- `src/handlers/admin.rs`: Client creation enforces type rules
- `src/handlers/oauth.rs`: Grant type restrictions per client type

### 4. ✅ Redirect URI Validation

**Standard**: Strict redirect_uri validation required

- Pre-registered redirect URIs per client
- Exact match validation (no wildcards)
- Invalid redirect_uri errors don't redirect

**Files**:
- `src/db/client.rs`: `validate_redirect_uri()` function
- `src/handlers/oauth.rs`: Validation in authorization flow

### 5. ✅ Scope Validation

**Standard**: Scope-based authorization

- Clients have allowed_scopes
- Requested scopes must be subset of allowed
- Scopes stored with tokens for validation

**Files**:
- `src/db/client.rs`: `validate_scope()` function
- `src/handlers/oauth.rs`: Scope validation and storage

### 6. ✅ Proper Error Responses

**Standard**: RFC 6749 error codes

Implemented error types:
- `invalid_request`: Malformed requests
- `invalid_client`: Client authentication failed
- `invalid_grant`: Invalid authorization code/refresh token
- `unauthorized_client`: Client not authorized for grant type
- `unsupported_grant_type`: Grant type not supported
- `invalid_scope`: Invalid scope requested
- `access_denied`: Authorization denied
- `unsupported_response_type`: Response type not supported
- `server_error`: Internal server error
- `temporarily_unavailable`: Service unavailable

**Files**:
- `src/oauth_error.rs`: Complete OAuth error implementation
- Returns proper HTTP status codes
- Includes WWW-Authenticate header for 401s
- Redirect errors for authorization endpoint

### 7. ✅ Token Security

**Standard**: Best practices for token generation and storage

- Cryptographically secure random token generation
- Tokens hashed (SHA-256) before storage
- Short-lived access tokens (configurable TTL)
- Long-lived refresh tokens (30 days)
- One-time use authorization codes
- Token expiration validation

**Files**:
- `src/util.rs`: `generate_secure_token()`, `hash_token()`
- `src/db/token.rs`: Access token storage with expiry
- `src/db/refresh_token.rs`: Refresh token with revocation support

### 8. ✅ Grant Types Supported

#### Authorization Code Grant (with PKCE)
```
POST /oauth/token
grant_type=authorization_code
&code={authorization_code}
&redirect_uri={redirect_uri}
&client_id={client_id}
&code_verifier={verifier}
```

#### Refresh Token Grant
```
POST /oauth/token
grant_type=refresh_token
&refresh_token={refresh_token}
&client_id={client_id}
&client_secret={secret} (for confidential clients)
```

#### Client Credentials Grant (Confidential clients only)
```
POST /oauth/token
grant_type=client_credentials
&client_id={client_id}
&client_secret={secret}
```

**Files**:
- `src/handlers/oauth.rs`: All grant type handlers

### 9. ⚠️ Removed/Deprecated Features

OAuth 2.1 removes several features from OAuth 2.0:

- ❌ **Implicit Grant**: Removed (security concerns)
- ❌ **Resource Owner Password Credentials**: Removed (security concerns)
- ❌ **Bearer Token in Query Parameters**: Not recommended

## Database Schema

### oauth_client
```sql
CREATE TABLE oauth_client (
    id TEXT PRIMARY KEY,
    secret_hash TEXT,                 -- NULL for public clients
    client_type TEXT NOT NULL,        -- 'public' or 'confidential'
    redirect_uris TEXT NOT NULL,      -- comma-separated
    allowed_scopes TEXT NOT NULL,     -- comma-separated
    created_at INTEGER NOT NULL
)
```

### authorization_codes
```sql
CREATE TABLE authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
)
```

### access_token
```sql
CREATE TABLE access_token (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    user_id TEXT
)
```

### refresh_tokens
```sql
CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
)
```

## API Endpoints

### Authorization Endpoint
```
GET /oauth/authorize
  ?response_type=code
  &client_id={client_id}
  &redirect_uri={redirect_uri}
  &scope={scope}
  &state={state}
  &code_challenge={challenge}
  &code_challenge_method=S256
  &user_id={user_id}
```

### Token Endpoint
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&redirect_uri={redirect_uri}
&client_id={client_id}
&client_secret={secret}  (for confidential clients)
&code_verifier={verifier}
```

### Admin Endpoints (Require Authorization)

#### Create Client
```
POST /admin/client
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "client_id": "my-app",
  "client_secret": "secret123",  // null for public clients
  "client_type": "confidential",  // or "public"
  "redirect_uris": "https://myapp.com/callback,https://myapp.com/callback2",
  "allowed_scopes": "read,write,profile"
}
```

#### Delete Client
```
DELETE /admin/client/{client_id}
Authorization: Bearer {admin_token}
```

#### Update Client Secret
```
PUT /admin/client/{client_id}
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "new_secret": "newsecret456"  // null for public clients
}
```

## Security Features

1. **Constant-Time Comparison**: Uses bcrypt for client secret verification
2. **Timing Attack Protection**: Performs dummy verification even for non-existent clients
3. **Rate Limiting**: Integrated rate limiting for auth endpoints
4. **CAPTCHA Support**: Cloudflare Turnstile integration for high-frequency requests
5. **Token Hashing**: All tokens stored as SHA-256 hashes
6. **Authorization Code Single-Use**: Codes marked as used after exchange
7. **Token Expiration**: All tokens have expiration times
8. **Refresh Token Revocation**: Support for revoking refresh tokens

## Configuration

Environment variables:
```
DATABASE_URL=sqlite://oauth.db
BIND=0.0.0.0:8084
BCRYPT_COST=12
TOKEN_TTL=3600                    # Access token lifetime (seconds)
ADMIN_TOKEN=admin_secret          # Admin API authentication
CF_SECRET_KEY=cloudflare_key      # Turnstile CAPTCHA
```

## Compliance Checklist

- ✅ PKCE required for all authorization code flows
- ✅ No implicit grant support
- ✅ No resource owner password credentials grant
- ✅ Proper error responses per RFC 6749
- ✅ Redirect URI validation with exact matching
- ✅ Public vs confidential client distinction
- ✅ Short-lived authorization codes (10 min)
- ✅ Refresh token support
- ✅ Scope validation
- ✅ One-time use authorization codes
- ✅ Cryptographically secure token generation
- ✅ Token hashing before storage
- ✅ WWW-Authenticate header on 401 responses

## Migration Notes

If migrating from the old implementation:

1. **Database Migration Required**: New schema includes:
   - `client_type`, `redirect_uris`, `allowed_scopes` in oauth_client
   - New `authorization_codes` table
   - New `refresh_tokens` table

2. **API Changes**:
   - Authorization endpoint now required for getting tokens
   - Client creation requires additional fields
   - Token endpoint requires `grant_type` parameter
   - PKCE parameters now mandatory

3. **Client Updates**:
   - Clients must implement PKCE flow
   - Must use authorization code flow (no more direct token issuance)
   - Public clients must not send client_secret

## References

- [OAuth 2.1 Draft Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
