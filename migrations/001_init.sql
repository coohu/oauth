-- Initial migration

-- Clients table
CREATE TABLE IF NOT EXISTS oauth_client (
    id TEXT PRIMARY KEY,
    secret_hash TEXT,
    client_type TEXT NOT NULL DEFAULT 'confidential',
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    tel TEXT UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Rate limits table
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

-- Authorization codes table
CREATE TABLE IF NOT EXISTS authorization_codes (
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
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);


-- Access tokens table
CREATE TABLE IF NOT EXISTS access_token (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    user_id TEXT
);