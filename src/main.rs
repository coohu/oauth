use axum::{
    extract::{Path, State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{
    postgres::{PgPoolOptions},
    sqlite::{SqlitePoolOptions},
    FromRow, Pool, Postgres, Sqlite,
};
use std::{env, net::SocketAddr, time::Duration};
use uuid::Uuid;
use moka::future::Cache;

#[derive(Clone)]
struct CodeCache {
    cache: Cache<String, AuthCode>,
}

impl CodeCache {
    fn new() -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(600))
                .build(),
        }
    }
    #[allow(dead_code)]
    async fn get(&self, key: &str) -> Option<AuthCode> {
        self.cache.get(key).await
    }

    async fn insert(&self, key: String, value: AuthCode) {
        self.cache.insert(key, value).await;
    }

    async fn remove(&self, key: &str) -> Option<AuthCode> {
        self.cache.remove(key).await
    }
}

#[derive(Clone)]
struct AppState {
    db: Database,
    cache: CodeCache,
}

#[derive(Clone)]
enum Database {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

// 优化:通过统一的方法抽象数据库差异,避免业务逻辑中充斥着 match
// Note: This method is currently unused but kept for potential future use
#[allow(dead_code)]
impl Database {
    async fn execute<'a>(&self, query: &'a str, args: Vec<String>) -> Result<(), sqlx::Error> {
        match self {
            Database::Sqlite(pool) => {
                let mut q = sqlx::query(query);
                for arg in args { q = q.bind(arg); }
                q.execute(pool).await?;
            }
            Database::Postgres(pool) => {
                // Postgres 使用 $1, $2... Sqlite 使用 ?
                // 这里为了演示简单保留原样,实际生产建议使用 QueryBuilder 或 sqlx::Any
                // 本处假设传入的 query 已经适配了对应数据库,或者使用简单的通用 SQL
                let mut q = sqlx::query(query);
                for arg in args { q = q.bind(arg); }
                q.execute(pool).await?;
            }
        }
        Ok(())
    }
}

impl AppState {
    async fn new() -> Result<Self, AppError> {
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://oauth.db".into());
        let db = if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
            let pool = PgPoolOptions::new().max_connections(5).connect(&database_url).await?;
            init_postgres(&pool).await?;
            Database::Postgres(pool)
        } else {
            let pool = SqlitePoolOptions::new().max_connections(5).connect(&database_url).await?;
            init_sqlite(&pool).await?;
            Database::Sqlite(pool)
        };

        let cache = CodeCache::new();
        load_codes_into_cache(&db, &cache).await?;

        Ok(Self { db, cache })
    }
}

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Conflict(String),
    NotFound(String),
    Database(sqlx::Error),
    Hash(bcrypt::BcryptError),
    Io(std::io::Error),
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, description) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "invalid_request", msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "access_denied", msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            AppError::Database(err) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("Database error: {}", err)),
            AppError::Hash(err) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("Hash error: {}", err)),
            AppError::Io(err) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("IO error: {}", err)),
        };
        (status, Json(json!({ "error": error_code, "error_description": description }))).into_response()
    }
}
impl From<sqlx::Error> for AppError { fn from(err: sqlx::Error) -> Self { AppError::Database(err) } }
impl From<bcrypt::BcryptError> for AppError { fn from(err: bcrypt::BcryptError) -> Self { AppError::Hash(err) } }
impl From<std::io::Error> for AppError { fn from(err: std::io::Error) -> Self { AppError::Io(err) } }


#[derive(Clone, Serialize, Deserialize, FromRow)]
struct User { id: String, username: String, password_hash: String }

#[derive(Clone, Serialize, Deserialize, FromRow)]
struct OAuthClient { client_id: String, client_secret: String, redirect_uri: String }

#[derive(Clone, Serialize, Deserialize, FromRow)]
struct AuthCode { code: String, client_id: String, redirect_uri: String, user_id: String, scope: String, expires_at: i64 }

#[derive(Clone, Serialize, Deserialize, FromRow)]
struct AccessToken { access_token: String, client_id: String, user_id: String, scope: String, expires_in: i64 }

#[derive(Deserialize)]
struct AuthPayload { username: String, password: String }

#[derive(Deserialize)]
struct ClientPayload { client_id: Option<String>, client_secret: Option<String>, redirect_uri: String }

#[derive(Serialize)]
struct RegisterResponse { message: &'static str, user_id: String, username: String }

#[derive(Serialize)]
struct LoginResponse { message: &'static str, user_id: String }

#[derive(Serialize)]
struct ClientResponse { client_id: String, client_secret: String, redirect_uri: String }

#[derive(Deserialize)]
struct AuthorizePayload { 
    client_id: String, 
    redirect_uri: String, 
    scope: Option<String>, 
    user_id: String,
    state: Option<String> // 修复:必须接收 state
}

#[derive(Serialize)]
struct AuthorizeResponse { code: String, state: String }

#[derive(Deserialize)]
struct TokenPayload {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    scope: String,
    expires_in: i64,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let state = AppState::new().await?;

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        // Auth Routes
        .route("/register", post(register))
        .route("/login", post(login))
        // OAuth Flow Routes
        .route("/authorize", post(authorize))
        .route("/token", post(token))
        .route("/verify", get(verify_token)) // 新增:验证 Token 接口
        // Client Management Routes
        .route("/clients", post(create_client).get(list_clients))
        .route("/clients/:client_id", get(get_client_handler).delete(delete_client))
        .with_state(state);

    let port: u16 = env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8082);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("OAuth Server listening on {addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn register(State(state): State<AppState>, Json(payload): Json<AuthPayload>) -> Result<Json<RegisterResponse>, AppError> {
    if payload.username.trim().is_empty() || payload.password.len() < 6 {
        return Err(AppError::BadRequest("Invalid username or password".into()));
    }
    if get_user_by_username(&state, &payload.username).await?.is_some() {
        return Err(AppError::Conflict("User already exists".into()));
    }

    let user_id = Uuid::new_v4().to_string();
    let hash = hash(payload.password, DEFAULT_COST)?;
    
    // 优化:使用帮助函数减少 match 嵌套,注意 Postgres 需要 $1 占位符,Sqlite 需要 ?
    // 为了简单,这里根据类型手动构建,实际项目可封装 QueryBuilder
    match &state.db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
                .bind(&user_id).bind(&payload.username).bind(&hash).execute(pool).await?;
        },
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
                .bind(&user_id).bind(&payload.username).bind(&hash).execute(pool).await?;
        }
    }

    Ok(Json(RegisterResponse { message: "User created", user_id, username: payload.username }))
}

async fn login(State(state): State<AppState>, Json(payload): Json<AuthPayload>) -> Result<Json<LoginResponse>, AppError> {
    let user = get_user_by_username(&state, &payload.username).await?
        .ok_or_else(|| AppError::Unauthorized("Invalid username or password".into()))?;

    if !verify(payload.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("Invalid username or password".into()));
    }
    Ok(Json(LoginResponse { message: "Login successful", user_id: user.id }))
}

async fn create_client(State(state): State<AppState>, Json(payload): Json<ClientPayload>) -> Result<Json<ClientResponse>, AppError> {
    let client_id = payload.client_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let client_secret = payload.client_secret.unwrap_or_else(|| Uuid::new_v4().to_string());
    
    match &state.db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (?, ?, ?)")
                .bind(&client_id).bind(&client_secret).bind(&payload.redirect_uri).execute(pool).await?;
        },
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES ($1, $2, $3)")
                .bind(&client_id).bind(&client_secret).bind(&payload.redirect_uri).execute(pool).await?;
        }
    }

    Ok(Json(ClientResponse { client_id, client_secret, redirect_uri: payload.redirect_uri }))
}

async fn list_clients(State(state): State<AppState>) -> Result<Json<Vec<ClientResponse>>, AppError> {
    let clients = match &state.db {
        Database::Sqlite(pool) => sqlx::query_as::<_, OAuthClient>("SELECT * FROM clients").fetch_all(pool).await?,
        Database::Postgres(pool) => sqlx::query_as::<_, OAuthClient>("SELECT * FROM clients").fetch_all(pool).await?,
    };
    
    Ok(Json(clients.into_iter().map(|c| ClientResponse {
        client_id: c.client_id, client_secret: c.client_secret, redirect_uri: c.redirect_uri
    }).collect()))
}

async fn get_client_handler(State(state): State<AppState>, Path(client_id): Path<String>) -> Result<Json<ClientResponse>, AppError> {
    let client = get_client(&state, &client_id).await?
        .ok_or_else(|| AppError::NotFound("Client not found".into()))?;
    
    Ok(Json(ClientResponse { client_id: client.client_id, client_secret: client.client_secret, redirect_uri: client.redirect_uri }))
}

async fn delete_client(State(state): State<AppState>, Path(client_id): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
   // 修复:通过显式丢弃返回值解决 SqliteQueryResult vs PgQueryResult 类型冲突
    match &state.db {
        Database::Sqlite(p) => { sqlx::query("DELETE FROM clients WHERE client_id = ?").bind(&client_id).execute(p).await?; }
        Database::Postgres(p) => { sqlx::query("DELETE FROM clients WHERE client_id = $1").bind(&client_id).execute(p).await?; }
    };
    Ok(Json(json!({"message": "deleted"})))
}

async fn authorize(State(state): State<AppState>, Json(payload): Json<AuthorizePayload>) -> Result<Json<AuthorizeResponse>, AppError> {
    let client = get_client(&state, &payload.client_id).await?
        .ok_or_else(|| AppError::Unauthorized("Client not found".into()))?;

    if client.redirect_uri != payload.redirect_uri {
        return Err(AppError::BadRequest("Redirect URI mismatch".into()));
    }

    // 实际场景中这里应该检查 user_id 是否合法 (session valid?)
    let code = AuthCode {
        code: Uuid::new_v4().to_string(),
        client_id: payload.client_id,
        redirect_uri: payload.redirect_uri,
        user_id: payload.user_id,
        scope: payload.scope.unwrap_or_else(|| "default".into()),
        expires_at: chrono::Utc::now().timestamp() + 600, // 10 minutes
    };

    state.cache.insert(code.code.clone(), code.clone()).await;
    let db_state = state.clone();
    let code_for_db = code.clone();
    tokio::spawn(async move {
        if let Err(e) = store_auth_code(&db_state, &code_for_db).await {
            tracing::error!("Failed to store auth code in db: {:?}", e);
        }
    });

    Ok(Json(AuthorizeResponse { code: code.code, state: payload.state.unwrap_or_default() }))
}

async fn token(State(state): State<AppState>, Json(payload): Json<TokenPayload>) -> Result<Json<TokenResponse>, AppError> {
    if payload.grant_type != "authorization_code" {
        return Err(AppError::BadRequest("Unsupported grant_type".into()));
    }

    let client = get_client(&state, &payload.client_id).await?
        .ok_or_else(|| AppError::Unauthorized("Invalid client".into()))?;

    if client.client_secret != payload.client_secret {
        return Err(AppError::Unauthorized("Invalid client_secret".into()));
    }

    let auth_code = consume_auth_code(&state, &payload.code).await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired code".into()))?;

    if auth_code.client_id != payload.client_id || auth_code.redirect_uri != payload.redirect_uri {
        return Err(AppError::BadRequest("Code verification failed".into()));
    }

    let token = AccessToken {
        access_token: Uuid::new_v4().to_string(),
        client_id: auth_code.client_id,
        user_id: auth_code.user_id,
        scope: auth_code.scope,
        expires_in: 3600,
    };

    store_access_token(&state, &token).await?;
    Ok(Json(TokenResponse {
        access_token: token.access_token,
        token_type: "Bearer",
        scope: token.scope,
        expires_in: token.expires_in,
    }))
}

async fn verify_token(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, AppError> {
    let auth_header = headers.get("Authorization").ok_or(AppError::Unauthorized("Missing Authorization header".into()))?;
    let token_str = auth_header.to_str().map_err(|_| AppError::Unauthorized("Invalid header".into()))?
        .replace("Bearer ", "");

    let token_data = get_access_token(&state, &token_str).await?
        .ok_or(AppError::Unauthorized("Invalid token".into()))?;

    // 此处可以添加过期时间检查
    
    Ok(Json(json!({
        "active": true,
        "client_id": token_data.client_id,
        "user_id": token_data.user_id,
        "scope": token_data.scope,
        "expires_in": token_data.expires_in
    })))
}

async fn get_user_by_username(state: &AppState, username: &str) -> Result<Option<User>, AppError> {
    match &state.db {
        Database::Sqlite(pool) => sqlx::query_as("SELECT * FROM users WHERE username = ?").bind(username).fetch_optional(pool).await.map_err(Into::into),
        Database::Postgres(pool) => sqlx::query_as("SELECT * FROM users WHERE username = $1").bind(username).fetch_optional(pool).await.map_err(Into::into),
    }
}

async fn get_client(state: &AppState, client_id: &str) -> Result<Option<OAuthClient>, AppError> {
    match &state.db {
        Database::Sqlite(pool) => sqlx::query_as("SELECT * FROM clients WHERE client_id = ?").bind(client_id).fetch_optional(pool).await.map_err(Into::into),
        Database::Postgres(pool) => sqlx::query_as("SELECT * FROM clients WHERE client_id = $1").bind(client_id).fetch_optional(pool).await.map_err(Into::into),
    }
}

async fn store_auth_code(state: &AppState, code: &AuthCode) -> Result<(), AppError> {
    match &state.db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO auth_codes (code, client_id, redirect_uri, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&code.code).bind(&code.client_id).bind(&code.redirect_uri).bind(&code.user_id).bind(&code.scope).bind(code.expires_at)
            .execute(pool).await?;
        },
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO auth_codes (code, client_id, redirect_uri, user_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(&code.code).bind(&code.client_id).bind(&code.redirect_uri).bind(&code.user_id).bind(&code.scope).bind(code.expires_at)
            .execute(pool).await?;
        }
    }
    Ok(())
}

async fn consume_auth_code(state: &AppState, value: &str) -> Result<Option<AuthCode>, AppError> {
    if let Some(code) = state.cache.remove(value).await {
        let db_state = state.clone();
        let value = value.to_string();
        tokio::spawn(async move {
            let _ = delete_auth_code(&db_state, &value).await;
        });
        return Ok(Some(code));
    }

    // Fallback to DB for codes not in cache (e.g. after restart)
    let code = delete_auth_code(state, value).await?;

    if let Some(c) = &code {
        if c.expires_at < chrono::Utc::now().timestamp() {
            return Ok(None);
        }
    }
    Ok(code)
}

async fn delete_auth_code(state: &AppState, value: &str) -> Result<Option<AuthCode>, AppError> {
    match &state.db {
        Database::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let code: Option<AuthCode> = sqlx::query_as("SELECT * FROM auth_codes WHERE code = ?").bind(value).fetch_optional(&mut *tx).await?;
            if code.is_some() {
                sqlx::query("DELETE FROM auth_codes WHERE code = ?").bind(value).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            Ok(code)
        }
        Database::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let code: Option<AuthCode> = sqlx::query_as("SELECT * FROM auth_codes WHERE code = $1").bind(value).fetch_optional(&mut *tx).await?;
            if code.is_some() {
                sqlx::query("DELETE FROM auth_codes WHERE code = $1").bind(value).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            Ok(code)
        }
    }
}

async fn store_access_token(state: &AppState, token: &AccessToken) -> Result<(), AppError> {
    match &state.db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO access_tokens (access_token, client_id, user_id, scope, expires_in) VALUES (?, ?, ?, ?, ?)")
                .bind(&token.access_token).bind(&token.client_id).bind(&token.user_id).bind(&token.scope).bind(token.expires_in)
                .execute(pool).await?;
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO access_tokens (access_token, client_id, user_id, scope, expires_in) VALUES ($1, $2, $3, $4, $5)")
                .bind(&token.access_token).bind(&token.client_id).bind(&token.user_id).bind(&token.scope).bind(token.expires_in)
                .execute(pool).await?;
        }
    }
    Ok(())
}

async fn get_access_token(state: &AppState, token: &str) -> Result<Option<AccessToken>, AppError> {
    match &state.db {
        Database::Sqlite(pool) => sqlx::query_as("SELECT * FROM access_tokens WHERE access_token = ?").bind(token).fetch_optional(pool).await.map_err(Into::into),
        Database::Postgres(pool) => sqlx::query_as("SELECT * FROM access_tokens WHERE access_token = $1").bind(token).fetch_optional(pool).await.map_err(Into::into),
    }
}

async fn load_codes_into_cache(db: &Database, cache: &CodeCache) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    let codes: Vec<AuthCode> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as("SELECT * FROM auth_codes WHERE expires_at > ?")
                .bind(now)
                .fetch_all(pool)
                .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as("SELECT * FROM auth_codes WHERE expires_at > $1")
                .bind(now)
                .fetch_all(pool)
                .await?
        }
    };

    for code in codes {
        cache.insert(code.code.clone(), code).await;
    }

    Ok(())
}

async fn init_sqlite(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, client_secret TEXT NOT NULL, redirect_uri TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS access_tokens (access_token TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, expires_in INTEGER NOT NULL)").execute(pool).await?;
    sqlx::query("INSERT OR IGNORE INTO clients (client_id, client_secret, redirect_uri) VALUES ('demo-client', 'demo-secret', 'http://localhost:8081/callback')").execute(pool).await?;
    Ok(())
}

async fn init_postgres(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, client_secret TEXT NOT NULL, redirect_uri TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at BIGINT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS access_tokens (access_token TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, expires_in INTEGER NOT NULL)").execute(pool).await?;
    sqlx::query("INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES ('demo-client', 'demo-secret', 'http://localhost:8081/callback') ON CONFLICT (client_id) DO NOTHING").execute(pool).await?;
    Ok(())
}