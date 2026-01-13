# Rust OAuth Server

A minimal Axum-based OAuth 2.0 authorization server demonstrating the authorization_code flow with SQLite or PostgreSQL persistence (SQLx).

## Features

- `/register` and `/login` with bcrypt-hashed passwords.
- `/authorize` issues authorization codes for valid clients/users.
- `/token` exchanges auth codes for bearer tokens.
- `/health` probe.
- SQLite (default) or PostgreSQL storage for users, clients, auth codes, and tokens.

## Running

```bash
# SQLite (default)
cargo run

# PostgreSQL
DATABASE_URL=postgres://user:password@localhost/oauth_db cargo run
```

Environment variables:

- `DATABASE_URL` (optional): defaults to `sqlite://oauth.db`. URLs starting with `sqlite://` use SQLite; anything else tries PostgreSQL.
- `PORT` (optional): defaults to `8082`.

Server listens on `0.0.0.0:<PORT>`.

## Example Flow

1. Register a user:
   ```bash
   curl -X POST http://localhost:8082/register \
        -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"securepassword"}'
   ```
   Response returns `user_id`.

2. Login:
   ```bash
   curl -X POST http://localhost:8082/login \
        -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"securepassword"}'
   ```
   Response returns `user_id`.

3. Authorize:
   ```bash
   curl -X POST http://localhost:8082/authorize \
        -H 'Content-Type: application/json' \
        -d '{
              "client_id": "demo-client",
              "redirect_uri": "http://localhost:8081/callback",
              "user_id": "<user-id-from-login>",
              "scope": "read"
            }'
   ```
   Response returns `code`.

4. Exchange code for token:
   ```bash
   curl -X POST http://localhost:8082/token \
        -H 'Content-Type: application/json' \
        -d '{
              "grant_type": "authorization_code",
              "client_id": "demo-client",
              "client_secret": "demo-secret",
              "redirect_uri": "http://localhost:8081/callback",
              "code": "<code-from-step-3>"
            }'
   ```
   Response returns `access_token`.

## Notes

- Demo client `demo-client` / `demo-secret` is seeded automatically.
- SQLite DB file (`oauth.db`) is created in the project directory by default.
- Extend by adding refresh tokens, more grant types, or richer user/session handling.
https://dash.cloudflare.com/fb0013caf2280071f85fc063696e87a7/turnstile/add
https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/
<link rel="preconnect" href="https://challenges.cloudflare.com">
<script
  src="https://challenges.cloudflare.com/turnstile/v0/api.js"
  async
  defer
></script>
<div class="cf-turnstile" data-sitekey="<YOUR-SITE-KEY>"></div>
<div class="cf-turnstile" data-sitekey="<YOUR-SITE-KEY>"></div>
<div
  class="cf-turnstile"
  data-sitekey="<YOUR-SITE-KEY>"
  data-theme="light"
  data-size="normal"
  data-callback="onSuccess"
></div>

sequenceDiagram
  participant U as 用户(浏览器/App)
  participant C as 客户端应用
  participant A as 授权服务器
  participant R as 资源服务器/API

  C->>C: 生成 code_verifier, code_challenge
  C->>U: 构造授权链接并跳转<br>?client_id=...&response_type=code<br>&code_challenge=...&state=...
  U->>A: 打开授权页面, 登录并授权
  A->>U: 携带授权码回调<br>?code=xxx&state=yyy
  U->>C: 重定向回回调地址(带着 code)
  C->>A: 用授权码换取令牌<br>?grant_type=authorization_code<br>&code=xxx&code_verifier=...
  A->>C: 返回 access_token (可选 refresh_token)
  C->>R: 调用 API, 在 Header 携带 access_token
  R->>C: 返回资源数据
