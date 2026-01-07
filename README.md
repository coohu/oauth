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
