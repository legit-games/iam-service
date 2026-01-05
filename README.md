# OAuth2 Server Enhancements

## Docker Compose (PostgreSQL)

A ready-to-run PostgreSQL for local development is provided.

```bash
# Start Postgres in background
docker compose up -d postgres

# Check health
docker compose ps
```

Default credentials:
- user: `oauth2`
- password: `oauth2pass`
- db: `oauth2db`
- port: `5432`

Connection DSN for the registration endpoint:
```
REG_DB_DSN=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable
```

Export `REG_DB_DSN` and run the example server to enable dynamic client registration:
```bash
export REG_DB_DSN=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable
# optionally run migrations on start for sqlite (not required for Postgres demo)
MIGRATE_ON_START=0 go run ./example/server
```

Then register a client:
```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost:9094/callback"],"client_name":"My App","token_endpoint_auth_method":"client_secret_basic"}' \
  http://localhost:9096/register | jq
```

## Swagger

Visit:
- Swagger UI: http://localhost:9096/swagger
- Swagger JSON: http://localhost:9096/swagger.json

# OAuth2 Server (Go)

## Operations: Refresh Token Rotation

The server supports configurable refresh token rotation policies:

- GenerateNew (default: true): Issue a new refresh token on refresh.
- ResetTime (default: true): Reset the refresh token creation time when rotating.
- RemoveOldAccess (default: true): Remove the previous access token after rotation.
- RemoveOldRefresh (default: true): Remove the previous refresh token (enforces reuse detection).
- AccessExpOverride: Override access token expiry (duration) during rotation.
- RefreshExpOverride: Override refresh token expiry (duration) during rotation.

These options live in `server.Config.RefreshRotation` and are applied to `manage.RefreshingConfig` during server initialization.

### Environment/Config Mapping
Currently, database and migration settings are loaded via YAML/ENV (`AppConfig`). Refresh Rotation has secure defaults enabled in code. If you need to change them, update `Config` before creating the server:

```go
cfg := server.NewConfig()
cfg.RefreshRotation.GenerateNew = true
cfg.RefreshRotation.RemoveOldRefresh = true
srv := server.NewServer(cfg, manage.NewDefaultManager())
```

### Behavior Verification
- Calling `/oauth/token` with the same `grant_type=refresh_token` twice in a row should fail on the second request.
- Run the test:

```bash
go test ./server -run TestRefreshTokenRotation_ReuseDetection -v
```

## Implicit Flow Disabled
- Requests to `/oauth/authorize?response_type=token` are rejected with HTTP 400 (`unsupported_response_type`).
- Swagger documents that Implicit is disabled.

Run the test:

```bash
go test ./server -run TestImplicitFlowDisabled -v
```

## Namespace Policy
- Namespace names must contain only uppercase letters A–Z; names are normalized to uppercase on storage.
- Namespace type is validated via an enum-like type: `publisher` or `game`.

## OpenID Connect (OIDC)
- OIDC Discovery, JWKS, and UserInfo endpoints are provided.
- Authorization Code with PKCE is recommended.
