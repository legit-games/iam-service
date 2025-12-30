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


