# Simple Makefile to manage local PostgreSQL via Docker Compose

.PHONY: db db-down db-ps db-logs db-restart db-wait env run dev swagger-open register

REG_DB_DSN_DEFAULT=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable

# Start PostgreSQL service defined in docker-compose.yml
db:
	docker compose up -d postgres

# Wait until PostgreSQL is ready (uses pg_isready inside container)
db-wait:
	@echo "Waiting for Postgres to be healthy..."
	@until docker compose exec -T postgres pg_isready -U oauth2 -d oauth2db >/dev/null 2>&1; do \
		printf '.'; \
		sleep 1; \
	done; echo " up"

# Run the example server with REG_DB_DSN (defaults to local compose DSN)
run:
	@echo "Starting example server..."
	@REG_DB_DSN=$${REG_DB_DSN:-$(REG_DB_DSN_DEFAULT)} go run ./example/server

# Convenience: bring DB up, wait, then run server with migrations enabled for Postgres
dev: db db-wait
	MIGRATE_ON_START=1 MIGRATE_DRIVER=postgres MIGRATE_DSN=$(REG_DB_DSN_DEFAULT) REG_DB_DSN=$(REG_DB_DSN_DEFAULT) $(MAKE) run

# Stop and remove PostgreSQL containers (keeps volume)
db-down:
	docker compose down

# Show compose services status
db-ps:
	docker compose ps

# Tail Postgres logs
db-logs:
	docker compose logs -f postgres

# Restart Postgres container
db-restart:
	docker compose restart postgres

# Print DSN to export for the server to use PostgreSQL-backed registration
env:
	@echo 'export REG_DB_DSN=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable'

# Open Swagger UI in default browser (macOS)
swagger-open:
	open http://localhost:9096/swagger

# Register a sample client against a running server
register:
	curl -s -X POST \
	  -H 'Content-Type: application/json' \
	  -d '{"redirect_uris":["http://localhost:9094/callback"],"client_name":"My App","token_endpoint_auth_method":"client_secret_basic"}' \
	  http://localhost:9096/register
