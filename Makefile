# Simple Makefile to manage local PostgreSQL via Docker Compose

.PHONY: db db-down db-ps db-logs db-restart db-wait env run dev swagger-open register valkey valkey-down valkey-ps valkey-logs dev-valkey build-server run-server build-client run-client examples kill-server build test

REG_DB_DSN_DEFAULT=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable
VALKEY_ADDR_DEFAULT=127.0.0.1:6379
SERVER_PORT?=9096

# Start PostgreSQL service defined in docker-compose.yml
db:
	docker compose up -d

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
	@REG_DB_DSN=$${REG_DB_DSN:-$(REG_DB_DSN_DEFAULT)} VALKEY_ADDR=$${VALKEY_ADDR:-$(VALKEY_ADDR_DEFAULT)} go run ./example/server

# Convenience: bring DB up, wait, then run server with migrations enabled for Postgres
dev: db db-wait
	MIGRATE_ON_START=1 MIGRATE_DRIVER=postgres MIGRATE_DSN=$(REG_DB_DSN_DEFAULT) REG_DB_DSN=$(REG_DB_DSN_DEFAULT) VALKEY_ADDR=$(VALKEY_ADDR_DEFAULT) $(MAKE) run

# Valkey controls
valkey:
	docker compose up -d valkey
valkey-down:
	docker compose down
valkey-ps:
	docker compose ps
valkey-logs:
	docker compose logs -f valkey

# Bring up Valkey and run server wired to Valkey
dev-valkey: valkey
	VALKEY_ADDR=$(VALKEY_ADDR_DEFAULT) MIGRATE_ON_START=0 $(MAKE) run

# Build and run example server (per README)
build-server:
	cd example/server && go build server.go
run-server:
	cd example/server && ./server

# Build and run example client (per README)
build-client:
	cd example/client && go build client.go
run-client:
	cd example/client && ./client

# Combined helper to build both
examples: build-server build-client
	@echo "Built example server and client. Use 'make run-server' and 'make run-client' to run."

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
	@echo 'export VALKEY_ADDR=127.0.0.1:6379'

# Open Swagger UI in default browser (macOS)
swagger-open:
	open http://localhost:$(SERVER_PORT)/swagger

# Kill any process listening on SERVER_PORT (default 9096)
kill-server:
	@echo "Killing server on port $(SERVER_PORT) if running..."
	@PIDS=$$(lsof -ti tcp:$(SERVER_PORT)); \
	if [ -n "$$PIDS" ]; then \
		echo "Found PIDs: $$PIDS"; \
		kill $$PIDS || true; \
		sleep 1; \
		PIDS2=$$(lsof -ti tcp:$(SERVER_PORT)); \
		if [ -n "$$PIDS2" ]; then \
			echo "Force killing remaining PIDs: $$PIDS2"; \
			kill -9 $$PIDS2 || true; \
		else \
			echo "Port $(SERVER_PORT) is now free."; \
		fi; \
	else \
		echo "No process found on port $(SERVER_PORT)."; \
	fi

# Register a sample client against a running server
register:
	curl -s -X POST \
	  -H 'Content-Type: application/json' \
	  -d '{"redirect_uris":["http://localhost:9094/callback"],"client_name":"My App","token_endpoint_auth_method":"client_secret_basic"}' \
	  http://localhost:$(SERVER_PORT)/iam/v1/oauth/clients

build: build-server build-client
	@echo "Built both server and client."

test: db db-wait
	go test ./...
