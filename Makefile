# Simple Makefile to manage local PostgreSQL via Docker Compose

.PHONY: db db-down db-ps db-logs db-restart db-wait env run dev swagger-open register valkey valkey-down valkey-ps valkey-logs dev-valkey build-server run-server build-client run-client examples kill-server build test admin-install admin-dev admin-build admin-clean dev-admin build-with-admin linktest linktest-build linktest-dev linktest-kill

REG_DB_DSN_DEFAULT=postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable
VALKEY_ADDR_DEFAULT=127.0.0.1:6379
SERVER_PORT?=9096
# Default DSN for migrations (falls back to REG_DB_DSN_DEFAULT)
MIGRATE_DSN?=$(REG_DB_DSN_DEFAULT)

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
	MIGRATE_ON_START=1 MIGRATE_DRIVER=postgres MIGRATE_DSN=$(REG_DB_DSN_DEFAULT) SEED_ON_START=1 REG_DB_DSN=$(REG_DB_DSN_DEFAULT) VALKEY_ADDR=$(VALKEY_ADDR_DEFAULT) $(MAKE) run

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

# Build migrate CLI binary
migrate-build:
	@mkdir -p bin
	go build -o bin/migrate ./migrate/cmd
	chmod +x bin/migrate

# Run DB migrations (goose up) using migrate CLI
migrate-up: migrate-build
	@echo "Running DB migrations..."
	MIGRATE_ON_START=1 MIGRATE_DRIVER=postgres MIGRATE_DSN=$(MIGRATE_DSN) MIGRATE_CMD=up bin/migrate
	@echo "Migrations completed."

build: build-server build-client
	@echo "Built both server and client."

# Use bash for recipe evaluation to ensure inline envs are applied consistently
SHELL := /bin/bash
.SHELLFLAGS := -lc

# Verbose shell when VERBOSE=1
ifeq ($(VERBOSE),1)
.SHELLFLAGS := -lc -x
endif

# Run full test suite ensuring DB is restarted fresh and capture logs
test: db-down db db-wait migrate-up
	@echo "Running tests with fresh DB and latest migrations..."
	env APP_ENV=test go test ./... -v -count=1
	@echo "Test logs captured to test.out"

# Focused verbose server tests
.PHONY: test-verbose
test-verbose: db-down db db-wait migrate-up
	@echo "Running server package tests with verbose logs..."
	env APP_ENV=test go test ./server -v -count=1
	@echo "Server test logs captured to server.test.out"

# ==========================================
# Admin Console (React)
# ==========================================

# Install admin console dependencies
admin-install:
	cd admin && npm install

# Run admin console dev server (Vite on port 5173)
admin-dev:
	cd admin && npm run dev

# Build admin console for production
admin-build:
	cd admin && npm run build

# Clean admin console build
admin-clean:
	rm -rf admin/dist admin/node_modules

# Copy admin dist to server package for embedding
admin-embed: admin-build
	@echo "Copying admin/dist to server/admin/dist for embedding..."
	@mkdir -p server/admin
	@rm -rf server/admin/dist
	@cp -r admin/dist server/admin/dist
	@echo "Admin console embedded successfully."

# Development: run Go server (dev mode) and Vite dev server concurrently
dev-admin: kill-server db db-wait migrate-up admin-install
	@echo "Starting Go server (dev mode) and Vite dev server..."
	@trap 'kill %1 %2 2>/dev/null' SIGINT SIGTERM; \
	(MIGRATE_ON_START=1 MIGRATE_DRIVER=postgres MIGRATE_DSN=$(REG_DB_DSN_DEFAULT) SEED_ON_START=1 REG_DB_DSN=$(REG_DB_DSN_DEFAULT) VALKEY_ADDR=$(VALKEY_ADDR_DEFAULT) go run -tags dev ./example/server) & \
	(cd admin && npm run dev) & \
	wait

# Build server with embedded admin console (production)
build-with-admin: admin-embed
	@echo "Building server with embedded admin console..."
	cd example/server && go build -o ../../bin/server-with-admin server.go
	@echo "Server built at bin/server-with-admin"

# ==========================================
# Account Linking Test Application
# ==========================================

LINKTEST_PORT?=8088

# Build linktest binary
linktest-build:
	@echo "Building linktest..."
	@mkdir -p bin
	go build -o bin/linktest ./cmd/linktest
	@echo "Linktest built at bin/linktest"

# Run linktest directly with go run
linktest:
	@echo "Starting Account Linking Test on port $(LINKTEST_PORT)..."
	DATABASE_URL=$(REG_DB_DSN_DEFAULT) PORT=$(LINKTEST_PORT) go run ./cmd/linktest

# Run linktest with DB setup (start DB, wait, migrate, then run)
linktest-dev: db db-wait migrate-up
	@echo "Starting Account Linking Test (dev mode) on port $(LINKTEST_PORT)..."
	DATABASE_URL=$(REG_DB_DSN_DEFAULT) PORT=$(LINKTEST_PORT) go run ./cmd/linktest

# Kill linktest process on LINKTEST_PORT
linktest-kill:
	@echo "Killing linktest on port $(LINKTEST_PORT) if running..."
	@PIDS=$$(lsof -ti tcp:$(LINKTEST_PORT)); \
	if [ -n "$$PIDS" ]; then \
		echo "Found PIDs: $$PIDS"; \
		kill -9 $$PIDS || true; \
		echo "Port $(LINKTEST_PORT) is now free."; \
	else \
		echo "No process found on port $(LINKTEST_PORT)."; \
	fi
