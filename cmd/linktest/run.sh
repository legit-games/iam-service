#!/bin/bash

# Link Test Application Runner
# This script sets up and runs the link test application on Mac

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default database configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-postgres}"
DB_NAME="${DB_NAME:-oauth2}"

export DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"

echo "============================================"
echo "  Link Test Application Setup"
echo "============================================"
echo ""
echo "Database: $DATABASE_URL"
echo ""

# Check if PostgreSQL is running
if ! command -v psql &> /dev/null; then
    echo "Warning: psql not found. Make sure PostgreSQL is installed."
    echo "On Mac: brew install postgresql@15"
fi

# Check if we can connect to the database
echo "Checking database connection..."
if psql "$DATABASE_URL" -c "SELECT 1" &> /dev/null; then
    echo "Database connection: OK"
else
    echo ""
    echo "Cannot connect to database. Please ensure:"
    echo "1. PostgreSQL is running"
    echo "2. Database '$DB_NAME' exists"
    echo ""
    echo "To create the database on Mac:"
    echo "  brew services start postgresql@15"
    echo "  createdb $DB_NAME"
    echo ""
    echo "Or with Docker:"
    echo "  docker run -d --name postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:15"
    echo "  docker exec -it postgres createdb -U postgres $DB_NAME"
    echo ""
    read -p "Press Enter to try anyway, or Ctrl+C to exit..."
fi

# Run migrations
echo ""
echo "Running database migrations..."
cd "$PROJECT_ROOT"
if [ -f "./migrate/cmd/main.go" ]; then
    go run ./migrate/cmd/main.go up || echo "Migration may have already been applied"
fi

# Build and run the application
echo ""
echo "Building application..."
go build -o "$SCRIPT_DIR/linktest" "$SCRIPT_DIR/main.go"

echo ""
echo "============================================"
echo "  Starting Link Test Application"
echo "  Open http://localhost:8088 in your browser"
echo "============================================"
echo ""

# Run the application
"$SCRIPT_DIR/linktest"
