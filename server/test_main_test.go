package server

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/migrate"
	_ "github.com/lib/pq"
)

// TestMain configures and runs DB migrations once before package tests against Docker PostgreSQL.
func TestMain(m *testing.M) {
	// Docker postgres connection
	dsn := "postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable"
	os.Setenv("MIGRATE_ON_START", "1")
	os.Setenv("MIGRATE_DRIVER", "postgres")
	os.Setenv("MIGRATE_DSN", dsn)
	os.Setenv("USER_DB_DRIVER", "postgres")
	os.Setenv("USER_DB_DSN", dsn)

	// Wait for DB to be ready (simple retry)
	var ready bool
	for i := 0; i < 20; i++ {
		if db, err := sql.Open("postgres", dsn); err == nil {
			if err = db.Ping(); err == nil {
				ready = true
				_ = db.Close()
				break
			}
			_ = db.Close()
		}
		time.Sleep(1 * time.Second)
	}
	if !ready {
		fmt.Fprintf(os.Stderr, "postgres is not ready on localhost:5432\n")
		os.Exit(1)
	}

	if err := migrate.RunFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "migrate failed: %v\n", err)
		os.Exit(1)
	}
	// Verify users table exists
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open test db failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	if _, err := db.Exec(`SELECT 1 FROM users LIMIT 1`); err != nil {
		fmt.Fprintf(os.Stderr, "users table missing after migration: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	os.Exit(code)
}
