package server

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/migrate"
	_ "github.com/lib/pq"
)

// TestMain configures and runs DB migrations once before package tests against Docker PostgreSQL.
func TestMain(m *testing.M) {
	// Load config (files + env overrides)
	cfg := GetConfig()
	enabled, driver, dsn, cmd, target := cfg.MigrateOptionsFromConfig()
	if strings.TrimSpace(dsn) == "" {
		// Fallback to IAM DB DSN if migrate.dsn is missing
		dsn = cfg.UserWriteDSN()
	}

	// Wait for DB to be ready (simple retry)
	var ready bool
	for i := 0; i < 20; i++ {
		if db, err := sql.Open(driver, dsn); err == nil {
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
		log.Printf("postgres is not ready: driver=%s dsn=%s", driver, dsn)
		// Exit with failure to indicate DB not available
		panic("db not ready")
	}

	log.Printf("postgres is ready: driver=%s dsn=%s", driver, dsn)
	if enabled {
		logger := migrateLogger()
		if err := migrate.Run(migrate.Options{Driver: driver, DSN: dsn, Command: cmd, Target: target, Logger: logger}); err != nil {
			panic(fmt.Sprintf("migrate failed: %v", err))
		}
	}

	// Verify accounts table exists
	db, err := sql.Open(driver, dsn)
	if err != nil {
		panic(fmt.Sprintf("open test db failed: %v", err))
	}
	defer db.Close()
	if _, err := db.Exec(`SELECT 1 FROM accounts LIMIT 1`); err != nil {
		log.Printf("accounts table missing after migration: %v", err)
		panic(fmt.Sprintf("accounts table missing after migration: %v", err))
	}

	code := m.Run()
	if code != 0 {
		log.Printf("tests failed with code %d", code)
		panic(fmt.Sprintf("tests failed with code %d", code))
	}
}

func migrateLogger() *log.Logger {
	return log.New(os.Stdout, "[migrate] ", log.LstdFlags)
}
