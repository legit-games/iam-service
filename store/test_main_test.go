package store

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

// TestMain configures and runs DB migrations for store tests
func TestMain(m *testing.M) {
	log.Printf("Starting store test setup...")

	// Get config from environment or use default
	dsn := getTestDSN()
	if strings.TrimSpace(dsn) == "" {
		log.Printf("no test DSN available, skipping store tests")
		return
	}

	driver := "postgres"
	log.Printf("Using DSN: %s", dsn)

	// Wait for DB to be ready
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
		return
	}

	log.Printf("postgres is ready for store tests: driver=%s dsn=%s", driver, dsn)

	// Run migrations
	logger := migrateLogger()
	log.Printf("Running migrations...")
	if err := migrate.Run(migrate.Options{
		Driver:  driver,
		DSN:     dsn,
		Command: "up",
		Logger:  logger,
	}); err != nil {
		panic(fmt.Sprintf("store test migration failed: %v", err))
	}

	log.Printf("Migrations completed, running tests...")

	// Run tests
	code := m.Run()
	if code != 0 {
		log.Printf("store tests failed with code %d", code)
		panic(fmt.Sprintf("store tests failed with code %d", code))
	}
}

func migrateLogger() *log.Logger {
	return log.New(os.Stdout, "[store-migrate] ", log.LstdFlags)
}
