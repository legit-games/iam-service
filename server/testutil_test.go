package server

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// getTestDSN returns the DSN set by TestMain or a sensible default for Docker Postgres.
func getTestDSN() (string, error) {
	dsn := os.Getenv("USER_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("MIGRATE_DSN")
	}
	if dsn == "" {
		dsn = "postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable"
	}
	if dsn == "" {
		return "", fmt.Errorf("no DSN configured; ensure TestMain sets USER_DB_DSN or MIGRATE_DSN")
	}
	return dsn, nil
}

// openTestDB opens a sql.DB against the test DSN using postgres driver.
func openTestDB() (*sql.DB, error) {
	dsn, err := getTestDSN()
	if err != nil {
		return nil, err
	}
	return sql.Open("postgres", dsn)
}
