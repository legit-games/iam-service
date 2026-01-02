package server

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// getTestDSN returns the DSN from AppConfig (write preferred, then read).
func getTestDSN() (string, error) {
	cfg := GetConfig()
	dsn := cfg.UserWriteDSN()
	if dsn == "" {
		dsn = cfg.UserReadDSN()
	}
	if dsn == "" {
		return "", fmt.Errorf("no DSN configured in config; ensure config.test.yaml has database.iam.dsn/read/write")
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
