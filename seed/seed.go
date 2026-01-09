package seed

import (
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// seedFS holds embedded SQL seed files in seed/sql.
//
//go:embed sql/*.sql
var seedFS embed.FS

// Options defines how to run seed migrations.
type Options struct {
	Driver  string      // e.g., sqlite, postgres, mysql
	DSN     string      // e.g., ./oauth2.db for sqlite, or full DSN for others
	Command string      // up, down, status, version, up-to, down-to, redo, reset
	Target  int64       // used with up-to/down-to
	Logger  *log.Logger // optional logger
}

// Run executes seed migrations based on provided options. If Driver or DSN are empty, it is a no-op.
func Run(opts Options) error {
	if strings.TrimSpace(opts.Driver) == "" || strings.TrimSpace(opts.DSN) == "" {
		return nil
	}

	// Check if there are any valid seed SQL files
	if !hasValidSeedFiles(opts.Logger) {
		return nil
	}

	if opts.Logger != nil {
		goose.SetLogger(opts.Logger)
	}
	goose.SetBaseFS(seedFS)
	goose.SetTableName("seed_migrations") // Separate table from schema migrations

	db, err := sql.Open(opts.Driver, opts.DSN)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	dir := "sql"
	switch strings.ToLower(strings.TrimSpace(opts.Command)) {
	case "", "up":
		return goose.Up(db, dir)
	case "down":
		return goose.Down(db, dir)
	case "status":
		return goose.Status(db, dir)
	case "version":
		return goose.Version(db, dir)
	case "up-to":
		return goose.UpTo(db, dir, opts.Target)
	case "down-to":
		return goose.DownTo(db, dir, opts.Target)
	case "redo":
		return goose.Redo(db, dir)
	case "reset":
		return goose.Reset(db, dir)
	default:
		return fmt.Errorf("unknown seed command: %s", opts.Command)
	}
}

// hasValidSeedFiles checks if there are any valid goose migration files in the seed/sql directory.
// Valid files must have the format: VERSION_name.sql (e.g., 0001_seed_data.sql)
func hasValidSeedFiles(logger *log.Logger) bool {
	entries, err := seedFS.ReadDir("sql")
	if err != nil {
		if logger != nil {
			logger.Println("no seed SQL directory found, skipping seed")
		}
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		// Check if filename has proper goose format (contains '_' separator after version number)
		idx := strings.Index(name, "_")
		if idx > 0 {
			// Has a valid version prefix
			return true
		}
	}

	if logger != nil {
		logger.Println("no valid seed SQL files found (files must be named like 0001_name.sql), skipping seed")
	}
	return false
}

// RunFromEnv reads configuration from environment variables and runs seed migrations
// if SEED_ON_START is truthy (1/true/TRUE/True).
//
// Env vars:
// - SEED_ON_START: if true/1, run seed migrations
// - SEED_DRIVER: sqlite, postgres, mysql, etc. (falls back to MIGRATE_DRIVER)
// - SEED_DSN: db connection string (falls back to MIGRATE_DSN)
// - SEED_CMD: up, down, status, version, up-to, down-to, redo, reset (default: up)
// - SEED_TARGET: integer version for up-to/down-to
func RunFromEnv() error {
	enabled := os.Getenv("SEED_ON_START")
	if !isTruthy(enabled) {
		return nil
	}

	cmd := strings.TrimSpace(os.Getenv("SEED_CMD"))
	if cmd == "" {
		cmd = "up"
	}

	var target int64
	if v := strings.TrimSpace(os.Getenv("SEED_TARGET")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			target = n
		}
	}

	// Fall back to MIGRATE_* env vars if SEED_* are not set
	driver := strings.TrimSpace(os.Getenv("SEED_DRIVER"))
	if driver == "" {
		driver = strings.TrimSpace(os.Getenv("MIGRATE_DRIVER"))
	}
	dsn := strings.TrimSpace(os.Getenv("SEED_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}

	logger := log.New(os.Stdout, "[seed] ", log.LstdFlags)

	return Run(Options{
		Driver:  driver,
		DSN:     dsn,
		Command: cmd,
		Target:  target,
		Logger:  logger,
	})
}

func isTruthy(v string) bool {
	s := strings.TrimSpace(strings.ToLower(v))
	return s == "1" || s == "true" || s == "yes" || s == "y"
}
