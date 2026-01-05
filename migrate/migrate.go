package migrate

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

// migrationsFS holds embedded SQL migrations in migrate/sql.
//
//go:embed sql/*.sql
var migrationsFS embed.FS

// Options defines how to run migrations.
type Options struct {
	Driver  string      // e.g., sqlite, postgres, mysql
	DSN     string      // e.g., ./oauth2.db for sqlite, or full DSN for others
	Command string      // up, down, status, version, up-to, down-to, redo, reset
	Target  int64       // used with up-to/down-to
	Logger  *log.Logger // optional logger
}

// Run executes migrations based on provided options. If Driver or DSN are empty, it is a no-op.
func Run(opts Options) error {
	if strings.TrimSpace(opts.Driver) == "" || strings.TrimSpace(opts.DSN) == "" {
		return nil
	}

	if opts.Logger != nil {
		goose.SetLogger(opts.Logger)
	}
	goose.SetBaseFS(migrationsFS)
	goose.SetTableName("schema_migrations")

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
		return fmt.Errorf("unknown migration command: %s", opts.Command)
	}
}

// RunFromEnv reads configuration from environment variables and runs migrations
// if MIGRATE_ON_START is truthy (1/true/TRUE/True).
//
// Env vars:
// - MIGRATE_ON_START: if true/1, run migrations
// - MIGRATE_DRIVER: sqlite, postgres, mysql, etc.
// - MIGRATE_DSN: db connection string (e.g., ./oauth2.db for sqlite)
// - MIGRATE_CMD: up, down, status, version, up-to, down-to, redo, reset (default: up)
// - MIGRATE_TARGET: integer version for up-to/down-to
func RunFromEnv() error {
	enabled := os.Getenv("MIGRATE_ON_START")
	if !isTruthy(enabled) {
		return nil
	}

	cmd := strings.TrimSpace(os.Getenv("MIGRATE_CMD"))
	if cmd == "" {
		cmd = "up"
	}

	var target int64
	if v := strings.TrimSpace(os.Getenv("MIGRATE_TARGET")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			target = n
		}
	}

	logger := log.New(os.Stdout, "[migrate] ", log.LstdFlags)

	return Run(Options{
		Driver:  strings.TrimSpace(os.Getenv("MIGRATE_DRIVER")),
		DSN:     strings.TrimSpace(os.Getenv("MIGRATE_DSN")),
		Command: cmd,
		Target:  target,
		Logger:  logger,
	})
}

func isTruthy(v string) bool {
	s := strings.TrimSpace(strings.ToLower(v))
	return s == "1" || s == "true" || s == "yes" || s == "y"
}
