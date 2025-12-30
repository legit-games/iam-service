# Database migrations (optional)

This project now includes a simple migration runner (similar to Flyway) built with [pressly/goose](https://github.com/pressly/goose). Migrations are embedded and can be run automatically at server startup or manually.

- Embedded SQL: `migrate/sql/*.sql`
- Runner: `migrate/migrate.go`
- Default driver: none. Example uses SQLite for simplicity.

## Run on server startup (example)

Set environment variables before starting the example server:

```sh
# SQLite file in current directory
export MIGRATE_ON_START=1
export MIGRATE_DRIVER=sqlite
export MIGRATE_DSN=./oauth2.db
# optional (default: up)
export MIGRATE_CMD=up
# optional (for up-to/down-to)
export MIGRATE_TARGET=0

# then run the example server
cd example/server
go run .
```

The example server imports `github.com/go-oauth2/oauth2/v4/migrate` and calls `migrate.RunFromEnv()` at startup. If `MIGRATE_ON_START` is not set to a truthy value, migrations are skipped.

## Manual usage from code

```go
import "github.com/go-oauth2/oauth2/v4/migrate"

err := migrate.Run(migrate.Options{
    Driver:  "sqlite",          // or "postgres", "mysql" (supply the driver import)
    DSN:     "./oauth2.db",     // DSN string for your driver
    Command: "up",               // up, down, status, version, up-to, down-to, redo, reset
    Target:  0,                   // used with up-to/down-to
})
if err != nil { /* handle */ }
```

For Postgres or MySQL, add the appropriate `database/sql` driver import in your app and set `MIGRATE_DRIVER`/`MIGRATE_DSN` accordingly.

## Notes
- The core library still uses in-memory/file `buntdb` token store by default; the SQL schema is illustrative. If you plan to use SQL storage, adapt the schema and implement a SQL-backed `TokenStore`/`ClientStore`.
- Goose keeps migration state in a `schema_migrations` table.
- To add a new migration, create a new `migrate/sql/XXXX_description.sql` file with `-- +goose Up` and `-- +goose Down` sections.

