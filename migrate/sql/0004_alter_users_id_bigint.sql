-- +goose Up
-- Alter users.id to BIGINT for Snowflake-compatible IDs (Postgres)
ALTER TABLE IF EXISTS users ALTER COLUMN id TYPE BIGINT USING id::BIGINT;

-- +goose Down
-- Revert users.id to INTEGER (may fail if values exceed integer range)
ALTER TABLE IF EXISTS users ALTER COLUMN id TYPE INTEGER USING id::INTEGER;

