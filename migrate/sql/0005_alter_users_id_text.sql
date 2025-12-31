-- +goose Up
-- Alter users.id to TEXT to store hyphenless UUID strings
ALTER TABLE IF EXISTS users ALTER COLUMN id TYPE TEXT USING id::text;

-- +goose Down
-- Revert users.id to BIGINT (may fail if non-numeric UUIDs exist)
ALTER TABLE IF EXISTS users ALTER COLUMN id TYPE BIGINT USING id::bigint;

