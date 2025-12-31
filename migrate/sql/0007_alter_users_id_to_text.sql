-- +goose Up
-- Convert users.id from BIGINT to TEXT to store hyphenless UUID identifiers.
-- Postgres syntax
ALTER TABLE users
    ALTER COLUMN id TYPE TEXT USING id::text;

-- +goose Down
-- Best-effort revert: convert back to BIGINT (will fail if any non-numeric ids exist)
ALTER TABLE users
    ALTER COLUMN id TYPE BIGINT USING id::bigint;

