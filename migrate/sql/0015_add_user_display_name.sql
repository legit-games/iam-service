-- +goose Up
-- Add display_name column to users table
ALTER TABLE users ADD COLUMN display_name TEXT;

-- +goose Down
ALTER TABLE users DROP COLUMN display_name;
