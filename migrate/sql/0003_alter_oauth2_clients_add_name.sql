-- +goose Up
-- Add 'name' column to oauth2_clients via ALTER to separate schema evolution from base create.
ALTER TABLE IF EXISTS oauth2_clients ADD COLUMN IF NOT EXISTS name TEXT;

-- +goose Down
ALTER TABLE IF EXISTS oauth2_clients DROP COLUMN IF EXISTS name;

