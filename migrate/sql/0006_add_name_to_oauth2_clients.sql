-- +goose Up
-- Add name column to oauth2_clients
ALTER TABLE IF EXISTS oauth2_clients ADD COLUMN IF NOT EXISTS name TEXT;

-- +goose Down
-- Remove name column
ALTER TABLE IF EXISTS oauth2_clients DROP COLUMN IF EXISTS name;
