-- +goose Up
-- Add permissions column to accounts table (JSON array)
ALTER TABLE accounts ADD COLUMN permissions JSONB DEFAULT '[]'::jsonb;

-- +goose Down
ALTER TABLE accounts DROP COLUMN permissions;
