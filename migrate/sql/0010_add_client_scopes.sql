-- +goose Up
-- Add scopes column to oauth2_clients table
ALTER TABLE oauth2_clients ADD COLUMN scopes JSONB DEFAULT '[]'::jsonb;

-- Create index on scopes for better query performance
CREATE INDEX idx_oauth2_clients_scopes ON oauth2_clients USING gin (scopes);

-- +goose Down
-- Remove scopes column and index
DROP INDEX IF EXISTS idx_oauth2_clients_scopes;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS scopes;
