-- +goose Up
-- Add active column to namespaces table for enable/disable functionality.
ALTER TABLE namespaces ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;

-- +goose Down
ALTER TABLE namespaces DROP COLUMN active;
