-- +goose Up
-- Add display_name column to users table
ALTER TABLE users ADD COLUMN display_name TEXT;

-- Set display_name for admin user
UPDATE users SET display_name = 'Admin' WHERE id = 'admin-user-001';

-- +goose Down
ALTER TABLE users DROP COLUMN display_name;
