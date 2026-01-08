-- +goose Up
-- Move permissions from accounts to users table

-- Step 1: Add permissions column to users table
ALTER TABLE users ADD COLUMN permissions JSONB DEFAULT '[]'::jsonb;

-- Step 2: Remove permissions column from accounts table
ALTER TABLE accounts DROP COLUMN permissions;

-- +goose Down
-- Reverse the migration

-- Step 1: Add permissions column back to accounts table
ALTER TABLE accounts ADD COLUMN permissions JSONB DEFAULT '[]'::jsonb;

-- Step 2: Remove permissions column from users table
ALTER TABLE users DROP COLUMN permissions;
