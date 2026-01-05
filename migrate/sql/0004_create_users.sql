-- +goose Up
-- Create users table to support multi-namespace users per account.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    namespace TEXT, -- NULL means HEAD user
    user_type TEXT NOT NULL CHECK (user_type IN ('HEAD','BODY')),
    provider_type TEXT, -- for BODY users
    provider_account_id TEXT, -- for BODY users
    orphaned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Basic indexes
CREATE INDEX IF NOT EXISTS idx_users_account_id ON users(account_id);
CREATE INDEX IF NOT EXISTS idx_users_namespace ON users(namespace);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider_type, provider_account_id);

-- Uniqueness: prevent duplicate BODY entries per account/namespace/provider combo
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_body_combo ON users(account_id, namespace, provider_type, provider_account_id);

-- +goose Down
DROP INDEX IF EXISTS uq_users_body_combo;
DROP INDEX IF EXISTS idx_users_provider;
DROP INDEX IF EXISTS idx_users_namespace;
DROP INDEX IF EXISTS idx_users_account_id;
DROP TABLE IF EXISTS users;

