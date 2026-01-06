-- +goose Up
-- Create platform_users table to store third-party platform account links.
CREATE TABLE IF NOT EXISTS platform_users (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    platform_user_id TEXT NOT NULL,
    origin_namespace TEXT,
    display_name TEXT,
    email_address TEXT,
    avatar_url TEXT,
    online_id TEXT,
    refresh_token TEXT,
    linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_platform_users_user_id ON platform_users(user_id);
CREATE INDEX IF NOT EXISTS idx_platform_users_namespace ON platform_users(namespace);
CREATE INDEX IF NOT EXISTS idx_platform_users_platform_id ON platform_users(platform_id);
CREATE INDEX IF NOT EXISTS idx_platform_users_lookup ON platform_users(namespace, user_id, platform_id);
CREATE INDEX IF NOT EXISTS idx_platform_users_platform_user ON platform_users(namespace, platform_id, platform_user_id);

-- Uniqueness: prevent duplicate platform links per user/namespace/platform combo
CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_users_combo ON platform_users(namespace, user_id, platform_id);

-- +goose Down
DROP INDEX IF EXISTS uq_platform_users_combo;
DROP INDEX IF EXISTS idx_platform_users_platform_user;
DROP INDEX IF EXISTS idx_platform_users_lookup;
DROP INDEX IF EXISTS idx_platform_users_platform_id;
DROP INDEX IF EXISTS idx_platform_users_namespace;
DROP INDEX IF EXISTS idx_platform_users_user_id;
DROP TABLE IF EXISTS platform_users;
