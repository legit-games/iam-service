-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Token revocation list - stores individual revoked tokens
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash VARCHAR(64) NOT NULL,  -- SHA256 hash of the token
    user_id VARCHAR(255),
    client_id VARCHAR(255),
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient lookup by token hash
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_hash ON revoked_tokens(token_hash);
-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);
-- Index for user-based queries
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(user_id) WHERE user_id IS NOT NULL;

-- User revocation list - when a user's ALL tokens should be invalidated
CREATE TABLE IF NOT EXISTS revoked_users (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient lookup by user_id
CREATE INDEX IF NOT EXISTS idx_revoked_users_user_id ON revoked_users(user_id);
-- Index for cleanup of expired entries
CREATE INDEX IF NOT EXISTS idx_revoked_users_expires ON revoked_users(expires_at);
-- Unique constraint to prevent duplicate active revocations for same user
CREATE UNIQUE INDEX IF NOT EXISTS idx_revoked_users_active ON revoked_users(user_id)
    WHERE expires_at > NOW();

-- Bloom filter storage for compressed token revocation data (date-partitioned)
CREATE TABLE IF NOT EXISTS revocation_bloom_filters (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    filter_date DATE NOT NULL,
    m INTEGER NOT NULL,           -- Bloom filter size (bits)
    k INTEGER NOT NULL,           -- Number of hash functions
    filter_data BYTEA NOT NULL,   -- Bloom filter bit array
    token_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Unique index for date-based lookup
CREATE UNIQUE INDEX IF NOT EXISTS idx_bloom_filters_date ON revocation_bloom_filters(filter_date);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP INDEX IF EXISTS idx_bloom_filters_date;
DROP TABLE IF EXISTS revocation_bloom_filters;

DROP INDEX IF EXISTS idx_revoked_users_active;
DROP INDEX IF EXISTS idx_revoked_users_expires;
DROP INDEX IF EXISTS idx_revoked_users_user_id;
DROP TABLE IF EXISTS revoked_users;

DROP INDEX IF EXISTS idx_revoked_tokens_user;
DROP INDEX IF EXISTS idx_revoked_tokens_expires;
DROP INDEX IF EXISTS idx_revoked_tokens_hash;
DROP TABLE IF EXISTS revoked_tokens;
