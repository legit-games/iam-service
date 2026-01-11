-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- ============================================================================
-- MFA Settings per user account
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_mfa_settings (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    account_id VARCHAR(255) NOT NULL UNIQUE,
    totp_secret_encrypted BYTEA,
    totp_secret_nonce BYTEA,
    totp_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enabled_at TIMESTAMP WITH TIME ZONE,
    disabled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_settings_account ON user_mfa_settings(account_id);

-- ============================================================================
-- Backup codes for MFA recovery (hashed with bcrypt)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_mfa_backup_codes (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    account_id VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_account ON user_mfa_backup_codes(account_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_unused ON user_mfa_backup_codes(account_id)
    WHERE used = FALSE;

-- ============================================================================
-- Namespace-level MFA requirement settings
-- ============================================================================
CREATE TABLE IF NOT EXISTS namespace_mfa_settings (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    namespace VARCHAR(255) NOT NULL UNIQUE,
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    grace_period_days INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_namespace_mfa_namespace ON namespace_mfa_settings(namespace);

-- ============================================================================
-- MFA attempt tracking for rate limiting
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_mfa_attempts (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    account_id VARCHAR(255) NOT NULL,
    attempt_type VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_attempts_account ON user_mfa_attempts(account_id);
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_locked ON user_mfa_attempts(account_id, locked_until);

-- ============================================================================
-- MFA tokens for two-phase login
-- ============================================================================
CREATE TABLE IF NOT EXISTS mfa_tokens (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash VARCHAR(64) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_tokens_hash ON mfa_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_tokens_account ON mfa_tokens(account_id);
CREATE INDEX IF NOT EXISTS idx_mfa_tokens_expires ON mfa_tokens(expires_at);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP INDEX IF EXISTS idx_mfa_tokens_expires;
DROP INDEX IF EXISTS idx_mfa_tokens_account;
DROP INDEX IF EXISTS idx_mfa_tokens_hash;
DROP TABLE IF EXISTS mfa_tokens;

DROP INDEX IF EXISTS idx_mfa_attempts_locked;
DROP INDEX IF EXISTS idx_mfa_attempts_account;
DROP TABLE IF EXISTS user_mfa_attempts;

DROP INDEX IF EXISTS idx_namespace_mfa_namespace;
DROP TABLE IF EXISTS namespace_mfa_settings;

DROP INDEX IF EXISTS idx_mfa_backup_codes_unused;
DROP INDEX IF EXISTS idx_mfa_backup_codes_account;
DROP TABLE IF EXISTS user_mfa_backup_codes;

DROP INDEX IF EXISTS idx_user_mfa_settings_account;
DROP TABLE IF EXISTS user_mfa_settings;
