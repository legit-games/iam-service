-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Email verification codes table for email address confirmation
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id VARCHAR(255) PRIMARY KEY,
    code VARCHAR(6) NOT NULL,                           -- 6-digit numeric code
    account_id VARCHAR(255) NOT NULL,                   -- Account requesting verification
    email VARCHAR(255) NOT NULL,                        -- Email to verify
    namespace_id VARCHAR(255) NOT NULL,                 -- Namespace scope
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,       -- When code expires (default 24 hours)
    verified BOOLEAN NOT NULL DEFAULT FALSE,            -- Whether email was verified
    verified_at TIMESTAMP WITH TIME ZONE,               -- When email was verified
    failed_attempts INTEGER NOT NULL DEFAULT 0,         -- Wrong code entry counter
    locked_until TIMESTAMP WITH TIME ZONE,              -- Lockout timestamp after too many failures
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- For looking up codes during validation
CREATE INDEX IF NOT EXISTS idx_email_verification_codes_code ON email_verification_codes(code);

-- For looking up by account
CREATE INDEX IF NOT EXISTS idx_email_verification_codes_account ON email_verification_codes(account_id);

-- For looking up by email and namespace
CREATE INDEX IF NOT EXISTS idx_email_verification_codes_email_ns ON email_verification_codes(email, namespace_id);

-- For cleanup jobs
CREATE INDEX IF NOT EXISTS idx_email_verification_codes_expires ON email_verification_codes(expires_at) WHERE verified = FALSE;

-- Rate limiting table for verification requests
CREATE TABLE IF NOT EXISTS email_verification_rate_limits (
    email VARCHAR(255) PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_request_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add email_verified column to users table if not exists
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP WITH TIME ZONE;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
DROP TABLE IF EXISTS email_verification_rate_limits;
DROP INDEX IF EXISTS idx_email_verification_codes_expires;
DROP INDEX IF EXISTS idx_email_verification_codes_email_ns;
DROP INDEX IF EXISTS idx_email_verification_codes_account;
DROP INDEX IF EXISTS idx_email_verification_codes_code;
DROP TABLE IF EXISTS email_verification_codes;
