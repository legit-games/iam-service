-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Password reset codes table for secure password recovery flow
CREATE TABLE IF NOT EXISTS password_reset_codes (
    id VARCHAR(255) PRIMARY KEY,
    code VARCHAR(6) NOT NULL,                           -- 6-digit numeric code
    account_id VARCHAR(255) NOT NULL,                   -- Account requesting reset
    email VARCHAR(255) NOT NULL,                        -- Email the code was sent to
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,       -- When code expires (default 1 hour)
    used BOOLEAN NOT NULL DEFAULT FALSE,                -- Whether code has been consumed
    used_at TIMESTAMP WITH TIME ZONE,                   -- When code was used
    failed_attempts INTEGER NOT NULL DEFAULT 0,         -- Wrong code entry counter
    locked_until TIMESTAMP WITH TIME ZONE,              -- Lockout timestamp after too many failures
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- For looking up codes during validation
CREATE INDEX IF NOT EXISTS idx_password_reset_codes_code ON password_reset_codes(code);

-- For rate limiting queries (requests per email in time window)
CREATE INDEX IF NOT EXISTS idx_password_reset_codes_email_created ON password_reset_codes(email, created_at);

-- For cleanup jobs
CREATE INDEX IF NOT EXISTS idx_password_reset_codes_expires ON password_reset_codes(expires_at) WHERE used = FALSE;

-- Rate limiting table for forgot-password requests
-- Tracks request attempts per email to prevent abuse
CREATE TABLE IF NOT EXISTS password_reset_rate_limits (
    email VARCHAR(255) PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_request_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP TABLE IF EXISTS password_reset_rate_limits;
DROP INDEX IF EXISTS idx_password_reset_codes_expires;
DROP INDEX IF EXISTS idx_password_reset_codes_email_created;
DROP INDEX IF EXISTS idx_password_reset_codes_code;
DROP TABLE IF EXISTS password_reset_codes;
