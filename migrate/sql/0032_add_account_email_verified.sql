-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Add email verification columns to accounts table
-- (email is stored in accounts, so email_verified should be here too)
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP WITH TIME ZONE;

-- Index for querying unverified accounts
CREATE INDEX IF NOT EXISTS idx_accounts_email_verified ON accounts(email_verified) WHERE email IS NOT NULL;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP INDEX IF EXISTS idx_accounts_email_verified;
ALTER TABLE accounts DROP COLUMN IF EXISTS email_verified_at;
ALTER TABLE accounts DROP COLUMN IF EXISTS email_verified;
