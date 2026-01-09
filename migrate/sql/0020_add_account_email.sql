-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Add email column to accounts table (optional, unique when not null)
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email) WHERE email IS NOT NULL;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP INDEX IF EXISTS idx_accounts_email;
ALTER TABLE accounts DROP COLUMN IF EXISTS email;
