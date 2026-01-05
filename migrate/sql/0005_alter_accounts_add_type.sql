-- +goose Up
-- Add account_type to accounts table for Account state management.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'HEADLESS';
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(account_type);

-- +goose Down
DROP INDEX IF EXISTS idx_accounts_type;
-- SQLite lacks DROP COLUMN; for portability we leave the column in place or recreate table in a separate rollback.

