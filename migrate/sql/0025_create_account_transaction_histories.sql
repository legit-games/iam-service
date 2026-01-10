-- +goose Up
-- Account transaction histories for detailed audit trail of linking/unlinking operations
-- Following the pattern from legit-iam-service

-- First, add description column to account_transactions if not exists
ALTER TABLE account_transactions ADD COLUMN IF NOT EXISTS description TEXT;

-- Create account_transaction_histories table
CREATE TABLE IF NOT EXISTS account_transaction_histories (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES account_transactions(id) ON DELETE CASCADE,

    -- User that was affected
    user_id TEXT,

    -- Account references
    account_id TEXT,
    from_account_id TEXT,
    to_account_id TEXT,

    -- User movement tracking
    from_user_id TEXT,
    to_user_id TEXT,

    -- Provider account being linked/unlinked
    provider_type TEXT,
    provider_account_id TEXT,

    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by TEXT
);

-- Indexes for common queries
CREATE INDEX idx_ath_transaction ON account_transaction_histories(transaction_id);
CREATE INDEX idx_ath_account ON account_transaction_histories(account_id);
CREATE INDEX idx_ath_user ON account_transaction_histories(user_id);
CREATE INDEX idx_ath_from_account ON account_transaction_histories(from_account_id);
CREATE INDEX idx_ath_to_account ON account_transaction_histories(to_account_id);
CREATE INDEX idx_ath_created ON account_transaction_histories(created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_ath_created;
DROP INDEX IF EXISTS idx_ath_to_account;
DROP INDEX IF EXISTS idx_ath_from_account;
DROP INDEX IF EXISTS idx_ath_user;
DROP INDEX IF EXISTS idx_ath_account;
DROP INDEX IF EXISTS idx_ath_transaction;
DROP TABLE IF EXISTS account_transaction_histories;
ALTER TABLE account_transactions DROP COLUMN IF EXISTS description;
