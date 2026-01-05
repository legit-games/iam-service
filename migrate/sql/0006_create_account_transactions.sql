-- +goose Up
-- Minimal transaction log for account link/unlink operations.
CREATE TABLE IF NOT EXISTS account_transactions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('LINK','UNLINK','CREATE_HEAD','CREATE_HEADLESS','ORPHAN','SET_FULL','SET_HEAD','SET_HEADLESS')),
    namespace TEXT,
    user_id TEXT,
    meta TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_account_transactions_account ON account_transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_account_transactions_action ON account_transactions(action);

-- +goose Down
DROP INDEX IF EXISTS idx_account_transactions_action;
DROP INDEX IF EXISTS idx_account_transactions_account;
DROP TABLE IF EXISTS account_transactions;

