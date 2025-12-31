-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Accounts table for API login, with TEXT id for hyphenless UUID identifiers.
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP INDEX IF EXISTS idx_accounts_username;
DROP TABLE IF EXISTS accounts;
