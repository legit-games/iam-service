-- +goose Up
-- Create ban tables for namespace-scoped user bans and audit history.

CREATE TABLE IF NOT EXISTS user_bans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('PERMANENT','TIMED')),
    reason TEXT,
    until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_bans_user_ns ON user_bans(user_id, namespace);

CREATE TABLE IF NOT EXISTS user_ban_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('BAN','UNBAN')),
    type TEXT,
    reason TEXT,
    until TIMESTAMP,
    actor_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_ban_hist_user_ns ON user_ban_history(user_id, namespace);

-- Account-level ban tables
CREATE TABLE IF NOT EXISTS account_bans (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('PERMANENT','TIMED')),
    reason TEXT,
    until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_account_bans_account ON account_bans(account_id);

CREATE TABLE IF NOT EXISTS account_ban_history (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('BAN','UNBAN')),
    type TEXT,
    reason TEXT,
    until TIMESTAMP,
    actor_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_account_ban_hist ON account_ban_history(account_id);

-- +goose Down
DROP INDEX IF EXISTS idx_account_ban_hist;
DROP INDEX IF EXISTS idx_account_bans_account;
DROP TABLE IF EXISTS account_ban_history;
DROP TABLE IF EXISTS account_bans;
DROP INDEX IF EXISTS idx_user_ban_hist_user_ns;
DROP INDEX IF EXISTS idx_user_bans_user_ns;
DROP TABLE IF EXISTS user_ban_history;
DROP TABLE IF EXISTS user_bans;
