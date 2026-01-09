-- +goose Up
-- Create login_history table to track user login activity.
CREATE TABLE IF NOT EXISTS login_history (
    id VARCHAR(32) PRIMARY KEY,
    account_id VARCHAR(32) NOT NULL,
    login_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    failure_reason VARCHAR(255),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_login_history_account_id ON login_history(account_id);
CREATE INDEX IF NOT EXISTS idx_login_history_login_at ON login_history(login_at);

-- +goose Down
DROP INDEX IF EXISTS idx_login_history_login_at;
DROP INDEX IF EXISTS idx_login_history_account_id;
DROP TABLE IF EXISTS login_history;
