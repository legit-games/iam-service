-- +goose Up
-- Remove link_history table - replaced by account_transaction_histories
DROP TABLE IF EXISTS link_history;

-- +goose Down
-- Recreate link_history table if rolling back
CREATE TABLE IF NOT EXISTS link_history (
    id VARCHAR(255) PRIMARY KEY,
    action VARCHAR(20) NOT NULL,
    head_account_id VARCHAR(255) NOT NULL,
    headless_account_id VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50),
    provider_account_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_link_history_head_account ON link_history(head_account_id);
CREATE INDEX idx_link_history_headless_account ON link_history(headless_account_id);
CREATE INDEX idx_link_history_namespace ON link_history(head_account_id, namespace);
CREATE INDEX idx_link_history_action ON link_history(action, created_at DESC);
