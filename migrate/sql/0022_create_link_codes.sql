-- +goose Up
CREATE TABLE IF NOT EXISTS link_codes (
    id VARCHAR(255) PRIMARY KEY,
    code VARCHAR(8) NOT NULL UNIQUE,
    headless_account_id VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_by VARCHAR(255),
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_link_codes_code ON link_codes(code);
CREATE INDEX idx_link_codes_headless_account ON link_codes(headless_account_id, namespace);
CREATE INDEX idx_link_codes_expires ON link_codes(expires_at) WHERE used = FALSE;

-- +goose Down
DROP TABLE IF EXISTS link_codes;
