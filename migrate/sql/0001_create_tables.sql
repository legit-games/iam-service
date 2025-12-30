-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- PostgreSQL schema for storing OAuth2 tokens and clients.

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    domain TEXT NOT NULL,
    user_id TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth2_tokens (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT,
    access TEXT NOT NULL,
    refresh TEXT,
    scope TEXT,
    access_created_at TIMESTAMP NOT NULL,
    access_expires_in INTEGER NOT NULL,
    refresh_created_at TIMESTAMP,
    refresh_expires_in INTEGER,
    code TEXT,
    code_created_at TIMESTAMP,
    code_expires_in INTEGER,
    payload TEXT,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id)
);

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_access ON oauth2_tokens(access);
CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_refresh ON oauth2_tokens(refresh);
CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_code ON oauth2_tokens(code);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP TABLE IF EXISTS oauth2_tokens;
DROP TABLE IF EXISTS oauth2_clients;
