-- +goose Up
-- Consolidated OAuth2 clients schema with 'name' column.
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    domain TEXT NOT NULL,
    user_id TEXT,
    name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE IF EXISTS oauth2_clients;

