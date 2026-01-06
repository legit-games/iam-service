-- +goose Up
-- Create platform_clients table to store OAuth client configurations for third-party platforms.
CREATE TABLE IF NOT EXISTS platform_clients (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    secret TEXT,
    redirect_uri TEXT,
    app_id TEXT,
    environment TEXT NOT NULL DEFAULT 'prod',
    platform_name TEXT,
    type TEXT,
    sso_url TEXT,
    organization_id TEXT,
    federation_metadata_url TEXT,
    acs_url TEXT,
    key_id TEXT,
    team_id TEXT,
    generic_oauth_flow BOOLEAN NOT NULL DEFAULT FALSE,
    authorization_endpoint TEXT,
    token_endpoint TEXT,
    userinfo_endpoint TEXT,
    scopes TEXT,
    jwks_endpoint TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_platform_clients_namespace ON platform_clients(namespace);
CREATE INDEX IF NOT EXISTS idx_platform_clients_platform_id ON platform_clients(platform_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_client_lookup ON platform_clients(namespace, platform_id);

-- +goose Down
DROP INDEX IF EXISTS idx_platform_client_lookup;
DROP INDEX IF EXISTS idx_platform_clients_platform_id;
DROP INDEX IF EXISTS idx_platform_clients_namespace;
DROP TABLE IF EXISTS platform_clients;
