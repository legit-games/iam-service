-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Create PUBLISHER namespace if it doesn't exist
INSERT INTO namespaces (id, name, type, description)
VALUES ('ns-publisher-001', 'PUBLISHER', 'publisher', 'Publisher Namespace')
ON CONFLICT (name) DO NOTHING;

-- Create admin-console OAuth client for admin console (public client with PKCE)
-- domain should match the redirect_uri origin
INSERT INTO oauth2_clients (id, secret, domain, user_id, public, permissions, scopes, namespace)
VALUES (
    'admin-console',
    '',
    'http://localhost:9096',
    NULL,
    TRUE,
    '["ADMIN:NAMESPACE:*"]'::jsonb,
    '["admin", "openid", "profile", "namespace:read", "namespace:write", "namespace:admin", "client:read", "client:write", "client:admin", "user:read", "user:write", "user:admin", "account:read", "account:write", "account:admin", "role:read", "role:write", "role:admin", "platform:read", "platform:write", "platform:admin"]'::jsonb,
    'PUBLISHER'
)
ON CONFLICT (id) DO UPDATE SET
    domain = EXCLUDED.domain,
    public = EXCLUDED.public,
    permissions = EXCLUDED.permissions,
    scopes = EXCLUDED.scopes,
    namespace = EXCLUDED.namespace,
    updated_at = CURRENT_TIMESTAMP;

-- Create admin account if not exists (password: admin123)
-- bcrypt hash of 'admin123' with cost 10
INSERT INTO accounts (id, username, password_hash, account_type)
VALUES (
    'admin-account-001',
    'admin',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.rF/YY1c.rPABQkJAi2',
    'HEAD'
)
ON CONFLICT (username) DO NOTHING;

-- Create admin user (HEAD type, no namespace for head users)
INSERT INTO users (id, account_id, namespace, user_type)
VALUES (
    'admin-user-001',
    'admin-account-001',
    NULL,
    'HEAD'
)
ON CONFLICT (id) DO NOTHING;

-- Create admin role with full permissions
INSERT INTO roles (id, namespace, name, role_type, permissions)
VALUES (
    'role-admin-001',
    'PUBLISHER',
    'admin',
    'USER',
    '["ADMIN:NAMESPACE:*"]'::jsonb
)
ON CONFLICT (id) DO NOTHING;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DELETE FROM roles WHERE id = 'role-admin-001';
DELETE FROM users WHERE id = 'admin-user-001';
DELETE FROM accounts WHERE id = 'admin-account-001';
DELETE FROM oauth2_clients WHERE id = 'admin-console';
DELETE FROM namespaces WHERE id = 'ns-publisher-001';
