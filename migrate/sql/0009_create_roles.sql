-- +goose Up
-- Roles (namespace-scoped), user/client role types, JSONB permissions
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    role_type TEXT NOT NULL CHECK (role_type IN ('USER','CLIENT')),
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_ns_name_type ON roles(namespace, name, role_type);
CREATE INDEX IF NOT EXISTS idx_roles_ns ON roles(namespace);

-- Mapping: user to roles (must be same namespace at application layer)
CREATE TABLE IF NOT EXISTS user_roles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_roles_user_role ON user_roles(user_id, role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_ns ON user_roles(namespace);

-- Mapping: client to roles
CREATE TABLE IF NOT EXISTS client_roles (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_client_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_client_roles_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_client_roles_client_role ON client_roles(client_id, role_id);
CREATE INDEX IF NOT EXISTS idx_client_roles_role ON client_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_client_roles_ns ON client_roles(namespace);

-- +goose Down
DROP TABLE IF EXISTS client_roles;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;

