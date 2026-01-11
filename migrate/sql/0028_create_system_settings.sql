-- +goose Up
-- System settings table for storing configurable settings like email, etc.
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL DEFAULT 'general',
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_system_settings_category ON system_settings(category);

-- Insert default email settings
INSERT INTO system_settings (key, value, description, category, is_secret) VALUES
    ('email.provider', 'console', 'Email provider: console, smtp', 'email', false),
    ('email.smtp.host', '', 'SMTP server host', 'email', false),
    ('email.smtp.port', '587', 'SMTP server port', 'email', false),
    ('email.smtp.username', '', 'SMTP username', 'email', false),
    ('email.smtp.password', '', 'SMTP password', 'email', true),
    ('email.smtp.from_address', '', 'Sender email address', 'email', false),
    ('email.smtp.from_name', 'OAuth2 Service', 'Sender display name', 'email', false),
    ('email.smtp.use_tls', 'true', 'Use STARTTLS', 'email', false),
    ('email.smtp.use_ssl', 'false', 'Use implicit SSL (port 465)', 'email', false),
    ('email.smtp.skip_verify', 'false', 'Skip TLS certificate verification', 'email', false),
    ('email.app_name', 'OAuth2 Service', 'Application name shown in emails', 'email', false),
    ('email.support_email', '', 'Support email shown in emails', 'email', false)
ON CONFLICT (key) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS system_settings;
