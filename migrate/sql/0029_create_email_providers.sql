-- +goose Up
-- Email providers table for configuring multiple email service providers
CREATE TABLE IF NOT EXISTS email_providers (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,  -- smtp, sendgrid, aws_ses, mailgun, mailchimp
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,

    -- Common settings
    from_address VARCHAR(255) NOT NULL,
    from_name VARCHAR(255) NOT NULL DEFAULT 'OAuth2 Service',
    reply_to_address VARCHAR(255),

    -- Provider-specific configuration (stored as JSON)
    config JSONB NOT NULL DEFAULT '{}',

    -- Email template settings
    app_name VARCHAR(255) NOT NULL DEFAULT 'OAuth2 Service',
    support_email VARCHAR(255),

    -- Metadata
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_providers_type ON email_providers(provider_type);
CREATE INDEX idx_email_providers_active ON email_providers(is_active) WHERE is_active = TRUE;
CREATE UNIQUE INDEX idx_email_providers_default ON email_providers(is_default) WHERE is_default = TRUE;

-- Insert a default console provider for development
INSERT INTO email_providers (id, name, provider_type, is_active, is_default, from_address, from_name, config, description)
VALUES (
    'console-dev',
    'Console (Development)',
    'console',
    TRUE,
    TRUE,
    'noreply@localhost',
    'OAuth2 Service',
    '{}',
    'Development provider that prints emails to console'
) ON CONFLICT (id) DO NOTHING;

-- Remove old system_settings email entries (migrating to new provider system)
DELETE FROM system_settings WHERE key LIKE 'email.%';

-- +goose Down
DROP TABLE IF EXISTS email_providers;

-- Restore system_settings email entries
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
