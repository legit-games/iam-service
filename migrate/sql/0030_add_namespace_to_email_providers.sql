-- +goose Up
-- Add namespace_id to email_providers table for namespace-scoped email configuration
ALTER TABLE email_providers ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(255);

-- Create index for namespace lookup
CREATE INDEX IF NOT EXISTS idx_email_providers_namespace ON email_providers(namespace_id);

-- Update unique constraint for default provider (one default per namespace)
DROP INDEX IF EXISTS idx_email_providers_default;
CREATE UNIQUE INDEX idx_email_providers_default ON email_providers(namespace_id, is_default) WHERE is_default = TRUE;

-- Update the console-dev provider to be global (null namespace means global/fallback)
UPDATE email_providers SET namespace_id = NULL WHERE id = 'console-dev';

-- +goose Down
DROP INDEX IF EXISTS idx_email_providers_default;
DROP INDEX IF EXISTS idx_email_providers_namespace;
ALTER TABLE email_providers DROP COLUMN IF EXISTS namespace_id;

-- Recreate original unique constraint
CREATE UNIQUE INDEX idx_email_providers_default ON email_providers(is_default) WHERE is_default = TRUE;
