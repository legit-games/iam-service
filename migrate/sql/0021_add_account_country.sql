-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Add country column to accounts table (ISO 3166-1 alpha-2 country code)
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS country VARCHAR(2);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

ALTER TABLE accounts DROP COLUMN IF EXISTS country;
