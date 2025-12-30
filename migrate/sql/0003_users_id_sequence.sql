-- +goose Up
-- Ensure Postgres users.id autoincrements via sequence
CREATE SEQUENCE IF NOT EXISTS users_id_seq START 1 OWNED BY users.id;
ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq');

-- +goose Down
ALTER TABLE users ALTER COLUMN id DROP DEFAULT;
DROP SEQUENCE IF EXISTS users_id_seq;
