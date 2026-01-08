-- +goose Up
-- Create account_users bridge table to link accounts and users

-- Step 1: Create the bridge table
CREATE TABLE IF NOT EXISTS account_users (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_account_users_account_id ON account_users(account_id);
CREATE INDEX IF NOT EXISTS idx_account_users_user_id ON account_users(user_id);

-- Step 2: Migrate existing data from users.account_id to account_users
INSERT INTO account_users (account_id, user_id, created_at)
SELECT account_id, id, created_at FROM users WHERE account_id IS NOT NULL;

-- Step 3: Drop account_id column from users table
ALTER TABLE users DROP COLUMN account_id;

-- +goose Down
-- Reverse the migration

-- Step 1: Add account_id column back to users table
ALTER TABLE users ADD COLUMN account_id TEXT;

-- Step 2: Migrate data back from account_users to users.account_id
UPDATE users SET account_id = (
    SELECT au.account_id FROM account_users au WHERE au.user_id = users.id LIMIT 1
);

-- Step 3: Drop account_users table
DROP TABLE IF EXISTS account_users;
