-- +goose Up
-- Add MERGE action to account_transactions action check constraint

ALTER TABLE account_transactions DROP CONSTRAINT IF EXISTS account_transactions_action_check;

ALTER TABLE account_transactions ADD CONSTRAINT account_transactions_action_check
    CHECK (action IN ('LINK','UNLINK','CREATE_HEAD','CREATE_HEADLESS','ORPHAN','SET_FULL','SET_HEAD','SET_HEADLESS','MERGE'));

-- +goose Down
-- Revert to original constraint without MERGE

ALTER TABLE account_transactions DROP CONSTRAINT IF EXISTS account_transactions_action_check;

ALTER TABLE account_transactions ADD CONSTRAINT account_transactions_action_check
    CHECK (action IN ('LINK','UNLINK','CREATE_HEAD','CREATE_HEADLESS','ORPHAN','SET_FULL','SET_HEAD','SET_HEADLESS'));
