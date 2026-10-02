-- NULL / [] retains the existing global scope. Account-scoped rules share
-- the same priority ordering and matching conditions as global rules.
ALTER TABLE error_passthrough_rules
    ADD COLUMN IF NOT EXISTS account_ids JSONB;
