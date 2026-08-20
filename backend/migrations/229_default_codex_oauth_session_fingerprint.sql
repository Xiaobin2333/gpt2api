-- Default legacy OpenAI OAuth accounts to stable device + root-session convergence.
-- Explicit off/device/session/full selections remain authoritative.
WITH candidates AS (
    SELECT
        id,
        CASE
            WHEN jsonb_typeof(extra) = 'object' THEN extra
            ELSE '{}'::jsonb
        END AS base_extra
    FROM accounts
    WHERE deleted_at IS NULL
      AND platform = 'openai'
      AND type = 'oauth'
      AND COALESCE(btrim(extra->>'codex_fingerprint_mode'), '') NOT IN ('off', 'device', 'session', 'full')
)
UPDATE accounts AS account
SET extra = jsonb_set(
    jsonb_set(
        candidates.base_extra,
        '{codex_fingerprint_mode}',
        to_jsonb('session'::text),
        true
    ),
    '{codex_fingerprint_seed}',
    CASE
        WHEN candidates.base_extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND candidates.base_extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
        THEN to_jsonb(candidates.base_extra->>'codex_fingerprint_seed')
        ELSE to_jsonb(gen_random_uuid()::text)
    END,
    true
)
FROM candidates
WHERE account.id = candidates.id;

-- Keep the migration self-contained for databases that skipped an older seed backfill.
UPDATE accounts
SET extra = jsonb_set(
    CASE
        WHEN jsonb_typeof(extra) = 'object' THEN extra
        ELSE '{}'::jsonb
    END,
    '{codex_fingerprint_seed}',
    to_jsonb(gen_random_uuid()::text),
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
  AND COALESCE(extra->>'codex_fingerprint_mode', '') IN ('device', 'session', 'full')
  AND (
      extra->>'codex_fingerprint_seed' IS NULL
      OR btrim(extra->>'codex_fingerprint_seed') = ''
      OR NOT (
          extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
      )
  );
