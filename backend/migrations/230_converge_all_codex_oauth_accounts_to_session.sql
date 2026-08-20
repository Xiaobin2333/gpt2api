-- Converge every existing OpenAI OAuth account to the session identity profile once.
-- Existing canonical seeds are preserved so upgrades do not rotate account identity.
UPDATE accounts
SET extra = jsonb_set(
    jsonb_set(
        CASE
            WHEN jsonb_typeof(extra) = 'object' THEN extra
            ELSE '{}'::jsonb
        END,
        '{codex_fingerprint_mode}',
        to_jsonb('session'::text),
        true
    ),
    '{codex_fingerprint_seed}',
    CASE
        WHEN extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
        THEN to_jsonb(extra->>'codex_fingerprint_seed')
        ELSE to_jsonb(gen_random_uuid()::text)
    END,
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth';
