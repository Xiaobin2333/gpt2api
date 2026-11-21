# Upstream sync, 2026-11-21

Merged `Wei-Shaw/sub2api` `328db26f4` (v0.2.24) into private main at
`254e8b5fa`. Both histories are retained.

- Simple mode: a key with an explicit group queries that group directly, even
  when a wider snapshot is warm. A key without a group retains the default pool.
  The stored pool includes temporarily blocked accounts, but the returned
  schedulable accounts exclude them. Prompt scanning keeps both the private
  threshold policy and upstream's UTF-8-safe chunking.
- Codex: the compiled client-version fallback is `0.171.0` (`rust-v0.171.0`,
  stable 2026-11-20). Disabling version sync ignores the old synced value; an
  explicit manual override still takes priority. Responses and WebSocket
  `response.create` support `prompt_cache_options.ttl` (`30m` or `12h`);
  compact does not. A downstream caller is not a trusted source for
  `request_country`, so provenance stays with the server.
- A Codex fork can share its parent's cache key while retaining a distinct
  body session in both HTTP forwarding modes. No persisted identity seed or
  configuration is rotated by this change. The existing TLS profiles retain
  the version of their original capture; they are not a new 0.171.0 capture.
- The private Docker workflow remains self-hosted and `linux/amd64` only.
