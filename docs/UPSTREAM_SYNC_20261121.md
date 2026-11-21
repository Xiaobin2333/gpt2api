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
  configuration is rotated by this change.
- The private Docker workflow remains self-hosted and `linux/amd64` only.

## Codex transport verification

On 2026-11-21 the official Linux x86_64 musl `codex-cli 0.171.0` completed
both a Responses SSE turn and a WebSocket `response.create` turn against an
isolated loopback TLS server. The executable from `@openai/codex@0.171.0-linux-x64`
had SHA-256 `b76a027d6b210f9a8da7aaf321dd235c700f0ef7a794d4a5314b9af6c134f0f0`.
Both negotiated TLS 1.3. With the test CA in
the system trust store and no CA environment override, the gateway dialers
matched the CLI's stable ClientHello fields: version, session ID length,
cipher suites, compression, and extension values (key shares compared by group
and length). HTTP extension order also matched; WSS order varies by design.
No handshake parameters changed. With an explicit CA override the CLI's HTTPS
ClientHello differed, so the default profile does not describe that mode. No
production accounts or upstream model entitlements were exercised.
