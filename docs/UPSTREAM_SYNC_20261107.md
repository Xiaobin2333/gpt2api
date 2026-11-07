# Upstream sync: sub2api v0.2.20

Updated 2026-11-07. Merge `Wei-Shaw/sub2api/main` through
`6b4b37db43443b5e88e424fe3c69602cc3810dfb` (v0.2.20). The previous private
main, `6b169abbc31785ea344be79f1f337ff99d74b76a`, is retained as
`backup/pre-upstream-sync-20261107`. History is not rewritten.

## Changes and merge decisions

- Includes upstream request-body budgets and read/write deadlines, bounded
  SSE queues and events, background-worker limits, JSON parsing optimizations,
  GPT Image 2.6 support, GPT-6.1 Terra metadata and compatibility fixes, and
  provider usage/response fixes.
- Adopts the upstream cyber transcript store's recorded prefix lengths and
  exact-prefix helpers. Runtime blocking retains the private explicit-session
  policy: shared API keys, IPs, user agents and transcript templates never
  establish user identity. Existing transcript-only entries are not consulted.
  Per-group overrides and compaction exclusions remain active.
- The new upstream 413 passthrough branch uses the private account-aware rule
  matcher. Rules apply to the selected account, including failover attempts;
  unrelated accounts retain the built-in response.
- The WebSocket-to-HTTP bridge preserves the identity already staged by WS
  ingress, avoiding derivation from an already rewritten session ID. Direct
  bridge calls use the private body-aware device/session resolver. Existing
  device seeds and deployment salt remain unchanged.
- Retains the compiled Codex 0.166.0 baseline and interactive CLI identity,
  Linux HTTP/WS TLS profiles, auto-sync-off fallback, refresh reasons and
  guardian metadata support from the previous sync.
- Retains simple-mode group scheduling and account rechecks, prompt-audit
  group scope, account-level error passthrough schema/UI, and OAuth expiry
  recovery (JWT/credential expiry, durable 401 refresh marker, locked refresh,
  rejection of expired tokens and scheduler cooldown recovery).
- Docker workflow remains self-hosted, linux/amd64 only, with persistent local
  BuildKit cache. Remote CI and Security Scan remain disabled.

## Validation

- Final full backend unit and integration runs passed (`go test -tags=unit
  ./...`, `go test -tags=integration ./...`, with bounded parallelism).
- Frontend: 385 test files / 3093 tests passed; Vue/TypeScript checking, Vite
  production build and ESLint passed. Docker runtime resources check passed.
- Added regressions cover account-scoped 413 responses, group-specific block
  reads/writes, shared-key long transcripts, body-only bridge sessions and
  preservation of an already converged WS frame. Bridge assertions use the
  existing official `session-id` header and installation metadata in the body,
  rather than upstream's legacy header expectations.
- The first integration run had an intermittent process-wide allocation-count
  assertion in `TestOpenAIResponsesOrphanPrecheckLargeEscapedContent`. It passed
  20 isolated repetitions and the final full integration run, without changing
  that test or production implementation.
- Validation uses test fixtures and isolated dependencies, not production
  OAuth credentials; this sync does not restart the production deployment.
