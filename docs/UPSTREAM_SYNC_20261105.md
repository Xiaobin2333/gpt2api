# Upstream sync and Codex 0.166.0

Updated 2026-11-05. Upstream `Wei-Shaw/sub2api/main` is merged through
`876b96d20` (v0.2.19 plus subsequent fixes). The previous private main is
preserved as `backup/pre-upstream-sync-20261105`; no history is rewritten.

## Private behavior retained

- Explicit groups constrain scheduling in simple mode, including account
  rechecks and sticky-session selection.
- Prompt audit scope and cyber session blocking retain their group settings
  and shared-key/session isolation.
- Account-level error passthrough rules, database fields, migrations, and UI
  remain present.
- Device and session identity convergence keeps its existing persistent seed
  and deployment salt. Updating the version does not rotate these identities.
- OAuth expiry recovery retains the durable refresh marker, JWT expiry hint,
  expired-token rejection, distributed refresh lock, and scheduler recovery.
- Docker uses the self-hosted runner, linux/amd64 only, and persistent local
  BuildKit state. The remote CI and Security Scan workflows remain disabled.

## Codex compatibility

The [official Codex changelog](https://developers.openai.com/codex/changelog)
lists 0.166.0 as the latest stable CLI release, published 2026-10-29.
The compiled version, canonical UA and model-query version use this baseline
even when auto-sync is disabled and the stored synchronized version is older.
An explicit manual version override remains supported.

The release source still initializes the interactive CLI's embedded app server
with `client_name=codex-tui` (`tui/src/app_server_connection.rs`).
`app-server/src/startup_config.rs` sets both the originator and the
`(codex-tui; version)` UA suffix. This private canonical identity is retained
instead of adopting upstream's normalization of TUI identities to a bare CLI
UA. Upstream overload retry and pre-output event handling fixes are merged.

OAuth refresh JSON now carries the official `refresh_reason` values:
`proactive_expiry`, `scheduled`, `unauthorized_recovery`, or `forced`.
These describe the existing refresh trigger and do not alter refresh eligibility.
The new boolean `guardian_recorded_items` turn metadata survives sanitization
and follows the official serialization order. It is never synthesized;
transport-only routing affinity is not admitted into request metadata.

The official Linux musl 0.166.0 binary was run in disposable containers with a
placeholder key against a local TLS endpoint. HTTP cipher suites, extensions,
groups, key shares and signatures match the existing OpenSSL profile. WebSocket
cipher suites, groups, key shares and signatures match the existing rustls/aws-lc
profile; extension order is randomized. Neither advertises ALPN. Profile labels
and regression expectations now record 0.166.0 without inventing wire changes.

This validates the implemented Linux compatibility profile. It does not imply
byte-for-byte equivalence across all operating systems, optional features or
network policies, and does not exercise production OAuth credentials.
