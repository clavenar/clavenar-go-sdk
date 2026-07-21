# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and the project
adheres to [Semantic Import Versioning](https://go.dev/ref/mod#versions).

## [Unreleased]

## [1.1.0] - 2026-07-21

### Added

- Governed execution with serializable prepared requests, a registered
  executor, durable intent/completion store, workload receipt signer, and
  actual provider-result return.
- The shared `clavenar.sdk-cross-language/v1` conformance fixture.

### Changed

- `Inspect` explicitly selects `clavenar.decision/v1` with a UUID allocated
  before the first attempt and retained across safe retries. `InspectAll`
  submits multi-tool turns through one ordered atomic-batch decision.

### Added

- 429 rate-limit verdicts (spec §"Agent-facing error envelope"):
  `Inspect` parses the 429 envelope into `VerdictRateLimited` —
  `RateLimitCode` (`rate_limited` / `quota_exceeded`), `Reasons`,
  optional `RetryAfterSecs` — and never retries it. In enforce mode
  `InspectAll`, `StreamGate`, and the adapters return the new
  `*RateLimited` error; observe mode surfaces the verdict via
  `OnVerdict` and passes the call through.

## [1.0.0]

Initial release. Go port of the Clavenar agent-wrapper SDK, behavior-
compatible with `@clavenar/agent-sdk` (TypeScript) and
`clavenar-agent-sdk` (Python) on the wire.

### Added

- Core package `github.com/clavenar/clavenar-go-sdk` (no provider
  dependency): `Inspect`, `InspectAll`, `PollPendingOnce`, the `Verdict`
  / `ToolCall` / `Options` types, the `Denied` / `Pending` /
  `ConfigError` / `TransportError` errors, `Pending.Resolve`, the
  `StreamGate` streaming primitive, and the Realtime helper.
- Enforce / observe modes with `OnVerdict` / `OnPolicyError` callbacks,
  retries with full-jitter backoff, and `context.Context` cancellation
  throughout.
- Opt-in provider adapters: `adapters/anthropic` (anthropic-sdk-go) and
  `adapters/openai` (openai-go v2), each with explicit inspectors, a
  wrap-and-forget facade, and a streaming gate.

### Notes

- Matches the TypeScript reference where the TS and Python SDKs diverge:
  an OpenAI non-streaming tool call with unparseable `arguments` is a
  `ConfigError`. See `docs/PARITY.md`.
- The module path stays unversioned for v1; a future v2 will require the
  `/v2` import suffix.
