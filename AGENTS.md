<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-go-sdk — agent-side wrapper SDK: explicit `Inspect`/`InspectAll` + opt-in provider adapters

Inspects the tool calls a model emits against your Clavenar policies
*before* your agent runs them. Zero-dep core (stdlib + `golang.org/x/sync`
only); provider SDKs live behind opt-in `adapters/*` sub-modules. Matches
the TypeScript / Python agent-SDKs 1:1 on the wire.

## Build, test, lint

Multi-module repo — run each command **per module**. Modules:
`.` (core), `adapters/anthropic`, `adapters/openai`, `examples`.

```
go build ./...
go test -race -count=1 ./...
gofmt -l .            # must print nothing
go vet ./...
golangci-lint run ./...   # golangci-lint v2 (.golangci.yaml)
govulncheck ./...
```

From an adapter/examples module, `cd adapters/anthropic && go test -race ./...`.
Adapters and `examples` use `replace` directives onto the local core
(`../..`), so a core API change must keep **every** module building —
build all four before you push. CI runs the core on the go 1.22/1.23/1.24
matrix; `examples` is build-only.

Run: library, no binary. The SDK is an HTTP client of a Clavenar gateway
(e.g. clavenar-lite) — `POST {endpoint}/mcp` for inspect, `GET
{endpoint}/pending/{id}` for pending resolve. Examples target
`http://localhost:8088`. Public entry: `clavenar.Inspect` /
`clavenar.InspectAll` (core), `clavenaranthropic.WrapMessages` /
`clavenaropenai.WrapCompletions` (adapters).

## Layout

Import path ends `clavenar-go-sdk`; package name is `clavenar`.

- `inspect.go` — `InspectAll` (batch, concurrent via `errgroup`).
- `transport.go` — `Inspect` (single), JSON-RPC envelope, `POST /mcp`, status→verdict mapping, jittered retry.
- `toolcall.go` — `ToolCall` normalization (the provider-agnostic unit of inspection).
- `options.go` — `Options`, `New(endpoint, ...Option)`, `WithToken` / `WithObserve` / `WithOnVerdict` / `WithOnPolicyError` / `WithRetry` / `WithTimeout`.
- `errors.go` — typed errors `*Denied` / `*Pending` / `*TransportError` / `*ConfigError`; `Pending.Resolve` polls `/pending/{id}`.
- `streamgate.go` — `StreamGate`: holds a tool-call's closing event until the verdict returns.
- `realtime.go` — `InspectRealtimeFunctionCall` one-shot helper for OpenAI Realtime WS events.
- `devmode.go` — `RenderDenyPanel` / stderr deny panel (gated on `DevMode`).
- `doc.go` — package doc.
- `adapters/anthropic/anthropic.go` — `WrapMessages` (response → `[]ToolCall` → gate).
- `adapters/openai/openai.go` — `WrapCompletions`.
- `examples/{custom-dispatcher,native-anthropic,native-openai,realtime}` — runnable integrations.
- `docs/SEQUENCES.md` (wire paths) · `docs/PARITY.md` (TS parity map).

## Conventions & invariants

- After adding or updating a feature, also update the relevant `MANUAL_TESTS*` file(s) when needed.
- **Inspect before dispatch — always.** The SDK exists so no model-emitted tool call runs un-inspected. Build `ToolCall` values and clear them through `Inspect`/`InspectAll` (or an adapter) ahead of execution; never run a call you haven't gated.
- **Zero-dep core.** The root module depends only on the stdlib + `golang.org/x/sync`. Provider SDKs belong in `adapters/*` only — never add an `anthropic`/`openai` import to the core module.
- **Fail closed.** In enforce mode an unreachable gateway returns `*TransportError`, never a silent allow. Observe mode never blocks: per-call transport errors fire `OnPolicyError` and the call passes.
- **Submission-order semantics.** `InspectAll` fans out concurrently but returns the first deny/pending in `calls[]` order, not wire order. `OnVerdict` fires per call before any deny→error translation.
- **Explicit over magic.** Go has no transparent client proxy (unlike TS/Python). Wrap the dispatcher or wrap the model client via an adapter.
- **DevMode is an attacker oracle.** Detailed per-detector denials (`DevMode: true`, gateway `CLAVENAR_PROXY_VERBOSE_VERDICTS=true`) leak which detector fired — dev/staging only, never enforce-prod.
- **Streaming gate.** Adapters hold the closing event (Anthropic `content_block_stop`, OpenAI `finish_reason:"tool_calls"`) until the verdict lands, so a denied call never reaches your loop as actionable.

Go standards that bind here:
- `gofmt -l .` must be empty and `go vet ./...` clean before pushing.
- `golangci-lint run` (v2; `.golangci.yaml` enables `gocritic`, `misspell`, `revive`, `unconvert`) passes on core + both adapters. Fix the code; don't `//nolint` to silence.
- `govulncheck ./...` clean on every module.
- Tests are `*_test.go` beside the code; run with `-race -count=1`.
- Doc comments are prose (package doc in `doc.go`); keep exported types behavior-compatible with the TS/Python SDKs — see `docs/PARITY.md` before changing wire behavior.
- Commit subjects must start with a lowercase letter.

## Pointers

README.md · SECURITY.md · CONTRIBUTING.md · CHANGELOG.md · docs/SEQUENCES.md · docs/PARITY.md
