# clavenar-go-sdk

[![CI](https://github.com/clavenar/clavenar-go-sdk/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/clavenar/clavenar-go-sdk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/clavenar/clavenar-go-sdk.svg)](https://pkg.go.dev/github.com/clavenar/clavenar-go-sdk)

Go SDK for [Clavenar](https://clavenar.com). Inspect the tool calls a
model emits against your policies *before* your agent runs them.

Part of the by-language agent-wrapper SDK family alongside
[`@clavenar/agent-sdk`](https://github.com/clavenar/clavenar-typescript-sdk)
(TypeScript) and
[`clavenar-agent-sdk`](https://github.com/clavenar/clavenar-python-sdk)
(Python) — all speak the same wire contract.

## Install

```bash
go get github.com/clavenar/clavenar-go-sdk@latest
```

The core package has **no provider dependency**. Provider adapters are
opt-in sub-modules:

```bash
go get github.com/clavenar/clavenar-go-sdk/adapters/anthropic@latest
go get github.com/clavenar/clavenar-go-sdk/adapters/openai@latest
```

## Two ways to integrate

Go favors explicit over magic, so there is no transparent client proxy
(as in the TS / Python SDKs). Instead:

### 1. Wrap the tool dispatcher (provider-agnostic)

Build `clavenar.ToolCall` values from whatever your framework hands you,
and inspect before dispatch:

```go
opts := clavenar.New("http://localhost:8088", clavenar.WithToken(token))

calls := []clavenar.ToolCall{
    {ID: "call_1", Name: "delete_user", Input: json.RawMessage(`{"user":"alice"}`)},
}
err := clavenar.InspectAll(ctx, calls, opts)

var denied *clavenar.Denied
if errors.As(err, &denied) {
    log.Printf("blocked %s: %v", denied.ToolName, denied.Reasons)
    return
}
// err == nil -> every call cleared; dispatch them.
```

### 2. Wrap the model client (provider adapters)

```go
import (
    anthropic "github.com/anthropics/anthropic-sdk-go"
    clavenar "github.com/clavenar/clavenar-go-sdk"
    clavenaranthropic "github.com/clavenar/clavenar-go-sdk/adapters/anthropic"
)

base := anthropic.NewClient()
messages := clavenaranthropic.WrapMessages(&base, clavenar.New("http://localhost:8088"))

msg, err := messages.New(ctx, params) // err is *clavenar.Denied on a policy block
```

OpenAI is the same shape:
`clavenaropenai.WrapCompletions(&base, opts)` then `completions.New(ctx, params)`.

## Verdicts and the error model

`clavenar.Inspect` returns a `Verdict` whose `Kind` is `VerdictAllow`,
`VerdictDeny`, `VerdictPending`, or `VerdictRateLimited`. Every request
explicitly selects the side-effect-free `clavenar.decision/v1` contract with
a UUID allocated before the first attempt. `InspectAll` sends multi-tool turns
as one ordered atomic decision. It and the adapter facades translate, in enforce mode, into typed errors
you match with `errors.As`:

| Error | Meaning |
|---|---|
| `*clavenar.Denied` | policy rejected the call — `ToolName`, `Reasons`, `ReviewReasons`, `IntentCategory`, `Layer`, `CorrelationID` |
| `*clavenar.Pending` | parked for human review — call `Resolve(ctx, nil)` to block until an operator decides |
| `*clavenar.RateLimited` | rejected before evaluation by the velocity or spend gate — `Code` (`rate_limited` / `quota_exceeded`), `Reasons`, `RetryAfterSecs` (nil on `quota_exceeded`), `Layer`, `CorrelationID`; never retried by the transport |
| `*clavenar.TransportError` | clavenar unreachable or returned an unexpected response — `Status` (0 = network) |
| `*clavenar.ConfigError` | bad options, or a model tool call with unparseable arguments |

## Debugging a denied call

`*clavenar.Denied` carries `Reasons`, `Layer`, and `CorrelationID`. To see
*which detector* fired, run the gateway with
`CLAVENAR_PROXY_VERBOSE_VERDICTS=true` (Lite: `--verbose-verdicts`) — the
deny then carries a per-detector `Detail` breakdown, exposed as
`denied.Detail` and rendered to stderr when you set `DevMode: true`:

```go
messages := clavenaranthropic.WrapMessages(&base, clavenar.Options{
    Endpoint: "https://clavenar.internal",
    DevMode:  true, // dev/staging only — detailed denials are an attacker oracle
})
// On a deny, the SDK prints a panel to stderr:
//   ━━ clavenar denied: send_email ━━
//     layer=brain  intent=Exfiltration  correlation=abc-123
//     detectors:
//       persona_drift         0.12
//       injection             0.91  ⚠ flagged
//     degraded: injection
```

Programmatic access (no `DevMode` needed):

```go
var denied *clavenar.Denied
if errors.As(err, &denied) && denied.Detail != nil {
    for _, d := range denied.Detail.Detectors {
        if d.Flagged || d.Score >= 0.5 {
            log.Printf("fired: %s (%.2f)", d.Detector, d.Score)
        }
    }
}
```

`Detail` is nil unless the gateway opts in; without it the panel prints a
hint. `clavenar.RenderDenyPanel(denied)` returns the string directly.

## Enforce vs observe

The default is enforce: deny and pending block. Observe never blocks —
verdicts surface via callbacks and every call passes through, the rollout
knob for tuning policies against live traffic:

```go
opts := clavenar.New(endpoint,
    clavenar.WithObserve(),
    clavenar.WithOnVerdict(func(v clavenar.Verdict, c clavenar.VerdictContext) error {
        log.Printf("%s -> %s", c.ToolName, v.Kind)
        return nil
    }),
)
```

## Pending review

```go
var pending *clavenar.Pending
if errors.As(err, &pending) {
    if err := pending.Resolve(ctx, nil); err != nil {
        // *clavenar.Denied (operator denied) or *clavenar.TransportError (timed out)
        return
    }
    // approved — re-dispatch the tool call
}
```

## Streaming

The adapters gate streaming responses: the closing event for a tool call
(Anthropic `content_block_stop`, the OpenAI `finish_reason:"tool_calls"`
chunk) is held until clavenar returns a verdict, so a denied call never
reaches your loop as actionable. See [`docs/SEQUENCES.md`](docs/SEQUENCES.md).

## Examples

[`examples/`](examples) — native Anthropic, native OpenAI, a
provider-agnostic custom dispatcher, and OpenAI Realtime.

## Behavior parity

This SDK matches the TypeScript reference 1:1 on the wire. See
[`docs/PARITY.md`](docs/PARITY.md) for the behavior map and the
(additive, Go-idiom) differences.

## License

[Apache-2.0](LICENSE).
