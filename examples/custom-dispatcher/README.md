# custom-dispatcher

The provider-agnostic pattern — no provider SDK dependency. Build
`clavenar.ToolCall` values from your framework's tool-dispatch boundary
and inspect them before running the tools:

```go
err := clavenar.InspectAll(ctx, calls, opts)
// errors.As(err, &denied) / &pending, or nil to dispatch
```

This is the recommended shape for framework integrations (langchaingo,
custom tool loops). Pending verdicts expose `Resolve` to block on a
human approval.

```bash
CLAVENAR_ENDPOINT=http://localhost:8088 go run .
```
