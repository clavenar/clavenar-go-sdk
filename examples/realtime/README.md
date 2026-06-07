# realtime

Gate OpenAI Realtime function calls. Inspect each
`response.function_call_arguments.done` event before dispatching the
tool from your websocket message pump:

```go
v, err := clavenar.InspectRealtimeFunctionCall(ctx, evt, opts)
// branch on v.Kind: VerdictAllow / VerdictDeny / VerdictPending
```

```bash
CLAVENAR_ENDPOINT=http://localhost:8088 go run .
```
