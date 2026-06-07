# native-anthropic

Wrap an `anthropic-sdk-go` client so every `tool_use` Claude emits is
inspected before `messages.New` returns. The load-bearing lines:

```go
messages := clavenaranthropic.WrapMessages(&base, clavenar.New(endpoint))
msg, err := messages.New(ctx, params) // err is *clavenar.Denied on a policy block
```

```bash
ANTHROPIC_API_KEY=... CLAVENAR_ENDPOINT=http://localhost:8088 go run .
```
