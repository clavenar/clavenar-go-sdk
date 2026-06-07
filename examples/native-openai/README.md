# native-openai

Wrap an `openai-go` client so every function tool call is inspected
before `chat.completions.New` returns.

```go
completions := clavenaropenai.WrapCompletions(&base, clavenar.New(endpoint))
res, err := completions.New(ctx, params) // err is *clavenar.Denied on a policy block
```

```bash
OPENAI_API_KEY=... CLAVENAR_ENDPOINT=http://localhost:8088 go run .
```
