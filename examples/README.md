# Examples

There are two ways to integrate clavenar, mirroring the TypeScript and
Python SDKs:

1. **Wrap the model client** — one line at boot, then call the provider
   API as usual. Every tool call the model emits is inspected before the
   response returns. See [`native-anthropic`](native-anthropic) and
   [`native-openai`](native-openai).
2. **Wrap the tool dispatcher** — build `clavenar.ToolCall` values from
   whatever your agent framework hands you and inspect them before
   dispatch. No provider SDK required. See
   [`custom-dispatcher`](custom-dispatcher).

Plus [`realtime`](realtime) for the OpenAI Realtime websocket surface.

Each example reads `CLAVENAR_ENDPOINT` (default `http://localhost:8088`,
a local [clavenar-lite](https://github.com/clavenar/clavenar-lite)) and
`CLAVENAR_LITE_TOKEN`. Run one with:

```bash
cd native-anthropic && go run .
```

This directory is its own Go module so the core SDK stays free of
provider dependencies.
