# Sequences

How the SDK behaves on each wire path. The SDK is a client of
[clavenar-lite](https://github.com/clavenar/clavenar-lite)'s
`POST /mcp` + `GET /pending/{id}` surface.

## Single inspect — `clavenar.Inspect`

1. Marshal the JSON-RPC envelope `{jsonrpc,method:"tools/call",params:{name,arguments},id}`.
2. `POST {endpoint}/mcp` with a per-request timeout (default 10s) derived
   from the caller's `ctx`.
3. Map the response: `200` → allow (read `X-Clavenar-Correlation-Id`),
   `403` → deny (normalize the envelope), `202` → pending
   (`correlationId = header ?? body`), anything else → transport error.
4. On a network error or 5xx, retry up to `MaxAttempts` with full-jitter
   backoff. `200` / `403` / other `4xx` never retry.

`Inspect` never blocks on a deny; it returns a `Verdict` and the caller
decides.

## Batch inspect — `clavenar.InspectAll`

1. Fan out one `Inspect` per call via `errgroup` (concurrent).
2. Consume results in **submission order** — the first deny in `calls[]`
   is the one returned, regardless of wire-order.
3. `OnVerdict` fires per call before any deny→error translation.
4. Enforce: first `Deny` → `*Denied`, first `Pending` → `*Pending`; a
   transport error fails closed and cancels the remaining inspections.
   Observe: nothing blocks; a per-call transport error fires
   `OnPolicyError` and the call is treated as allowed.

## Streaming gate — adapters

The adapter reads the provider stream on one goroutine and drives a
`clavenar.StreamGate`:

1. Tool-call opening → `gate.Start(key, id, name)`.
2. Argument fragments → `gate.Update(key, …)`.
3. The closing event (Anthropic `content_block_stop`, the OpenAI
   `finish_reason:"tool_calls"` chunk) → `gate.Close` / `CloseByPrefix`
   **before** the event is forwarded downstream. The gate assembles the
   buffered call(s) and runs `InspectAll`.
4. On an enforce-mode deny the gate returns the error, the adapter stops
   the stream, and the closing event is never emitted — partner code
   never sees the denied call as actionable. Empty arguments assemble to
   `{}`; unparseable arguments are a `*ConfigError`.

## Pending resolve — `Pending.Resolve`

1. Poll `GET /pending/{id}` every `PollInterval` (default 2s) until the
   deadline (default 10m) or `ctx` cancellation.
2. `decision:"allow"` → return nil; `decision:"deny"` → `*Denied`
   (`IntentCategory="PendingDenied"`, reason = decider note or
   `"operator denied"`).
3. `401` / `404` are terminal; `5xx` and network blips are swallowed and
   retried on the next tick.

## Realtime — `InspectRealtimeFunctionCall`

A one-shot helper: normalize a `response.function_call_arguments.done`
event into a `ToolCall` (arguments forwarded as a raw JSON string if they
don't parse) and run a single `Inspect`. Returns the `Verdict`; the WS
message pump decides what to send back.
