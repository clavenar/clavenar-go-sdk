# Behavior parity

The Go SDK reproduces the TypeScript reference
([`@clavenar/agent-sdk`](https://github.com/clavenar/clavenar-typescript-sdk))
byte-for-byte on the wire. The behaviors below are identical across the
TS, Python, and Go SDKs — with one validation-strictness caveat noted in
the differences list below: on `GET /pending/{id}` the Go and Python SDKs
validate the response body leniently while TS strictly validates the full
`PendingView` shape, so TS is the strict outlier there.

| Behavior | Contract |
|---|---|
| Inspect request | `POST {endpoint}/mcp`, JSON-RPC 2.0 `{jsonrpc,method:"tools/call",params:{name,arguments},id}`; `arguments` forwarded verbatim |
| Auth | `Authorization: Bearer {token}` only when a token is set |
| 200 | allow; `X-Clavenar-Correlation-Id` surfaced when present |
| 403 | deny; missing `reasons`/`review_reasons` → empty, missing `intent_category` → `""`; non-string `error` → transport error |
| 202 | pending; `correlationId = header ?? body`, both empty → transport error |
| Retry | network + 5xx retry up to `MaxAttempts` (default 3); full-jitter backoff `base*2^attempt*(0.5+rand*0.5)`, base 100ms; 200/403/other-4xx never retry; timeout 10s |
| Inspect-all | concurrent inspect, **submission-order** first-deny; `OnVerdict` before any deny→error |
| Enforce | first deny → `Denied`, pending → `Pending`; transport error fails closed, `OnPolicyError` not called |
| Observe | nothing blocks; per-call transport failure → `OnPolicyError`, treated as allowed |
| Streaming | closing event held until verdict; empty args → `{}`; unparseable drained args → `ConfigError` |
| Resolve | poll `GET /pending/{id}` every 2s, ceiling 10m; deny → `Denied` (`IntentCategory="PendingDenied"`, reason = decider note or `"operator denied"`); 401/404 terminal; 5xx/network swallowed |
| OpenAI non-streaming, unparseable args | `ConfigError` (matches TS, not Python's raw-string fallback) |
| Realtime | `arguments` forwarded as a raw JSON string on parse failure |
| URL join | trims one trailing/leading slash; never drops a base path like `https://gw/clavenar` |

## Intentional, additive Go-idiom differences

None change wire bytes or verdict outcomes:

1. **No transparent client proxy.** TS/Python wrap the client object and
   intercept `create`. Go has no equivalent, so the canonical surface is
   the explicit `clavenar.Inspect` / `clavenar.InspectAll` plus the
   opt-in adapter facades (`WrapMessages` / `WrapCompletions`). Verdict
   semantics are identical.
2. **`context.Context` everywhere.** Every call and `Pending.Resolve`
   takes a `ctx`, so callers can cancel a long human-approval wait. The
   wall-clock deadline is still enforced.
3. **Errors via `errors.As`.** `Denied` / `Pending` / `ConfigError` /
   `TransportError` are pointer error types with the same fields (TS
   naming), matched with `errors.As`. `TransportError.Status == 0` is the
   Go encoding of TS's `status === undefined` ("no HTTP response").
4. **errgroup cancellation.** On an enforce-mode transport error the
   remaining in-flight inspections are cancelled — a latency optimization
   with no observable difference (enforce fails closed regardless of
   which call wins the race; denies are still decided in submission
   order).
5. **No `extraHeaders` option** — matches the TS reference (the Python
   SDK has one; the Go SDK follows TS).
6. **Lenient `GET /pending/{id}` body validation.** `parsePendingView`
   validates only the `decision` field (`null` / `"allow"` / `"deny"`)
   and unmarshals the rest of the `PendingView` verbatim — matching the
   Python SDK's `_parse_pending_view`. The TS reference's `isPendingView`
   is the strict outlier: it asserts the full body shape
   (`correlation_id`, `agent_id`, `tool_type`, `method`, `review_reasons`,
   `requested_at`, `decided_at`, `decider_note`) and throws on any
   mismatch. The two diverge only on a non-conformant body; a conformant
   gateway yields the same verdict everywhere.
