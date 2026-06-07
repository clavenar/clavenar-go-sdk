# Contributing

## Layout

This repo is a multi-module workspace:

- `.` — the core `clavenar` package (no provider dependency).
- `adapters/anthropic`, `adapters/openai` — opt-in provider bridges,
  each its own module with its own `go.mod`.
- `examples/` — runnable examples, its own module.

The adapter and example modules use a `replace` directive pointing at the
local core during development. On release the core is tagged first, then
each adapter's `require` is updated to the tagged version (the `replace`
is dropped from published modules — Go ignores `replace` in dependencies
anyway).

## Verify before pushing

```bash
# core
gofmt -l .                 # must print nothing
go vet ./...
go test -race -count=1 ./...
golangci-lint run
govulncheck ./...

# each adapter module
(cd adapters/anthropic && go vet ./... && go test -race ./... && golangci-lint run)
(cd adapters/openai    && go vet ./... && go test -race ./... && golangci-lint run)

# examples build
(cd examples && go build ./...)
```

## Conventions

- Match the existing structure; the core takes no provider dependency.
- Behavior must stay 1:1 with the TypeScript reference on the wire — if a
  change touches wire behavior, update `docs/PARITY.md` and add a test.
- Tests live beside the code and run against an `httptest.Server`; no
  live network in unit tests.
