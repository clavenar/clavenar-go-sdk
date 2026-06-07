# Security

## Reporting a vulnerability

Email **security@clavenar.com** with details and a reproduction. Please
do not open a public issue for security reports. We aim to acknowledge
within two business days.

## Posture

- **No provider dependency in the core.** `github.com/clavenar/clavenar-go-sdk`
  depends only on the standard library and `golang.org/x/sync`. The
  Anthropic / OpenAI SDKs are pulled only by the opt-in `adapters/*`
  sub-modules, so the core's supply-chain surface stays minimal.
- **Fail-closed by default.** In enforce mode a transport failure to
  reach clavenar returns a `*TransportError` rather than silently
  allowing the call.
- **No secrets at rest.** The SDK holds only the endpoint URL and an
  optional bearer token, both supplied by the caller per process.
- **Supply chain.** CI runs `govulncheck` on every push, and release
  archives ship with checksums and a generated SBOM.

## Supported versions

The latest minor release receives security fixes.
