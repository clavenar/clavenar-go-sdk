// Package clavenar is the agent-wrapper SDK for Clavenar: it inspects
// the tool calls a model emits against your policies before your agent
// runs them.
//
// The import path ends in clavenar-go-sdk but the package is clavenar,
// so callers write clavenar.Inspect / clavenar.InspectAll and branch on
// *clavenar.Denied / *clavenar.Pending.
//
// Inspect submits a single normalized ToolCall and returns its Verdict.
// InspectAll inspects a batch and, in enforce mode, returns the first
// *Denied / *Pending in submission order; in observe mode it only fires
// the OnVerdict / OnPolicyError callbacks and never blocks. The provider
// adapters under adapters/anthropic and adapters/openai turn a provider
// response into []ToolCall; the core package takes no provider dependency.
package clavenar
