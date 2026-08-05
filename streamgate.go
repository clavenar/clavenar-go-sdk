package clavenar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// StreamGate accumulates streaming tool-call fragments and inspects an
// assembled batch when the caller signals a close. Provider stream
// adapters drive it: Start when a tool call opens (Anthropic), Update for
// each fragment (Anthropic arg deltas, or OpenAI deltas that carry
// id/name/args together), then Close — called BEFORE the adapter
// forwards the closing event — to inspect.
//
// Close returns the same *Denied / *Pending / *RateLimited /
// *TransportError / *ConfigError an InspectAll would, so the adapter can
// stop the stream before releasing the closing event on a deny. Keys identify a tool
// call within the stream: the Anthropic content-block index, or
// "choiceIndex:toolIndex" for OpenAI.
//
// A StreamGate is not safe for concurrent use; drive it from the single
// goroutine that reads the upstream stream.
type StreamGate struct {
	opts  Options
	bufs  map[string]*toolBuf
	order []string
	bytes int
	err   error
}

const (
	maxDecisionBatchCalls  = 128
	maxToolArgumentsBytes  = 1 << 20
	maxToolBatchBytes      = 4 << 20
	maxToolIdentifierBytes = 1024
)

type toolBuf struct {
	id   string
	name string
	args strings.Builder
}

// NewStreamGate returns a gate bound to opts.
func NewStreamGate(opts Options) *StreamGate {
	return &StreamGate{opts: opts, bufs: map[string]*toolBuf{}}
}

func (g *StreamGate) ensure(key string) *toolBuf {
	if g.err != nil {
		return nil
	}
	if key == "" || len(key) > maxToolIdentifierBytes {
		g.fail("tool call key is empty or too large")
		return nil
	}
	b := g.bufs[key]
	if b == nil {
		if len(g.bufs) >= maxDecisionBatchCalls {
			g.fail("too many open tool calls")
			return nil
		}
		b = &toolBuf{}
		g.bufs[key] = b
		g.order = append(g.order, key)
	}
	return b
}

func (g *StreamGate) fail(message string) {
	if g.err == nil {
		g.err = &ConfigError{Msg: "clavenar stream: " + message}
	}
}

// Start registers an opening tool call under key with its id and name.
func (g *StreamGate) Start(key, id, name string) {
	if _, exists := g.bufs[key]; exists {
		g.fail("duplicate start for tool call key " + key)
		return
	}
	b := g.ensure(key)
	if b == nil {
		return
	}
	if len(id) > maxToolIdentifierBytes || len(name) > maxToolIdentifierBytes {
		g.fail("tool call id or name is too large")
		return
	}
	b.id = id
	b.name = name
}

// Update merges a fragment into the buffer for key, creating it if no
// Start arrived first (the OpenAI delta case). Empty id / name / fragment
// are ignored.
func (g *StreamGate) Update(key, id, name, argsFragment string) {
	b := g.ensure(key)
	if b == nil {
		return
	}
	if len(id) > maxToolIdentifierBytes || len(name) > maxToolIdentifierBytes {
		g.fail("tool call id or name is too large")
		return
	}
	if id != "" {
		if b.id != "" && b.id != id {
			g.fail("tool call id changed for key " + key)
			return
		}
		b.id = id
	}
	if name != "" {
		if b.name != "" && b.name != name {
			g.fail("tool call name changed for key " + key)
			return
		}
		b.name = name
	}
	if argsFragment != "" {
		if b.args.Len()+len(argsFragment) > maxToolArgumentsBytes || g.bytes+len(argsFragment) > maxToolBatchBytes {
			g.fail("tool call arguments exceed the configured safety limit")
			return
		}
		b.args.WriteString(argsFragment)
		g.bytes += len(argsFragment)
	}
}

// Has reports whether a tool-call buffer is open under key.
func (g *StreamGate) Has(key string) bool {
	_, ok := g.bufs[key]
	return ok
}

// Close assembles the buffered calls for the given keys (in argument
// order), removes them, and inspects them as one batch. Keys with no
// open buffer are skipped, so calling Close on every closing event —
// including non-tool blocks — is safe.
func (g *StreamGate) Close(ctx context.Context, keys ...string) error {
	if g.err != nil {
		return g.err
	}
	calls := make([]ToolCall, 0, len(keys))
	closed := make(map[string]bool, len(keys))
	for _, key := range keys {
		b := g.bufs[key]
		if b == nil {
			continue
		}
		delete(g.bufs, key)
		g.bytes -= b.args.Len()
		closed[key] = true
		call, err := b.toCall()
		if err != nil {
			g.pruneOrder(closed)
			return err
		}
		calls = append(calls, call)
	}
	g.pruneOrder(closed)
	if len(calls) == 0 {
		return nil
	}
	return InspectAll(ctx, calls, g.opts)
}

// CloseByPrefix closes every open key with the given prefix, in the order
// the keys were first seen — the OpenAI per-choice drain.
func (g *StreamGate) CloseByPrefix(ctx context.Context, prefix string) error {
	var keys []string
	for _, k := range g.order {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return g.Close(ctx, keys...)
}

func (g *StreamGate) pruneOrder(closed map[string]bool) {
	if len(closed) == 0 {
		return
	}
	out := g.order[:0]
	for _, k := range g.order {
		if !closed[k] {
			out = append(out, k)
		}
	}
	g.order = out
}

func (b *toolBuf) toCall() (ToolCall, error) {
	if b.id == "" || b.name == "" {
		return ToolCall{}, &ConfigError{Msg: fmt.Sprintf("clavenar stream: tool call buffer missing id or name (id=%q name=%q)", b.id, b.name)}
	}
	raw := b.args.String()
	if raw == "" {
		return ToolCall{ID: b.id, Name: b.name, Input: json.RawMessage(`{}`)}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ToolCall{}, &ConfigError{Msg: fmt.Sprintf("clavenar stream: tool call %s (%s) has unparseable arguments", b.id, b.name)}
	}
	return ToolCall{ID: b.id, Name: b.name, Input: json.RawMessage(raw)}, nil
}
