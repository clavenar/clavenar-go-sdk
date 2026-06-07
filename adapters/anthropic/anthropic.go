// Package clavenaranthropic adapts the official anthropic-sdk-go to the
// Clavenar agent-wrapper core: it normalizes Anthropic tool_use blocks
// into clavenar.ToolCall and inspects them before your agent runs them.
//
// The core github.com/clavenar/clavenar-go-sdk package has no provider
// dependency; this module is the opt-in bridge for users of
// github.com/anthropics/anthropic-sdk-go.
package clavenaranthropic

import (
	"context"
	"strconv"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"
	clavenar "github.com/clavenar/clavenar-go-sdk"
)

// InspectMessage walks a non-streaming Anthropic response for tool_use
// blocks and inspects them with clavenar.InspectAll. In enforce mode a
// denied or parked call returns *clavenar.Denied / *clavenar.Pending, so
// the caller checks the error before executing any tool. In observe mode
// it returns nil and surfaces verdicts via the options callbacks.
func InspectMessage(ctx context.Context, msg *anthropic.Message, opts clavenar.Options) error {
	if msg == nil {
		return nil
	}
	return clavenar.InspectAll(ctx, toToolCalls(msg), opts)
}

func toToolCalls(msg *anthropic.Message) []clavenar.ToolCall {
	var calls []clavenar.ToolCall
	for _, block := range msg.Content {
		if block.Type == "tool_use" {
			calls = append(calls, clavenar.ToolCall{ID: block.ID, Name: block.Name, Input: block.Input})
		}
	}
	return calls
}

// Messages wraps an Anthropic MessageService so every response is
// inspected. Construct it with WrapMessages, then call New / NewStreaming
// exactly as you would client.Messages.
//
// This facade covers only the create surface; reach for the underlying
// client for anything else (client.Models, beta endpoints, ...).
type Messages struct {
	svc  *anthropic.MessageService
	opts clavenar.Options
}

// WrapMessages binds a client's MessageService to clavenar.
func WrapMessages(client *anthropic.Client, opts clavenar.Options) *Messages {
	return &Messages{svc: &client.Messages, opts: opts}
}

// New calls the underlying Messages.New and then inspects the response.
// A transport / provider error is returned unchanged; a policy deny or
// park (enforce mode) returns the clavenar error and the message is
// discarded.
func (m *Messages) New(ctx context.Context, params anthropic.MessageNewParams, opts ...option.RequestOption) (*anthropic.Message, error) {
	msg, err := m.svc.New(ctx, params, opts...)
	if err != nil {
		return nil, err
	}
	if err := InspectMessage(ctx, msg, m.opts); err != nil {
		return nil, err
	}
	return msg, nil
}

// NewStreaming wraps Messages.NewStreaming, gating tool calls: each
// content_block_stop for a tool_use is held until clavenar returns a
// verdict.
func (m *Messages) NewStreaming(ctx context.Context, params anthropic.MessageNewParams, opts ...option.RequestOption) *Stream {
	return StreamMessages(ctx, m.svc.NewStreaming(ctx, params, opts...), m.opts)
}

// Stream is a gated Anthropic event stream. Range over Events; once the
// channel closes, call Err to learn whether the stream ended cleanly or
// was stopped by a deny / park / transport failure. On an enforce-mode
// deny the closing content_block_stop event for the denied tool is never
// emitted — partner code never sees the denied call as actionable.
type Stream struct {
	events chan anthropic.MessageStreamEventUnion
	err    error
}

// Events returns the gated event channel.
func (s *Stream) Events() <-chan anthropic.MessageStreamEventUnion { return s.events }

// Err returns the terminal error after Events is drained.
func (s *Stream) Err() error { return s.err }

// StreamMessages gates an existing Anthropic stream against clavenar.
func StreamMessages(ctx context.Context, upstream *ssestream.Stream[anthropic.MessageStreamEventUnion], opts clavenar.Options) *Stream {
	out := &Stream{events: make(chan anthropic.MessageStreamEventUnion)}
	gate := clavenar.NewStreamGate(opts)
	go func() {
		defer close(out.events)
		defer func() { _ = upstream.Close() }()
		for upstream.Next() {
			evt := upstream.Current()
			switch evt.Type {
			case "content_block_start":
				if evt.ContentBlock.Type == "tool_use" {
					gate.Start(blockKey(evt.Index), evt.ContentBlock.ID, evt.ContentBlock.Name)
				}
			case "content_block_delta":
				if evt.Delta.Type == "input_json_delta" {
					gate.Update(blockKey(evt.Index), "", "", evt.Delta.PartialJSON)
				}
			case "content_block_stop":
				// Inspect BEFORE the stop event is released, so a denied
				// tool_use never reaches the partner as a closed block.
				if err := gate.Close(ctx, blockKey(evt.Index)); err != nil {
					out.err = err
					return
				}
			}
			select {
			case out.events <- evt:
			case <-ctx.Done():
				out.err = ctx.Err()
				return
			}
		}
		if err := upstream.Err(); err != nil {
			out.err = err
		}
	}()
	return out
}

func blockKey(index int64) string { return strconv.FormatInt(index, 10) }
