// Package clavenaropenai adapts the official openai-go (v2) chat
// completions surface to the Clavenar agent-wrapper core: it normalizes
// OpenAI function tool calls into clavenar.ToolCall and inspects them
// before your agent runs them.
//
// The core github.com/clavenar/clavenar-go-sdk package has no provider
// dependency; this module is the opt-in bridge for users of
// github.com/openai/openai-go.
package clavenaropenai

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	clavenar "github.com/clavenar/clavenar-go-sdk"
	openai "github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
)

// InspectChatCompletion walks an OpenAI chat completion for function tool
// calls and inspects them with clavenar.InspectAll. A tool call whose
// arguments aren't valid JSON yields *clavenar.ConfigError — a contract
// violation by the model, not something policy can usefully see. In
// enforce mode a denied / parked call returns *clavenar.Denied /
// *clavenar.Pending.
func InspectChatCompletion(ctx context.Context, completion *openai.ChatCompletion, opts clavenar.Options) error {
	if completion == nil {
		return nil
	}
	calls, err := toToolCalls(completion)
	if err != nil {
		return err
	}
	return clavenar.InspectAll(ctx, calls, opts)
}

func toToolCalls(completion *openai.ChatCompletion) ([]clavenar.ToolCall, error) {
	var calls []clavenar.ToolCall
	for _, choice := range completion.Choices {
		for _, tc := range choice.Message.ToolCalls {
			if tc.Type != "function" {
				continue
			}
			if !json.Valid([]byte(tc.Function.Arguments)) {
				return nil, &clavenar.ConfigError{Msg: fmt.Sprintf(
					"clavenar: OpenAI tool_call %s (%s) had unparseable arguments", tc.ID, tc.Function.Name)}
			}
			calls = append(calls, clavenar.ToolCall{
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: json.RawMessage(tc.Function.Arguments),
			})
		}
	}
	return calls, nil
}

// Completions wraps an OpenAI ChatCompletionService so every response is
// inspected. Construct it with WrapCompletions, then call New /
// NewStreaming exactly as you would client.Chat.Completions.
type Completions struct {
	svc  *openai.ChatCompletionService
	opts clavenar.Options
}

// WrapCompletions binds a client's Chat.Completions service to clavenar.
func WrapCompletions(client *openai.Client, opts clavenar.Options) *Completions {
	return &Completions{svc: &client.Chat.Completions, opts: opts}
}

// New calls the underlying Chat.Completions.New and then inspects the
// response. A transport / provider error is returned unchanged; a policy
// deny or park (enforce mode) returns the clavenar error and the
// completion is discarded.
func (c *Completions) New(ctx context.Context, params openai.ChatCompletionNewParams, opts ...option.RequestOption) (*openai.ChatCompletion, error) {
	completion, err := c.svc.New(ctx, params, opts...)
	if err != nil {
		return nil, err
	}
	if err := InspectChatCompletion(ctx, completion, c.opts); err != nil {
		return nil, err
	}
	return completion, nil
}

// NewStreaming wraps Chat.Completions.NewStreaming, gating tool calls:
// the chunk carrying finish_reason="tool_calls" for a choice is held
// until clavenar clears every tool call in that choice.
func (c *Completions) NewStreaming(ctx context.Context, params openai.ChatCompletionNewParams, opts ...option.RequestOption) *Stream {
	return StreamChat(ctx, c.svc.NewStreaming(ctx, params, opts...), c.opts)
}

// Stream is a gated OpenAI chunk stream. Range over Events; once the
// channel closes, call Err. On an enforce-mode deny the finishing chunk
// for the affected choice is never emitted.
type Stream struct {
	events chan openai.ChatCompletionChunk
	err    error
}

// Events returns the gated chunk channel.
func (s *Stream) Events() <-chan openai.ChatCompletionChunk { return s.events }

// Err returns the terminal error after Events is drained.
func (s *Stream) Err() error { return s.err }

// StreamChat gates an existing OpenAI chunk stream against clavenar.
func StreamChat(ctx context.Context, upstream *ssestream.Stream[openai.ChatCompletionChunk], opts clavenar.Options) *Stream {
	out := &Stream{events: make(chan openai.ChatCompletionChunk)}
	gate := clavenar.NewStreamGate(opts)
	go func() {
		defer close(out.events)
		defer func() { _ = upstream.Close() }()
		for upstream.Next() {
			chunk := upstream.Current()
			var toDrain []int64
			for _, choice := range chunk.Choices {
				for _, d := range choice.Delta.ToolCalls {
					gate.Update(chunkKey(choice.Index, d.Index), d.ID, d.Function.Name, d.Function.Arguments)
				}
				if choice.FinishReason == "tool_calls" {
					toDrain = append(toDrain, choice.Index)
				}
			}
			// Inspect BEFORE the finishing chunk is released.
			for _, idx := range toDrain {
				if err := gate.CloseByPrefix(ctx, strconv.FormatInt(idx, 10)+":"); err != nil {
					out.err = err
					return
				}
			}
			select {
			case out.events <- chunk:
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

func chunkKey(choiceIndex, toolIndex int64) string {
	return strconv.FormatInt(choiceIndex, 10) + ":" + strconv.FormatInt(toolIndex, 10)
}
