package clavenar

import (
	"context"
	"encoding/json"
)

// RealtimeFunctionCallDone is the terminal event for one OpenAI Realtime
// tool call: the response.function_call_arguments.done event carrying
// the call_id + final JSON-encoded arguments, plus the tool name from
// the matching response.output_item.added event.
type RealtimeFunctionCallDone struct {
	CallID    string
	Name      string
	Arguments string
}

// NormalizeRealtimeFunctionCall converts a Realtime done event into a
// ToolCall. The arguments string is forwarded as a raw JSON string when
// it isn't valid JSON, so a malformed-args policy rule can still inspect
// the attempt rather than have the SDK swallow it.
func NormalizeRealtimeFunctionCall(evt RealtimeFunctionCallDone) ToolCall {
	input := json.RawMessage(evt.Arguments)
	if !json.Valid([]byte(evt.Arguments)) {
		// Re-encode the raw text as a JSON string value.
		quoted, _ := json.Marshal(evt.Arguments)
		input = quoted
	}
	return ToolCall{ID: evt.CallID, Name: evt.Name, Input: input}
}

// InspectRealtimeFunctionCall is a one-shot inspect for a Realtime
// function call — equivalent to
// Inspect(ctx, NormalizeRealtimeFunctionCall(evt), opts) — giving a WS
// message pump a single entry point.
func InspectRealtimeFunctionCall(ctx context.Context, evt RealtimeFunctionCallDone, opts Options) (Verdict, error) {
	return Inspect(ctx, NormalizeRealtimeFunctionCall(evt), opts)
}
