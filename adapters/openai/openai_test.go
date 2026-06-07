package clavenaropenai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clavenar "github.com/clavenar/clavenar-go-sdk"
	openai "github.com/openai/openai-go/v2"
)

func opts(endpoint string) clavenar.Options {
	return clavenar.Options{
		Endpoint: endpoint,
		Retry:    clavenar.Retry{MaxAttempts: 1, BaseDelay: time.Millisecond},
		Timeout:  2 * time.Second,
	}
}

func completionWith(args string) *openai.ChatCompletion {
	return &openai.ChatCompletion{
		Choices: []openai.ChatCompletionChoice{
			{
				Message: openai.ChatCompletionMessage{
					ToolCalls: []openai.ChatCompletionMessageToolCallUnion{
						{
							ID:   "call_1",
							Type: "function",
							Function: openai.ChatCompletionMessageFunctionToolCallFunction{
								Name:      "delete_user",
								Arguments: args,
							},
						},
					},
				},
			},
		},
	}
}

func TestToToolCallsExtracts(t *testing.T) {
	calls, err := toToolCalls(completionWith(`{"user":"alice"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0].ID != "call_1" || calls[0].Name != "delete_user" {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Input) != `{"user":"alice"}` {
		t.Fatalf("input = %s", calls[0].Input)
	}
}

func TestToToolCallsUnparseableIsConfigError(t *testing.T) {
	_, err := toToolCalls(completionWith(`not json`))
	var ce *clavenar.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want *clavenar.ConfigError, got %v", err)
	}
}

func TestInspectChatCompletionDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"security_violation","reasons":["destructive"]}`))
	}))
	defer srv.Close()

	err := InspectChatCompletion(context.Background(), completionWith(`{}`), opts(srv.URL))
	var d *clavenar.Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *clavenar.Denied, got %v", err)
	}
	if d.ToolName != "delete_user" {
		t.Fatalf("tool = %s", d.ToolName)
	}
}

func TestInspectChatCompletionNil(t *testing.T) {
	if err := InspectChatCompletion(context.Background(), nil, opts("http://127.0.0.1:9")); err != nil {
		t.Fatalf("want nil for nil completion, got %v", err)
	}
}
