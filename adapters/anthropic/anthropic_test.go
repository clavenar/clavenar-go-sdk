package clavenaranthropic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	clavenar "github.com/clavenar/clavenar-go-sdk"
)

func opts(endpoint string) clavenar.Options {
	return clavenar.Options{
		Endpoint: endpoint,
		Retry:    clavenar.Retry{MaxAttempts: 1, BaseDelay: time.Millisecond},
		Timeout:  2 * time.Second,
	}
}

func msgWithToolUse() *anthropic.Message {
	return &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{
			{Type: "text", Text: "let me help"},
			{Type: "tool_use", ID: "toolu_1", Name: "delete_user", Input: json.RawMessage(`{"user":"alice"}`)},
		},
	}
}

func TestToToolCallsExtracts(t *testing.T) {
	calls := toToolCalls(msgWithToolUse())
	if len(calls) != 1 {
		t.Fatalf("want 1 tool call, got %d", len(calls))
	}
	if calls[0].ID != "toolu_1" || calls[0].Name != "delete_user" {
		t.Fatalf("call = %+v", calls[0])
	}
	if string(calls[0].Input) != `{"user":"alice"}` {
		t.Fatalf("input = %s", calls[0].Input)
	}
}

func TestInspectMessageDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"security_violation","reasons":["destructive"]}`))
	}))
	defer srv.Close()

	err := InspectMessage(context.Background(), msgWithToolUse(), opts(srv.URL))
	var d *clavenar.Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *clavenar.Denied, got %v", err)
	}
	if d.ToolName != "delete_user" {
		t.Fatalf("tool = %s", d.ToolName)
	}
}

func TestInspectMessageNoToolsNoCall(t *testing.T) {
	// No tool_use blocks -> nil with no network call.
	msg := &anthropic.Message{Content: []anthropic.ContentBlockUnion{{Type: "text", Text: "hi"}}}
	if err := InspectMessage(context.Background(), msg, opts("http://127.0.0.1:9")); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestInspectMessageNil(t *testing.T) {
	if err := InspectMessage(context.Background(), nil, opts("http://127.0.0.1:9")); err != nil {
		t.Fatalf("want nil for nil message, got %v", err)
	}
}
