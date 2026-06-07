package clavenar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeRealtimeValidJSON(t *testing.T) {
	tc := NormalizeRealtimeFunctionCall(RealtimeFunctionCallDone{
		CallID: "call_1", Name: "transfer", Arguments: `{"amount":100}`,
	})
	if tc.ID != "call_1" || tc.Name != "transfer" {
		t.Fatalf("ids = %+v", tc)
	}
	if string(tc.Input) != `{"amount":100}` {
		t.Fatalf("input should be the raw JSON object, got %s", tc.Input)
	}
}

func TestNormalizeRealtimeInvalidJSON(t *testing.T) {
	tc := NormalizeRealtimeFunctionCall(RealtimeFunctionCallDone{
		CallID: "call_2", Name: "transfer", Arguments: `not json`,
	})
	// Malformed args are forwarded as a JSON string so policy can still
	// inspect the attempt.
	if string(tc.Input) != `"not json"` {
		t.Fatalf("input should be re-encoded raw string, got %s", tc.Input)
	}
}

func TestInspectRealtimeFunctionCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v, err := InspectRealtimeFunctionCall(context.Background(),
		RealtimeFunctionCallDone{CallID: "call_3", Name: "f", Arguments: `{}`},
		mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictAllow {
		t.Fatalf("kind = %v", v.Kind)
	}
}
