package clavenar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// nameRouter decodes params.name and returns a per-tool response.
func nameRouter(t *testing.T, route func(name string) (status int, corr, body string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		status, corr, body := route(req.Params.Name)
		if corr != "" {
			w.Header().Set("X-Clavenar-Correlation-Id", corr)
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

func TestInspectAllEmpty(t *testing.T) {
	if err := InspectAll(context.Background(), nil, mustOpts("http://127.0.0.1:9")); err != nil {
		t.Fatalf("empty calls should be nil, got %v", err)
	}
}

func TestInspectAllOrderedFirstDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		// The first call in submission order returns last over the wire.
		if req.Params.Name == "slow_deny" {
			time.Sleep(40 * time.Millisecond)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x","reasons":["denied ` + req.Params.Name + `"]}`))
	}))
	defer srv.Close()

	calls := []ToolCall{
		{ID: "1", Name: "slow_deny", Input: json.RawMessage(`{}`)},
		{ID: "2", Name: "fast_deny", Input: json.RawMessage(`{}`)},
	}
	err := InspectAll(context.Background(), calls, mustOpts(srv.URL))
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
	if d.ToolName != "slow_deny" {
		t.Fatalf("first deny must follow submission order (slow_deny), got %s", d.ToolName)
	}
}

func TestInspectAllEnforceTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	policyErrFired := false
	opts := mustOpts(srv.URL, WithOnPolicyError(func(*TransportError, VerdictContext) error {
		policyErrFired = true
		return nil
	}))
	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, opts)
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusInternalServerError {
		t.Fatalf("want TransportError(500), got %v", err)
	}
	if policyErrFired {
		t.Fatalf("OnPolicyError must NOT fire in enforce mode")
	}
}

func TestInspectAllObservePassesThrough(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusForbidden, "", `{"error":"x","reasons":["no"]}`
	})
	defer srv.Close()

	var kinds []VerdictKind
	opts := mustOpts(srv.URL, WithObserve(), WithOnVerdict(func(v Verdict, _ VerdictContext) error {
		kinds = append(kinds, v.Kind)
		return nil
	}))
	if err := InspectAll(context.Background(), []ToolCall{sampleCall()}, opts); err != nil {
		t.Fatalf("observe mode must not return error on deny, got %v", err)
	}
	if len(kinds) != 1 || kinds[0] != VerdictDeny {
		t.Fatalf("OnVerdict kinds = %v", kinds)
	}
}

func TestInspectAllObserveTransportTreatedAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	polCalls := 0
	opts := mustOpts(srv.URL, WithObserve(), WithOnPolicyError(func(*TransportError, VerdictContext) error {
		polCalls++
		return nil
	}))
	if err := InspectAll(context.Background(), []ToolCall{sampleCall()}, opts); err != nil {
		t.Fatalf("observe transport failure must be treated as allow, got %v", err)
	}
	if polCalls != 1 {
		t.Fatalf("OnPolicyError fired %d times, want 1", polCalls)
	}
}

func TestInspectAllPendingEnforce(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusAccepted, "cp", `{"status":"pending","correlation_id":"cp","review_reasons":["needs review"]}`
	})
	defer srv.Close()

	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, mustOpts(srv.URL))
	var p *Pending
	if !errors.As(err, &p) {
		t.Fatalf("want *Pending, got %v", err)
	}
	if p.CorrelationID != "cp" || p.ToolName != "delete_user" {
		t.Fatalf("pending = %+v", p)
	}
}

func TestInspectAllRateLimitedEnforce(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusTooManyRequests, "c-429",
			`{"verdict":"rate_limited","layer":"proxy","error":"rate_limited","reasons":["agent request velocity exceeded"],"retry_after_secs":30}`
	})
	defer srv.Close()

	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, mustOpts(srv.URL))
	var rl *RateLimited
	if !errors.As(err, &rl) {
		t.Fatalf("want *RateLimited, got %v", err)
	}
	if rl.ToolName != "delete_user" || rl.Code != "rate_limited" || rl.Layer != "proxy" || rl.CorrelationID != "c-429" {
		t.Fatalf("rate limited = %+v", rl)
	}
	if rl.RetryAfterSecs == nil || *rl.RetryAfterSecs != 30 {
		t.Fatalf("retry_after_secs = %v", rl.RetryAfterSecs)
	}
	if len(rl.Reasons) != 1 || rl.Reasons[0] != "agent request velocity exceeded" {
		t.Fatalf("reasons = %v", rl.Reasons)
	}
	if got, want := rl.Error(), `clavenar rate_limited for tool "delete_user" (retry after 30s)`; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestInspectAllQuotaExceededEnforce(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusTooManyRequests, "",
			`{"verdict":"quota_exceeded","error":"quota_exceeded","reasons":["tenant monthly spend cap reached"]}`
	})
	defer srv.Close()

	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, mustOpts(srv.URL))
	var rl *RateLimited
	if !errors.As(err, &rl) {
		t.Fatalf("want *RateLimited, got %v", err)
	}
	if rl.Code != "quota_exceeded" || rl.RetryAfterSecs != nil {
		t.Fatalf("rate limited = %+v", rl)
	}
	if got, want := rl.Error(), `clavenar quota_exceeded for tool "delete_user"`; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestInspectAllRateLimitedObserve(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusTooManyRequests, "",
			`{"verdict":"rate_limited","error":"rate_limited","reasons":["agent request velocity exceeded"],"retry_after_secs":30}`
	})
	defer srv.Close()

	var kinds []VerdictKind
	opts := mustOpts(srv.URL, WithObserve(), WithOnVerdict(func(v Verdict, _ VerdictContext) error {
		kinds = append(kinds, v.Kind)
		return nil
	}))
	if err := InspectAll(context.Background(), []ToolCall{sampleCall()}, opts); err != nil {
		t.Fatalf("observe mode must not return error on rate limit, got %v", err)
	}
	if len(kinds) != 1 || kinds[0] != VerdictRateLimited {
		t.Fatalf("OnVerdict kinds = %v", kinds)
	}
}

func TestInspectAllOnVerdictAbort(t *testing.T) {
	srv := nameRouter(t, func(string) (int, string, string) {
		return http.StatusOK, "", ""
	})
	defer srv.Close()

	sentinel := errors.New("stop")
	opts := mustOpts(srv.URL, WithOnVerdict(func(Verdict, VerdictContext) error { return sentinel }))
	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, opts)
	if !errors.Is(err, sentinel) {
		t.Fatalf("OnVerdict error should propagate, got %v", err)
	}
}

func TestInspectAllConfigError(t *testing.T) {
	err := InspectAll(context.Background(), []ToolCall{sampleCall()}, Options{Endpoint: ""})
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConfigError, got %v", err)
	}
}
