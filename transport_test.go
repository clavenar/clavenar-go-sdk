package clavenar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustOpts(endpoint string, mods ...Option) Options {
	o := Options{
		Endpoint: endpoint,
		Retry:    Retry{MaxAttempts: 1, BaseDelay: time.Millisecond},
		Timeout:  2 * time.Second,
	}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func sampleCall() ToolCall {
	return ToolCall{ID: "toolu_1", Name: "delete_user", Input: json.RawMessage(`{"user":"alice"}`)}
}

func TestInspectAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Clavenar-Correlation-Id", "corr-123")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictAllow || v.CorrelationID != "corr-123" {
		t.Fatalf("got %+v", v)
	}
}

func TestInspectDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Clavenar-Correlation-Id", "c1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"security_violation","reasons":["nope"],"review_reasons":["r"],"intent_category":"Destruction","layer":"policy"}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictDeny {
		t.Fatalf("kind = %v", v.Kind)
	}
	if len(v.Reasons) != 1 || v.Reasons[0] != "nope" {
		t.Fatalf("reasons = %v", v.Reasons)
	}
	if v.IntentCategory != "Destruction" || v.Layer != "policy" || v.CorrelationID != "c1" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestInspectDenyNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x"}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Reasons == nil || len(v.Reasons) != 0 {
		t.Fatalf("reasons should normalize to empty, got %#v", v.Reasons)
	}
	if v.ReviewReasons == nil || len(v.ReviewReasons) != 0 {
		t.Fatalf("review_reasons should normalize to empty, got %#v", v.ReviewReasons)
	}
	if v.IntentCategory != "" {
		t.Fatalf("intent_category should normalize to empty, got %q", v.IntentCategory)
	}
}

func TestInspectDenyBadShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"foo":1}`))
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusForbidden {
		t.Fatalf("want TransportError(403), got %v", err)
	}
}

func TestInspectPendingHeaderWins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Clavenar-Correlation-Id", "ch")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","correlation_id":"cb","review_reasons":["x"]}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictPending || v.CorrelationID != "ch" {
		t.Fatalf("want pending with header corr, got %+v", v)
	}
	if len(v.ReviewReasons) != 1 || v.ReviewReasons[0] != "x" {
		t.Fatalf("review reasons = %v", v.ReviewReasons)
	}
}

func TestInspectPendingBodyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","correlation_id":"cb","review_reasons":[]}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.CorrelationID != "cb" {
		t.Fatalf("want body corr fallback, got %q", v.CorrelationID)
	}
}

func TestInspectPendingBothEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","correlation_id":"","review_reasons":[]}`))
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusAccepted {
		t.Fatalf("want TransportError(202), got %v", err)
	}
	if !strings.Contains(te.Msg, "missing correlation id") {
		t.Fatalf("msg = %q", te.Msg)
	}
}

func TestInspectRateLimited(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"verdict":"rate_limited","layer":"proxy","error":"rate_limited","reasons":["agent request velocity exceeded"],"correlation_id":"c-429","retry_after_secs":17}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(),
		mustOpts(srv.URL, WithRetry(Retry{MaxAttempts: 3, BaseDelay: time.Millisecond})))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictRateLimited || v.RateLimitCode != "rate_limited" {
		t.Fatalf("verdict = %+v", v)
	}
	if v.RetryAfterSecs == nil || *v.RetryAfterSecs != 17 {
		t.Fatalf("retry_after_secs = %v", v.RetryAfterSecs)
	}
	if v.Layer != "proxy" || v.CorrelationID != "c-429" {
		t.Fatalf("verdict = %+v", v)
	}
	if len(v.Reasons) != 1 || v.Reasons[0] != "agent request velocity exceeded" {
		t.Fatalf("reasons = %v", v.Reasons)
	}
	// A 429 is a verdict, not a transient failure — exactly one attempt.
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("attempts = %d, want 1 (429 must not retry)", got)
	}
}

func TestInspectRateLimitedQuotaExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"verdict":"quota_exceeded","layer":"proxy","error":"quota_exceeded","reasons":["tenant monthly spend cap reached"]}`))
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictRateLimited || v.RateLimitCode != "quota_exceeded" {
		t.Fatalf("verdict = %+v", v)
	}
	if v.RetryAfterSecs != nil {
		t.Fatalf("retry_after_secs should be nil, got %d", *v.RetryAfterSecs)
	}
}

func TestInspectRateLimitedBadShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"wrong":"shape"}`))
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusTooManyRequests {
		t.Fatalf("want TransportError(429), got %v", err)
	}
}

func TestInspectUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusInternalServerError {
		t.Fatalf("want TransportError(500), got %v", err)
	}
}

func TestInspectNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(url))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != 0 {
		t.Fatalf("want TransportError(status 0), got %v", err)
	}
}

func TestInspectTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL, WithTimeout(20*time.Millisecond)))
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("want TransportError, got %v", err)
	}
	if !strings.Contains(te.Msg, "timed out") {
		t.Fatalf("msg = %q", te.Msg)
	}
}

func TestInspectRequestEnvelope(t *testing.T) {
	var gotMethod, gotPath, gotCT, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL, WithToken("tok")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/mcp" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotCT != "application/json" || gotAuth != "Bearer tok" {
		t.Fatalf("headers ct=%q auth=%q", gotCT, gotAuth)
	}
	var env struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      string `json:"id"`
		Params  struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("body not json: %v (%s)", err, gotBody)
	}
	if env.JSONRPC != "2.0" || env.Method != "tools/call" || env.ID != "toolu_1" || env.Params.Name != "delete_user" {
		t.Fatalf("envelope = %+v", env)
	}
	if string(env.Params.Arguments) != `{"user":"alice"}` {
		t.Fatalf("arguments not passed through verbatim: %s", env.Params.Arguments)
	}
}

func TestInspectNoAuthHeaderWithoutToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := Inspect(context.Background(), sampleCall(), mustOpts(srv.URL)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("auth header should be absent, got %q", gotAuth)
	}
}

func TestInspectConfigError(t *testing.T) {
	_, err := Inspect(context.Background(), sampleCall(), Options{Endpoint: ""})
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConfigError, got %v", err)
	}

	_, err = Inspect(context.Background(), sampleCall(), Options{Endpoint: "not-a-url"})
	if !errors.As(err, &ce) {
		t.Fatalf("want ConfigError for bad URL, got %v", err)
	}
}

func TestInspectMaxAttemptsBelowOne(t *testing.T) {
	_, err := Inspect(context.Background(), sampleCall(), Options{
		Endpoint: "http://127.0.0.1:9",
		Retry:    Retry{MaxAttempts: -1},
	})
	var te *TransportError
	if !errors.As(err, &te) || !strings.Contains(te.Msg, "MaxAttempts") {
		t.Fatalf("want MaxAttempts TransportError, got %v", err)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v, err := Inspect(context.Background(), sampleCall(),
		mustOpts(srv.URL, WithRetry(Retry{MaxAttempts: 3, BaseDelay: time.Millisecond})))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Kind != VerdictAllow {
		t.Fatalf("kind = %v", v.Kind)
	}
	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestRetryExhausted(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(),
		mustOpts(srv.URL, WithRetry(Retry{MaxAttempts: 2, BaseDelay: time.Millisecond})))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusBadGateway {
		t.Fatalf("want TransportError(502), got %v", err)
	}
	if got := atomic.LoadInt32(&n); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := Inspect(context.Background(), sampleCall(),
		mustOpts(srv.URL, WithRetry(Retry{MaxAttempts: 3, BaseDelay: time.Millisecond})))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusBadRequest {
		t.Fatalf("want TransportError(400), got %v", err)
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx must not retry)", got)
	}
}

func TestJoinURL(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"http://x/", "/mcp", "http://x/mcp"},
		{"http://x", "mcp", "http://x/mcp"},
		{"https://gw.example.com/clavenar", "/mcp", "https://gw.example.com/clavenar/mcp"},
	}
	for _, c := range cases {
		if got := joinURL(c.base, c.path); got != c.want {
			t.Errorf("joinURL(%q,%q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}

func TestBackoffBounds(t *testing.T) {
	base := 100 * time.Millisecond
	for attempt := 0; attempt < 4; attempt++ {
		ceiling := base << attempt
		for i := 0; i < 200; i++ {
			d := backoff(base, attempt)
			if d < ceiling/2 || d > ceiling {
				t.Fatalf("attempt %d: backoff %s outside [%s,%s]", attempt, d, ceiling/2, ceiling)
			}
		}
	}
}
