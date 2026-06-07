package clavenar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pendingView(decision, note string) string {
	d := "null"
	if decision != "" {
		d = `"` + decision + `"`
	}
	n := "null"
	if note != "" {
		n = `"` + note + `"`
	}
	return `{"correlation_id":"c1","agent_id":"a","tool_type":"shell","method":"tools/call",` +
		`"review_reasons":[],"requested_at":"2026-01-01T00:00:00Z","decided_at":null,` +
		`"decision":` + d + `,"decider_note":` + n + `}`
}

func newTestPending(endpoint string) *Pending {
	return newPending(
		ToolCall{ID: "toolu_1", Name: "delete_user"},
		Verdict{Kind: VerdictPending, CorrelationID: "c1", ReviewReasons: []string{"needs review"}},
		mustOpts(endpoint),
	)
}

func fastResolve() *ResolveOptions {
	return &ResolveOptions{PollInterval: 2 * time.Millisecond, Timeout: 2 * time.Second}
}

func TestResolveAllow(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			_, _ = w.Write([]byte(pendingView("", "")))
			return
		}
		_, _ = w.Write([]byte(pendingView("allow", "")))
	}))
	defer srv.Close()

	if err := newTestPending(srv.URL).Resolve(context.Background(), fastResolve()); err != nil {
		t.Fatalf("want nil on allow, got %v", err)
	}
}

func TestResolveDenyWithNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pendingView("deny", "too risky")))
	}))
	defer srv.Close()

	err := newTestPending(srv.URL).Resolve(context.Background(), fastResolve())
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
	if d.IntentCategory != "PendingDenied" {
		t.Fatalf("intent = %q", d.IntentCategory)
	}
	if len(d.Reasons) != 1 || d.Reasons[0] != "too risky" {
		t.Fatalf("reasons = %v", d.Reasons)
	}
	if d.CorrelationID != "c1" {
		t.Fatalf("corr = %q", d.CorrelationID)
	}
}

func TestResolveDenyNoNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pendingView("deny", "")))
	}))
	defer srv.Close()

	err := newTestPending(srv.URL).Resolve(context.Background(), fastResolve())
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
	if len(d.Reasons) != 1 || d.Reasons[0] != "operator denied" {
		t.Fatalf("reasons = %v, want [operator denied]", d.Reasons)
	}
}

func TestResolveTerminal404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := newTestPending(srv.URL).Resolve(context.Background(), fastResolve())
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusNotFound {
		t.Fatalf("want TransportError(404), got %v", err)
	}
}

func TestResolveSwallows5xxThenAllow(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(pendingView("allow", "")))
	}))
	defer srv.Close()

	if err := newTestPending(srv.URL).Resolve(context.Background(), fastResolve()); err != nil {
		t.Fatalf("5xx should be swallowed, got %v", err)
	}
}

func TestResolveDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pendingView("", "")))
	}))
	defer srv.Close()

	err := newTestPending(srv.URL).Resolve(context.Background(),
		&ResolveOptions{PollInterval: 5 * time.Millisecond, Timeout: 30 * time.Millisecond})
	var te *TransportError
	if !errors.As(err, &te) || !strings.Contains(te.Msg, "not decided within") {
		t.Fatalf("want deadline TransportError, got %v", err)
	}
}

func TestResolveBadInterval(t *testing.T) {
	err := newTestPending("http://127.0.0.1:9").Resolve(context.Background(),
		&ResolveOptions{PollInterval: -1, Timeout: time.Second})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("want TransportError, got %v", err)
	}
}

func TestResolveContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pendingView("", "")))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := newTestPending(srv.URL).Resolve(ctx, &ResolveOptions{PollInterval: 5 * time.Millisecond, Timeout: 5 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
