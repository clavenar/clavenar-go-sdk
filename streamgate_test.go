package clavenar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStreamGateAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := NewStreamGate(mustOpts(srv.URL))
	g.Start("0", "toolu_1", "delete_user")
	g.Update("0", "", "", `{"user":`)
	g.Update("0", "", "", `"alice"}`)
	if err := g.Close(context.Background(), "0"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if g.Has("0") {
		t.Fatalf("buffer should be cleared after Close")
	}
}

func TestStreamGateDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x","reasons":["no"]}`))
	}))
	defer srv.Close()

	g := NewStreamGate(mustOpts(srv.URL))
	g.Start("0", "toolu_1", "delete_user")
	g.Update("0", "", "", `{}`)
	err := g.Close(context.Background(), "0")
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
}

func TestStreamGateEmptyArgs(t *testing.T) {
	var gotArgs string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &env)
		gotArgs = string(env.Params.Arguments)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := NewStreamGate(mustOpts(srv.URL))
	g.Start("0", "toolu_1", "noop")
	if err := g.Close(context.Background(), "0"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if gotArgs != "{}" {
		t.Fatalf("empty args should become {}, got %q", gotArgs)
	}
}

func TestStreamGateUnparseableArgs(t *testing.T) {
	g := NewStreamGate(mustOpts("http://127.0.0.1:9"))
	g.Start("0", "toolu_1", "f")
	g.Update("0", "", "", "not json")
	err := g.Close(context.Background(), "0")
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConfigError, got %v", err)
	}
}

func TestStreamGateMissingIDName(t *testing.T) {
	g := NewStreamGate(mustOpts("http://127.0.0.1:9"))
	g.Update("0", "", "", `{"a":1}`) // args only, no id/name
	err := g.Close(context.Background(), "0")
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConfigError, got %v", err)
	}
}

func TestStreamGateNonToolClose(t *testing.T) {
	g := NewStreamGate(mustOpts("http://127.0.0.1:9"))
	// Closing a key that never opened (a text block) is a no-op.
	if err := g.Close(context.Background(), "7"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestStreamGateBatchOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x","reasons":["denied ` + req.Params.Name + `"]}`))
	}))
	defer srv.Close()

	g := NewStreamGate(mustOpts(srv.URL))
	g.Update("0:0", "id_a", "first", `{}`)
	g.Update("0:1", "id_b", "second", `{}`)
	err := g.CloseByPrefix(context.Background(), "0:")
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
	if d.ToolName != "first" {
		t.Fatalf("batch deny must follow first-seen order (first), got %s", d.ToolName)
	}
}

func TestStreamGateObserve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x","reasons":["no"]}`))
	}))
	defer srv.Close()

	var kinds []VerdictKind
	opts := mustOpts(srv.URL, WithObserve(), WithOnVerdict(func(v Verdict, _ VerdictContext) error {
		kinds = append(kinds, v.Kind)
		return nil
	}))
	g := NewStreamGate(opts)
	g.Start("0", "toolu_1", "f")
	g.Update("0", "", "", `{}`)
	if err := g.Close(context.Background(), "0"); err != nil {
		t.Fatalf("observe must not return error, got %v", err)
	}
	if len(kinds) != 1 || kinds[0] != VerdictDeny {
		t.Fatalf("kinds = %v", kinds)
	}
}
