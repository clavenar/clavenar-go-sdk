// Command custom-dispatcher shows the provider-agnostic pattern: build
// clavenar.ToolCall values from whatever your agent framework hands you
// and inspect them before dispatch. No provider SDK required — this is
// the idiomatic surface for framework integrations (langchaingo, custom
// tool loops, ...).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"

	clavenar "github.com/clavenar/clavenar-go-sdk"
)

func main() {
	opts := clavenar.New(
		envOr("CLAVENAR_ENDPOINT", "http://localhost:8088"),
		clavenar.WithToken(os.Getenv("CLAVENAR_LITE_TOKEN")),
	)

	// Whatever your framework decided to call this turn:
	calls := []clavenar.ToolCall{
		{ID: "call_1", Name: "delete_user", Input: json.RawMessage(`{"user":"alice"}`)},
	}

	err := clavenar.InspectAll(context.Background(), calls, opts)
	var denied *clavenar.Denied
	var pending *clavenar.Pending
	switch {
	case errors.As(err, &denied):
		log.Printf("blocked %s: %v", denied.ToolName, denied.Reasons)
	case errors.As(err, &pending):
		log.Printf("parked %s for review; waiting for an operator...", pending.ToolName)
		if err := pending.Resolve(context.Background(), nil); err != nil {
			log.Printf("not approved: %v", err)
			return
		}
		log.Printf("approved — dispatch %s", pending.ToolName)
	case err != nil:
		log.Fatalf("clavenar transport/config error: %v", err)
	default:
		log.Printf("all %d tool call(s) cleared — dispatch them", len(calls))
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
