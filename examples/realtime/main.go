// Command realtime shows gating OpenAI Realtime function calls: inspect
// each response.function_call_arguments.done event before dispatching
// the tool from your websocket message pump.
package main

import (
	"context"
	"log"
	"os"

	clavenar "github.com/clavenar/clavenar-go-sdk"
)

func main() {
	opts := clavenar.New(envOr("CLAVENAR_ENDPOINT", "http://localhost:8088"))

	// In a real WS pump you'd assemble this from response.output_item.added
	// (call_id + name) and response.function_call_arguments.done (arguments).
	evt := clavenar.RealtimeFunctionCallDone{
		CallID:    "call_42",
		Name:      "wire_transfer",
		Arguments: `{"amount":5000,"to":"external"}`,
	}

	v, err := clavenar.InspectRealtimeFunctionCall(context.Background(), evt, opts)
	if err != nil {
		log.Fatalf("inspect failed: %v", err)
	}
	switch v.Kind {
	case clavenar.VerdictDeny:
		// Send a function_call_output item back over the WS describing the deny.
		log.Printf("deny %s: %v", evt.Name, v.Reasons)
	case clavenar.VerdictPending:
		log.Printf("pending %s (correlation %s)", evt.Name, v.CorrelationID)
	case clavenar.VerdictRateLimited:
		// Back off (v.RetryAfterSecs when set) before re-sending the call.
		log.Printf("rate limited %s: %v", evt.Name, v.Reasons)
	default:
		log.Printf("allow — dispatch %s", evt.Name)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
