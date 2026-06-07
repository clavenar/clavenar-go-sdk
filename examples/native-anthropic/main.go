// Command native-anthropic wraps the official anthropic-sdk-go so every
// tool call Claude emits is inspected by clavenar before your tool loop
// runs it.
package main

import (
	"context"
	"errors"
	"log"
	"os"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	clavenar "github.com/clavenar/clavenar-go-sdk"
	clavenaranthropic "github.com/clavenar/clavenar-go-sdk/adapters/anthropic"
)

func main() {
	base := anthropic.NewClient(option.WithAPIKey(os.Getenv("ANTHROPIC_API_KEY")))
	messages := clavenaranthropic.WrapMessages(&base, clavenar.New(
		envOr("CLAVENAR_ENDPOINT", "http://localhost:8088"),
		clavenar.WithToken(os.Getenv("CLAVENAR_LITE_TOKEN")),
	))

	msg, err := messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.Model("claude-sonnet-4-5"),
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("delete the alice user")),
		},
	})

	var denied *clavenar.Denied
	var pending *clavenar.Pending
	switch {
	case errors.As(err, &denied):
		log.Printf("blocked tool %q: %v", denied.ToolName, denied.Reasons)
	case errors.As(err, &pending):
		log.Printf("tool %q parked for review (%s)", pending.ToolName, pending.CorrelationID)
	case err != nil:
		log.Fatal(err)
	default:
		// Your tool loop only ever sees policy-cleared tool_use blocks.
		log.Printf("response cleared: %d content block(s)", len(msg.Content))
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
