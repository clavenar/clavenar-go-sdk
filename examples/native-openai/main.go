// Command native-openai wraps the official openai-go client so every
// tool call the model emits is inspected by clavenar before your tool
// loop runs it.
package main

import (
	"context"
	"errors"
	"log"
	"os"

	clavenar "github.com/clavenar/clavenar-go-sdk"
	clavenaropenai "github.com/clavenar/clavenar-go-sdk/adapters/openai"
	openai "github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
)

func main() {
	base := openai.NewClient(option.WithAPIKey(os.Getenv("OPENAI_API_KEY")))
	completions := clavenaropenai.WrapCompletions(&base, clavenar.New(
		envOr("CLAVENAR_ENDPOINT", "http://localhost:8088"),
		clavenar.WithToken(os.Getenv("CLAVENAR_LITE_TOKEN")),
	))

	completion, err := completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model: openai.ChatModelGPT4o,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("delete the alice user"),
		},
	})

	var denied *clavenar.Denied
	switch {
	case errors.As(err, &denied):
		log.Printf("blocked tool %q: %v", denied.ToolName, denied.Reasons)
	case err != nil:
		log.Fatal(err)
	default:
		log.Printf("response cleared: %d choice(s)", len(completion.Choices))
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
