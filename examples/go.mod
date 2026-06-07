module github.com/clavenar/clavenar-go-sdk/examples

go 1.24

require (
	github.com/anthropics/anthropic-sdk-go v1.48.0
	github.com/clavenar/clavenar-go-sdk v0.0.0
	github.com/clavenar/clavenar-go-sdk/adapters/anthropic v0.0.0
	github.com/clavenar/clavenar-go-sdk/adapters/openai v0.0.0
	github.com/openai/openai-go/v2 v2.7.1
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/standard-webhooks/standard-webhooks/libraries v0.0.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/sync v0.16.0 // indirect
)

replace github.com/clavenar/clavenar-go-sdk => ..

replace github.com/clavenar/clavenar-go-sdk/adapters/anthropic => ../adapters/anthropic

replace github.com/clavenar/clavenar-go-sdk/adapters/openai => ../adapters/openai
