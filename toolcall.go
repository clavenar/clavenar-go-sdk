package clavenar

import "encoding/json"

// ToolCall is the provider-agnostic shape clavenar inspects. Anthropic
// tool_use blocks and OpenAI tool_calls normalize into this; Input is
// the model's exact argument bytes, forwarded without re-encoding.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// VerdictKind is the outcome clavenar returned for one tool call.
type VerdictKind int

const (
	// VerdictAllow: the call cleared policy.
	VerdictAllow VerdictKind = iota
	// VerdictDeny: policy rejected the call.
	VerdictDeny
	// VerdictPending: the call was parked for human review.
	VerdictPending
)

func (k VerdictKind) String() string {
	switch k {
	case VerdictAllow:
		return "allow"
	case VerdictDeny:
		return "deny"
	case VerdictPending:
		return "pending"
	default:
		return "unknown"
	}
}

// Verdict is the result of inspecting one tool call. Inspect returns it
// directly; InspectAll turns Deny / Pending into *Denied / *Pending in
// enforce mode.
type Verdict struct {
	Kind VerdictKind
	// CorrelationID is the x-clavenar-correlation-id response header,
	// when the deployment sets it — opaque to the SDK, load-bearing for
	// ledger lookups.
	CorrelationID string
	// Reasons, ReviewReasons, IntentCategory and Layer are populated on
	// Deny (Layer only when the server reports it). ReviewReasons is
	// also set on Pending.
	Reasons        []string
	ReviewReasons  []string
	IntentCategory string
	Layer          string
}

// VerdictContext identifies the tool call an OnVerdict / OnPolicyError
// callback fired for.
type VerdictContext struct {
	ToolName  string
	ToolUseID string
	ToolInput json.RawMessage
}

// PendingView is the body of GET /pending/{id}. Decision is nil until an
// operator decides; Pending.Resolve watches it.
type PendingView struct {
	CorrelationID string   `json:"correlation_id"`
	AgentID       string   `json:"agent_id"`
	ToolType      string   `json:"tool_type"`
	Method        string   `json:"method"`
	ReviewReasons []string `json:"review_reasons"`
	RequestedAt   string   `json:"requested_at"`
	DecidedAt     *string  `json:"decided_at"`
	Decision      *string  `json:"decision"`
	DeciderNote   *string  `json:"decider_note"`
}
