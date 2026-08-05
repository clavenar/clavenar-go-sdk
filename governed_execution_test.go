package clavenar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureID = "cfcc8767-4c73-41cc-8ece-b855863924c4"

type recordingStore struct {
	order      *[]string
	intent     ExecutionIntent
	completion ExecutionCompletion
	failIntent bool
}

func (s *recordingStore) LoadExecution(_ context.Context, _ string) (ExecutionState, error) {
	state := ExecutionState{}
	if s.intent.IdempotencyID != "" {
		intent := s.intent
		state.Intent = &intent
	}
	if s.completion.IdempotencyID != "" {
		completion := s.completion
		state.Completion = &completion
	}
	return state, nil
}

func (s *recordingStore) CommitIntent(_ context.Context, intent ExecutionIntent) error {
	*s.order = append(*s.order, "intent")
	if s.failIntent {
		return errors.New("store unavailable")
	}
	s.intent = intent
	return nil
}

func (s *recordingStore) CommitCompletionAndEnqueueReceipt(
	_ context.Context,
	completion ExecutionCompletion,
) error {
	*s.order = append(*s.order, "completion")
	s.completion = completion
	return nil
}

func TestExecutePreparedToolDurableOrderAndActualResult(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	body := fixtureAuthorization(t, prepared)
	var gotDecision, gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDecision = r.Header.Get(decisionContractHeader)
		gotID = r.Header.Get(idempotencyIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	order := []string{}
	store := &recordingStore{order: &order}
	outcome, err := ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision:            New(srv.URL),
		ExecutorID:          "payments-provider",
		Store:               store,
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return nil },
		Executor: func(_ context.Context, request ToolExecutionRequest) (ExecutionEffect, error) {
			order = append(order, "effect")
			if request.IdempotencyID != fixtureID {
				t.Fatalf("executor idempotency id = %q", request.IdempotencyID)
			}
			return ExecutionEffect{Result: json.RawMessage(`{"ok":true}`), EffectID: "provider-operation-123"}, nil
		},
		Signer: func(_ context.Context, _ UnsignedExecutionReceipt) (WorkloadSignature, error) {
			return WorkloadSignature{
				Algorithm:             "ES256",
				CredentialFingerprint: "sha256:" + repeat("1", 64),
				Value:                 "signed",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"intent", "effect", "completion"}) {
		t.Fatalf("order = %v", order)
	}
	if gotDecision != decisionContract || gotID != fixtureID {
		t.Fatalf("decision headers contract=%q id=%q", gotDecision, gotID)
	}
	if string(outcome.Result) != `{"ok":true}` || outcome.EffectID != "provider-operation-123" {
		t.Fatalf("outcome = %+v", outcome)
	}
	wantHash := "sha256:4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93"
	if store.completion.ActualResultSHA256 != wantHash {
		t.Fatalf("result hash = %q", store.completion.ActualResultSHA256)
	}
}

func TestExecutePreparedToolIntentFailureInvokesNoExecutor(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixtureAuthorization(t, prepared))
	}))
	defer srv.Close()
	order := []string{}
	called := false
	_, err = ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision:            New(srv.URL),
		ExecutorID:          "payments-provider",
		Store:               &recordingStore{order: &order, failIntent: true},
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return nil },
		Executor: func(context.Context, ToolExecutionRequest) (ExecutionEffect, error) {
			called = true
			return ExecutionEffect{}, nil
		},
		Signer: func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error) {
			return WorkloadSignature{}, nil
		},
	})
	if err == nil || err.Error() != "store unavailable" {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("executor ran after intent failure")
	}
}

func TestExecutePreparedToolNeverRetriesExecutorFailure(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	var decisions, effects int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&decisions, 1)
		_, _ = w.Write(fixtureAuthorization(t, prepared))
	}))
	defer srv.Close()
	order := []string{}
	_, err = ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision:            New(srv.URL, WithRetry(Retry{MaxAttempts: 3, BaseDelay: time.Millisecond})),
		ExecutorID:          "payments-provider",
		Store:               &recordingStore{order: &order},
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return nil },
		Executor: func(context.Context, ToolExecutionRequest) (ExecutionEffect, error) {
			atomic.AddInt32(&effects, 1)
			return ExecutionEffect{}, errors.New("provider response lost")
		},
		Signer: func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error) {
			t.Fatal("signer ran after executor failure")
			return WorkloadSignature{}, nil
		},
	})
	if err == nil || err.Error() != "provider response lost" {
		t.Fatalf("error = %v", err)
	}
	if atomic.LoadInt32(&decisions) != 1 || atomic.LoadInt32(&effects) != 1 {
		t.Fatalf("decision/effect attempts = %d/%d, want 1/1", decisions, effects)
	}
}

func TestInspectBatchUsesOneOrderedDecision(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, err := InspectBatch(context.Background(), []ToolCall{
		{ID: "call-a", Name: "first", Input: json.RawMessage(`{"n":1}`)},
		{ID: "call-b", Name: "second", Input: json.RawMessage(`{"n":2}`)},
	}, New(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if payload["method"] != "clavenar/tools.batch" {
		t.Fatalf("method = %v", payload["method"])
	}
	params := payload["params"].(map[string]any)
	arguments := params["arguments"].(map[string]any)
	calls := arguments["calls"].([]any)
	if calls[0].(map[string]any)["id"] != "call-a" || calls[1].(map[string]any)["id"] != "call-b" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestExecutePreparedToolRejectsUnverifiedAuthorization(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixtureAuthorization(t, prepared))
	}))
	defer srv.Close()
	order := []string{}
	_, err = ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision:   New(srv.URL),
		ExecutorID: "payments-provider",
		Store:      &recordingStore{order: &order},
		Executor: func(context.Context, ToolExecutionRequest) (ExecutionEffect, error) {
			t.Fatal("executor ran")
			return ExecutionEffect{}, nil
		},
		Signer: func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error) {
			return WorkloadSignature{}, nil
		},
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return errors.New("unknown identity key") },
	})
	var ce *ConfigError
	if !errors.As(err, &ce) || !strings.Contains(ce.Msg, "signature verification failed") {
		t.Fatalf("want signature verification ConfigError, got %v", err)
	}
	if len(order) != 0 {
		t.Fatalf("unverified authorization reached durable store: %v", order)
	}
}

func TestExecutePreparedToolFailsClosedOnUnreconciledIntent(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	signed := fixtureSignedAuthorization(t, prepared)
	auth := signed.Authorization
	order := []string{}
	store := &recordingStore{order: &order, intent: ExecutionIntent{
		Contract: DurableExecutionContract, Stage: "execution.intent", AuthorizationID: auth.AuthorizationID,
		IdempotencyID: auth.IdempotencyID, Tenant: auth.Tenant, WorkloadID: auth.AgentID,
		WorkloadSPIFFE: auth.AgentSPIFFE, PayloadSHA256: auth.PayloadSHA256,
		ExecutorID: "payments-provider", Authorization: signed,
	}}
	_, err = ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision: New("https://clavenar.invalid"), ExecutorID: "payments-provider", Store: store,
		Executor: func(context.Context, ToolExecutionRequest) (ExecutionEffect, error) {
			t.Fatal("executor repeated an indeterminate effect")
			return ExecutionEffect{}, nil
		},
		Signer: func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error) {
			return WorkloadSignature{}, nil
		},
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return nil },
	})
	var recovery *RecoveryRequired
	if !errors.As(err, &recovery) || recovery.IdempotencyID != fixtureID {
		t.Fatalf("want RecoveryRequired, got %v", err)
	}
}

func TestExecutePreparedToolRecoversEffectWithoutRepeatingExecutor(t *testing.T) {
	prepared, err := RestoreToolRequest(fixtureID, "payments.transfer", json.RawMessage(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	signed := fixtureSignedAuthorization(t, prepared)
	auth := signed.Authorization
	order := []string{}
	store := &recordingStore{order: &order, intent: ExecutionIntent{
		Contract: DurableExecutionContract, Stage: "execution.intent", AuthorizationID: auth.AuthorizationID,
		IdempotencyID: auth.IdempotencyID, Tenant: auth.Tenant, WorkloadID: auth.AgentID,
		WorkloadSPIFFE: auth.AgentSPIFFE, PayloadSHA256: auth.PayloadSHA256,
		ExecutorID: "payments-provider", Authorization: signed,
	}}
	outcome, err := ExecutePreparedTool(context.Background(), prepared, GovernedExecutionOptions{
		Decision: New("https://clavenar.invalid"), ExecutorID: "payments-provider", Store: store,
		Executor: func(context.Context, ToolExecutionRequest) (ExecutionEffect, error) {
			t.Fatal("executor repeated a recovered effect")
			return ExecutionEffect{}, nil
		},
		Recoverer: func(context.Context, ExecutionIntent) (ExecutionEffect, bool, error) {
			return ExecutionEffect{Result: json.RawMessage(`{"ok":true}`), EffectID: "provider-operation-123"}, true, nil
		},
		Signer: func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error) {
			return WorkloadSignature{Algorithm: "ES256", CredentialFingerprint: auth.CredentialFingerprint, Value: "signed"}, nil
		},
		AuthorizationVerify: func(context.Context, SignedAuthorization) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.EffectID != "provider-operation-123" || store.completion.EffectID != outcome.EffectID {
		t.Fatalf("recovered outcome = %+v", outcome)
	}
}

func TestCanonicalJSONPreservesLargeInteger(t *testing.T) {
	got, err := canonicalJSON([]byte(`{"value":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"value":9007199254740993}` {
		t.Fatalf("large integer changed during canonicalization: %s", got)
	}
}

func TestCanonicalJSONRejectsIntegersOutsideSupportedRange(t *testing.T) {
	for _, raw := range []string{
		`{"value":18446744073709551616}`,
		`{"value":-9223372036854775809}`,
	} {
		if _, err := canonicalJSON([]byte(raw)); err == nil {
			t.Fatalf("canonicalJSON(%s) unexpectedly accepted an out-of-range integer", raw)
		}
	}
}

func TestRestoreToolRequestAppliesInspectionInputLimits(t *testing.T) {
	_, err := RestoreToolRequest(
		fixtureID,
		"payments.transfer",
		json.RawMessage(strings.Repeat("x", maxToolArgumentsBytes+1)),
	)
	var configErr *ConfigError
	if !errors.As(err, &configErr) || !strings.Contains(configErr.Msg, "safety limit") {
		t.Fatalf("want bounded prepared-request ConfigError, got %v", err)
	}
}

func fixtureSignedAuthorization(t *testing.T, prepared PreparedToolRequest) SignedAuthorization {
	t.Helper()
	var signed SignedAuthorization
	if err := json.Unmarshal(fixtureAuthorization(t, prepared), &signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

func fixtureAuthorization(t *testing.T, prepared PreparedToolRequest) []byte {
	t.Helper()
	payload, err := json.Marshal(inspectRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  inspectParams{Name: prepared.Name, Arguments: prepared.Arguments},
		ID:      prepared.IdempotencyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA256, err := hashCanonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedAuthorization{
		Authorization: Authorization{
			Contract:              ExecutionContract,
			Stage:                 "authorization",
			AuthorizationID:       "354c33ed-e5d3-4af7-a1b8-b009d50b0bc5",
			IdempotencyID:         prepared.IdempotencyID,
			CorrelationID:         "c1a28e4c-a17d-5b3d-884b-e5b627f762c2",
			AgentID:               "payments-agent",
			AgentSPIFFE:           "spiffe://clavenar.local/tenant/acme/agent/payments-agent/instance/one",
			Tenant:                "acme",
			CredentialFingerprint: "sha256:" + repeat("1", 64),
			Method:                "tools/call",
			ToolName:              prepared.Name,
			ExecutionPayload:      payload,
			PayloadSHA256:         payloadSHA256,
			DecisionPrincipal:     json.RawMessage(`{"subject":"system:policy-brain"}`),
			ModificationDiff:      json.RawMessage(`null`),
			PolicyBundle:          json.RawMessage(`{"schema_version":1}`),
			BrainVersion:          "brain-fixture",
			BrainEvidenceSHA256:   "sha256:" + repeat("3", 64),
		},
		IdentitySignature: json.RawMessage(`{"algorithm":"Ed25519","value":"signed"}`),
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
