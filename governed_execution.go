package clavenar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	// ExecutionContract is the authorization and terminal receipt wire contract.
	ExecutionContract = "clavenar.execution/v1"
	// DurableExecutionContract is the application-owned intent/outbox contract.
	DurableExecutionContract = "clavenar.sdk-durable-intent-outbox/v1"
)

// PreparedToolRequest retains a stable identity allocated before network access.
type PreparedToolRequest struct {
	IdempotencyID string          `json:"idempotency_id"`
	Name          string          `json:"name"`
	Arguments     json.RawMessage `json:"arguments"`
}

// PrepareToolRequest creates a serializable request with a canonical UUID.
func PrepareToolRequest(name string, arguments json.RawMessage) (PreparedToolRequest, error) {
	id, err := newUUID()
	if err != nil {
		return PreparedToolRequest{}, &ConfigError{Msg: "clavenar: failed to allocate request identity: " + err.Error()}
	}
	return RestoreToolRequest(id, name, arguments)
}

// RestoreToolRequest validates a previously persisted request without replacing its identity.
func RestoreToolRequest(idempotencyID, name string, arguments json.RawMessage) (PreparedToolRequest, error) {
	prepared := PreparedToolRequest{IdempotencyID: idempotencyID, Name: name, Arguments: arguments}
	if err := validatePreparedToolRequest(prepared); err != nil {
		return PreparedToolRequest{}, err
	}
	return prepared, nil
}

// Authorization is the exact execution payload and verified decision binding.
type Authorization struct {
	Contract              string          `json:"contract"`
	Stage                 string          `json:"stage"`
	AuthorizationID       string          `json:"authorization_id"`
	IdempotencyID         string          `json:"idempotency_id"`
	CorrelationID         string          `json:"correlation_id"`
	AgentID               string          `json:"agent_id"`
	AgentSPIFFE           string          `json:"agent_spiffe"`
	Tenant                string          `json:"tenant"`
	CredentialFingerprint string          `json:"credential_fingerprint"`
	Method                string          `json:"method"`
	ToolName              string          `json:"tool_name"`
	ExecutionPayload      json.RawMessage `json:"execution_payload"`
	PayloadSHA256         string          `json:"payload_sha256"`
	DecisionPrincipal     json.RawMessage `json:"decision_principal"`
	ModificationDiff      json.RawMessage `json:"modification_diff"`
	PolicyBundle          json.RawMessage `json:"policy_bundle"`
	BrainVersion          string          `json:"brain_version"`
	BrainEvidenceSHA256   string          `json:"brain_evidence_sha256"`
}

// SignedAuthorization includes Identity's signature over Authorization.
type SignedAuthorization struct {
	Authorization     Authorization   `json:"authorization"`
	IdentitySignature json.RawMessage `json:"identity_signature"`
}

// ToolExecutionRequest is the only input released to the registered executor.
type ToolExecutionRequest struct {
	AuthorizationID  string          `json:"authorization_id"`
	IdempotencyID    string          `json:"idempotency_id"`
	ExecutorID       string          `json:"executor_id"`
	ExecutionPayload json.RawMessage `json:"execution_payload"`
}

// ExecutionEffect is the executor's actual result and provider effect identity.
type ExecutionEffect struct {
	Result   json.RawMessage `json:"result"`
	EffectID string          `json:"effect_id"`
}

// ExecutionIntent is committed before the registered executor is invoked.
type ExecutionIntent struct {
	Contract        string              `json:"contract"`
	Stage           string              `json:"stage"`
	AuthorizationID string              `json:"authorization_id"`
	IdempotencyID   string              `json:"idempotency_id"`
	Tenant          string              `json:"tenant"`
	WorkloadID      string              `json:"workload_id"`
	WorkloadSPIFFE  string              `json:"workload_spiffe"`
	PayloadSHA256   string              `json:"payload_sha256"`
	ExecutorID      string              `json:"executor_id"`
	Authorization   SignedAuthorization `json:"authorization"`
}

// WorkloadSignature is supplied by the private key for the active workload SVID.
type WorkloadSignature struct {
	Algorithm             string `json:"algorithm"`
	CredentialFingerprint string `json:"credential_fingerprint"`
	Value                 string `json:"value"`
}

// UnsignedExecutionReceipt contains every terminal binding covered by the signer.
type UnsignedExecutionReceipt struct {
	Contract              string              `json:"contract"`
	Stage                 string              `json:"stage"`
	AuthorizationID       string              `json:"authorization_id"`
	IdempotencyID         string              `json:"idempotency_id"`
	CorrelationID         string              `json:"correlation_id"`
	AgentID               string              `json:"agent_id"`
	AgentSPIFFE           string              `json:"agent_spiffe"`
	Tenant                string              `json:"tenant"`
	CredentialFingerprint string              `json:"credential_fingerprint"`
	Method                string              `json:"method"`
	PayloadSHA256         string              `json:"payload_sha256"`
	Authorization         SignedAuthorization `json:"authorization"`
	ResultSHA256          string              `json:"result_sha256"`
	EffectID              string              `json:"effect_id"`
}

// ExecutionReceipt is atomically retained with the actual completion.
type ExecutionReceipt struct {
	UnsignedExecutionReceipt
	WorkloadSignature WorkloadSignature `json:"workload_signature"`
}

// ExecutionCompletion is the application's atomic result plus receipt outbox record.
type ExecutionCompletion struct {
	Contract           string           `json:"contract"`
	Stage              string           `json:"stage"`
	AuthorizationID    string           `json:"authorization_id"`
	IdempotencyID      string           `json:"idempotency_id"`
	ExecutorID         string           `json:"executor_id"`
	ActualResult       json.RawMessage  `json:"actual_result"`
	ActualResultSHA256 string           `json:"actual_result_sha256"`
	EffectID           string           `json:"effect_id"`
	Receipt            ExecutionReceipt `json:"receipt"`
}

// DurableExecutionStore owns the pre-effect intent and terminal receipt outbox transaction.
type DurableExecutionStore interface {
	CommitIntent(context.Context, ExecutionIntent) error
	CommitCompletionAndEnqueueReceipt(context.Context, ExecutionCompletion) error
}

// ToolExecutor is the sole callback allowed to produce an SDK-governed effect.
type ToolExecutor func(context.Context, ToolExecutionRequest) (ExecutionEffect, error)

// ReceiptSigner signs the exact terminal receipt using the active workload key.
type ReceiptSigner func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error)

// GovernedExecutionOptions configures explicit side-effect-free authorization and execution.
type GovernedExecutionOptions struct {
	Decision   Options
	ExecutorID string
	Executor   ToolExecutor
	Store      DurableExecutionStore
	Signer     ReceiptSigner
}

// GovernedExecutionOutcome returns only the actual effect and retained receipt.
type GovernedExecutionOutcome struct {
	Result        json.RawMessage  `json:"result"`
	EffectID      string           `json:"effect_id"`
	IdempotencyID string           `json:"idempotency_id"`
	Receipt       ExecutionReceipt `json:"receipt"`
}

// ExecuteTool prepares and executes one exact tool request.
func ExecuteTool(
	ctx context.Context,
	name string,
	arguments json.RawMessage,
	opts GovernedExecutionOptions,
) (GovernedExecutionOutcome, error) {
	prepared, err := PrepareToolRequest(name, arguments)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	return ExecutePreparedTool(ctx, prepared, opts)
}

// ExecutePreparedTool authorizes without a server effect, commits intent,
// invokes the registered executor once, and retains completion plus receipt.
func ExecutePreparedTool(
	ctx context.Context,
	prepared PreparedToolRequest,
	opts GovernedExecutionOptions,
) (GovernedExecutionOutcome, error) {
	if err := validatePreparedToolRequest(prepared); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if err := validateGovernedOptions(opts); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	body, err := json.Marshal(inspectRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  inspectParams{Name: prepared.Name, Arguments: prepared.Arguments},
		ID:      prepared.IdempotencyID,
	})
	if err != nil {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: failed to encode prepared request: " + err.Error()}
	}
	signed, err := requestAuthorization(ctx, body, prepared.IdempotencyID, opts.Decision.withDefaults())
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if err := validateAuthorization(signed, prepared, body); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	auth := signed.Authorization
	intent := ExecutionIntent{
		Contract:        DurableExecutionContract,
		Stage:           "execution.intent",
		AuthorizationID: auth.AuthorizationID,
		IdempotencyID:   auth.IdempotencyID,
		Tenant:          auth.Tenant,
		WorkloadID:      auth.AgentID,
		WorkloadSPIFFE:  auth.AgentSPIFFE,
		PayloadSHA256:   auth.PayloadSHA256,
		ExecutorID:      opts.ExecutorID,
		Authorization:   signed,
	}
	if err := opts.Store.CommitIntent(ctx, intent); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	effect, err := opts.Executor(ctx, ToolExecutionRequest{
		AuthorizationID:  auth.AuthorizationID,
		IdempotencyID:    auth.IdempotencyID,
		ExecutorID:       opts.ExecutorID,
		ExecutionPayload: auth.ExecutionPayload,
	})
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if effect.EffectID == "" || !json.Valid(effect.Result) {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: executor returned an invalid effect"}
	}
	resultSHA256, err := hashCanonicalJSON(effect.Result)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	unsigned := UnsignedExecutionReceipt{
		Contract:              ExecutionContract,
		Stage:                 "execution.completed",
		AuthorizationID:       auth.AuthorizationID,
		IdempotencyID:         auth.IdempotencyID,
		CorrelationID:         auth.CorrelationID,
		AgentID:               auth.AgentID,
		AgentSPIFFE:           auth.AgentSPIFFE,
		Tenant:                auth.Tenant,
		CredentialFingerprint: auth.CredentialFingerprint,
		Method:                auth.Method,
		PayloadSHA256:         auth.PayloadSHA256,
		Authorization:         signed,
		ResultSHA256:          resultSHA256,
		EffectID:              effect.EffectID,
	}
	signature, err := opts.Signer(ctx, unsigned)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if signature.Algorithm == "" || signature.CredentialFingerprint == "" || signature.Value == "" {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: receipt signer returned an invalid signature"}
	}
	receipt := ExecutionReceipt{UnsignedExecutionReceipt: unsigned, WorkloadSignature: signature}
	completion := ExecutionCompletion{
		Contract:           DurableExecutionContract,
		Stage:              "execution.completed",
		AuthorizationID:    auth.AuthorizationID,
		IdempotencyID:      auth.IdempotencyID,
		ExecutorID:         opts.ExecutorID,
		ActualResult:       effect.Result,
		ActualResultSHA256: resultSHA256,
		EffectID:           effect.EffectID,
		Receipt:            receipt,
	}
	if err := opts.Store.CommitCompletionAndEnqueueReceipt(ctx, completion); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	return GovernedExecutionOutcome{
		Result:        effect.Result,
		EffectID:      effect.EffectID,
		IdempotencyID: auth.IdempotencyID,
		Receipt:       receipt,
	}, nil
}

func requestAuthorization(
	ctx context.Context,
	body []byte,
	idempotencyID string,
	o Options,
) (SignedAuthorization, error) {
	var lastErr error
	for attempt := 0; attempt < o.Retry.MaxAttempts; attempt++ {
		signed, err := requestAuthorizationOnce(ctx, body, idempotencyID, o)
		if err == nil {
			return signed, nil
		}
		var transportErr *TransportError
		if !errors.As(err, &transportErr) || !isRetriable(transportErr) || attempt+1 == o.Retry.MaxAttempts {
			return SignedAuthorization{}, err
		}
		lastErr = err
		if err := sleepCtx(ctx, backoff(o.Retry.BaseDelay, attempt)); err != nil {
			return SignedAuthorization{}, err
		}
	}
	return SignedAuthorization{}, lastErr
}

func requestAuthorizationOnce(
	ctx context.Context,
	body []byte,
	idempotencyID string,
	o Options,
) (SignedAuthorization, error) {
	rctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, joinURL(o.Endpoint, "/mcp"), bytes.NewReader(body))
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization: failed to build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(decisionContractHeader, decisionContract)
	req.Header.Set(idempotencyIDHeader, idempotencyID)
	if o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.Token)
	}
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization failed: " + err.Error()}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization: failed to read response: " + err.Error(), Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return SignedAuthorization{}, &TransportError{
			Msg:    fmt.Sprintf("clavenar authorization: unexpected status %d: %s", resp.StatusCode, data),
			Status: resp.StatusCode,
		}
	}
	var signed SignedAuthorization
	if err := json.Unmarshal(data, &signed); err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization: invalid body: " + err.Error(), Status: resp.StatusCode}
	}
	return signed, nil
}

func validatePreparedToolRequest(prepared PreparedToolRequest) error {
	if !validUUID(prepared.IdempotencyID) {
		return &ConfigError{Msg: "clavenar: prepared idempotency id must be a UUID"}
	}
	if prepared.Name == "" || !json.Valid(prepared.Arguments) {
		return &ConfigError{Msg: "clavenar: prepared tool name and JSON arguments are required"}
	}
	return nil
}

func validateGovernedOptions(opts GovernedExecutionOptions) error {
	if err := opts.Decision.validate(); err != nil {
		return err
	}
	if opts.ExecutorID == "" || opts.Executor == nil || opts.Store == nil || opts.Signer == nil {
		return &ConfigError{Msg: "clavenar: executor id, executor, durable store, and receipt signer are required"}
	}
	return nil
}

func validateAuthorization(signed SignedAuthorization, prepared PreparedToolRequest, body []byte) error {
	auth := signed.Authorization
	if auth.Contract != ExecutionContract || auth.Stage != "authorization" {
		return &ConfigError{Msg: "clavenar: invalid governed execution authorization contract"}
	}
	if auth.IdempotencyID != prepared.IdempotencyID {
		return &ConfigError{Msg: "clavenar: authorization changed the idempotency identity"}
	}
	if !validUUID(auth.AuthorizationID) || !validUUID(auth.CorrelationID) {
		return &ConfigError{Msg: "clavenar: authorization contains an invalid UUID"}
	}
	if auth.AgentID == "" || auth.AgentSPIFFE == "" || auth.Tenant == "" || auth.PayloadSHA256 == "" {
		return &ConfigError{Msg: "clavenar: authorization is missing an execution binding"}
	}
	if len(auth.ModificationDiff) == 0 || bytes.Equal(bytes.TrimSpace(auth.ModificationDiff), []byte("null")) {
		left, err := canonicalJSON(auth.ExecutionPayload)
		if err != nil {
			return err
		}
		right, err := canonicalJSON(body)
		if err != nil {
			return err
		}
		if !bytes.Equal(left, right) {
			return &ConfigError{Msg: "clavenar: authorization changed an unmodified execution payload"}
		}
	}
	return nil
}

func hashCanonicalJSON(raw json.RawMessage) (string, error) {
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalJSON(raw []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, &ConfigError{Msg: "clavenar: invalid JSON value: " + err.Error()}
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, &ConfigError{Msg: "clavenar: failed to canonicalize JSON: " + err.Error()}
	}
	return canonical, nil
}
