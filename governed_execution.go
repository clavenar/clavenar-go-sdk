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
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	// LoadExecution returns the durable state for one stable idempotency ID.
	// A zero ExecutionState means no intent has been committed yet.
	LoadExecution(context.Context, string) (ExecutionState, error)
	CommitIntent(context.Context, ExecutionIntent) error
	CommitCompletionAndEnqueueReceipt(context.Context, ExecutionCompletion) error
}

// ExecutionState is the resumable state of one governed execution. Completion
// implies that Intent has also been durably retained.
type ExecutionState struct {
	Intent     *ExecutionIntent     `json:"intent,omitempty"`
	Completion *ExecutionCompletion `json:"completion,omitempty"`
}

// ToolExecutor is the sole callback allowed to produce an SDK-governed effect.
// Implementations must use request.IdempotencyID at the provider boundary.
type ToolExecutor func(context.Context, ToolExecutionRequest) (ExecutionEffect, error)

// EffectRecoverer reconciles an intent whose executor may already have run.
// It returns found=true only with the conclusive provider result; false is
// treated as ambiguous and never authorizes a second executor invocation.
type EffectRecoverer func(context.Context, ExecutionIntent) (effect ExecutionEffect, found bool, err error)

// AuthorizationVerifier cryptographically verifies Identity's signature over
// the exact SignedAuthorization. The SDK validates all structural bindings
// before invoking this callback.
type AuthorizationVerifier func(context.Context, SignedAuthorization) error

// ReceiptSigner signs the exact terminal receipt using the active workload key.
type ReceiptSigner func(context.Context, UnsignedExecutionReceipt) (WorkloadSignature, error)

// GovernedExecutionOptions configures explicit side-effect-free authorization and execution.
type GovernedExecutionOptions struct {
	Decision            Options
	ExecutorID          string
	Executor            ToolExecutor
	Recoverer           EffectRecoverer
	Store               DurableExecutionStore
	Signer              ReceiptSigner
	AuthorizationVerify AuthorizationVerifier
	// FinalizationTimeout bounds signing and durable completion after an
	// effect succeeds. Zero uses 30 seconds. Caller cancellation does not
	// interrupt this post-effect critical section.
	FinalizationTimeout time.Duration
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
	state, err := opts.Store.LoadExecution(ctx, prepared.IdempotencyID)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if state.Completion != nil {
		return recoveredCompletion(ctx, prepared, body, opts, state)
	}
	if state.Intent != nil {
		if err := validateStoredIntent(ctx, *state.Intent, prepared, body, opts); err != nil {
			return GovernedExecutionOutcome{}, err
		}
		if opts.Recoverer == nil {
			return GovernedExecutionOutcome{}, &RecoveryRequired{IdempotencyID: prepared.IdempotencyID}
		}
		effect, found, err := opts.Recoverer(ctx, *state.Intent)
		if err != nil {
			return GovernedExecutionOutcome{}, err
		}
		if !found {
			return GovernedExecutionOutcome{}, &RecoveryRequired{IdempotencyID: prepared.IdempotencyID}
		}
		return completeExecution(ctx, state.Intent.Authorization, effect, opts)
	}
	signed, err := requestAuthorization(ctx, body, prepared.IdempotencyID, opts.Decision.withDefaults())
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if err := validateAuthorization(signed, prepared, body); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if err := opts.AuthorizationVerify(ctx, signed); err != nil {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: authorization signature verification failed: " + err.Error()}
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
	return completeExecution(ctx, signed, effect, opts)
}

func completeExecution(
	ctx context.Context,
	signed SignedAuthorization,
	effect ExecutionEffect,
	opts GovernedExecutionOptions,
) (GovernedExecutionOutcome, error) {
	auth := signed.Authorization
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
	finalizationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.finalizationTimeout())
	defer cancel()
	signature, err := opts.Signer(finalizationCtx, unsigned)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if signature.Algorithm == "" || signature.CredentialFingerprint == "" || signature.Value == "" {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: receipt signer returned an invalid signature"}
	}
	if signature.CredentialFingerprint != auth.CredentialFingerprint {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: receipt signer credential does not match the authorization"}
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
	if err := opts.Store.CommitCompletionAndEnqueueReceipt(finalizationCtx, completion); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	return GovernedExecutionOutcome{
		Result:        effect.Result,
		EffectID:      effect.EffectID,
		IdempotencyID: auth.IdempotencyID,
		Receipt:       receipt,
	}, nil
}

func (opts GovernedExecutionOptions) finalizationTimeout() time.Duration {
	if opts.FinalizationTimeout == 0 {
		return 30 * time.Second
	}
	return opts.FinalizationTimeout
}

func validateStoredIntent(
	ctx context.Context,
	intent ExecutionIntent,
	prepared PreparedToolRequest,
	body []byte,
	opts GovernedExecutionOptions,
) error {
	if intent.Contract != DurableExecutionContract || intent.Stage != "execution.intent" ||
		intent.IdempotencyID != prepared.IdempotencyID || intent.ExecutorID != opts.ExecutorID {
		return &ConfigError{Msg: "clavenar: stored execution intent does not match the prepared request"}
	}
	if err := validateAuthorization(intent.Authorization, prepared, body); err != nil {
		return err
	}
	auth := intent.Authorization.Authorization
	if intent.AuthorizationID != auth.AuthorizationID || intent.Tenant != auth.Tenant ||
		intent.WorkloadID != auth.AgentID || intent.WorkloadSPIFFE != auth.AgentSPIFFE ||
		intent.PayloadSHA256 != auth.PayloadSHA256 {
		return &ConfigError{Msg: "clavenar: stored execution intent changed an authorization binding"}
	}
	if err := opts.AuthorizationVerify(ctx, intent.Authorization); err != nil {
		return &ConfigError{Msg: "clavenar: stored authorization signature verification failed: " + err.Error()}
	}
	return nil
}

func recoveredCompletion(
	ctx context.Context,
	prepared PreparedToolRequest,
	body []byte,
	opts GovernedExecutionOptions,
	state ExecutionState,
) (GovernedExecutionOutcome, error) {
	if state.Intent == nil {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: durable completion is missing its execution intent"}
	}
	if err := validateStoredIntent(ctx, *state.Intent, prepared, body, opts); err != nil {
		return GovernedExecutionOutcome{}, err
	}
	completion := *state.Completion
	auth := state.Intent.Authorization.Authorization
	if completion.Contract != DurableExecutionContract || completion.Stage != "execution.completed" ||
		completion.AuthorizationID != auth.AuthorizationID || completion.IdempotencyID != prepared.IdempotencyID ||
		completion.ExecutorID != opts.ExecutorID || completion.EffectID == "" || !json.Valid(completion.ActualResult) {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: stored execution completion is invalid"}
	}
	resultSHA256, err := hashCanonicalJSON(completion.ActualResult)
	if err != nil {
		return GovernedExecutionOutcome{}, err
	}
	if completion.ActualResultSHA256 != resultSHA256 || completion.Receipt.ResultSHA256 != resultSHA256 ||
		completion.Receipt.AuthorizationID != auth.AuthorizationID || completion.Receipt.IdempotencyID != prepared.IdempotencyID ||
		completion.Receipt.EffectID != completion.EffectID || completion.Receipt.WorkloadSignature.CredentialFingerprint != auth.CredentialFingerprint ||
		completion.Receipt.WorkloadSignature.Algorithm == "" || completion.Receipt.WorkloadSignature.Value == "" {
		return GovernedExecutionOutcome{}, &ConfigError{Msg: "clavenar: stored execution completion failed integrity validation"}
	}
	return GovernedExecutionOutcome{
		Result:        completion.ActualResult,
		EffectID:      completion.EffectID,
		IdempotencyID: completion.IdempotencyID,
		Receipt:       completion.Receipt,
	}, nil
}

func requestAuthorization(
	ctx context.Context,
	body []byte,
	idempotencyID string,
	o Options,
) (SignedAuthorization, error) {
	if o.Retry.MaxAttempts < 1 || o.Retry.MaxAttempts > maxRetryAttempts {
		return SignedAuthorization{}, &ConfigError{Msg: fmt.Sprintf("clavenar: effective Retry.MaxAttempts must be between 1 and %d", maxRetryAttempts)}
	}
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
	httpClient, token, closeTransport, transportErr := o.requestTransport(ctx)
	if transportErr != nil {
		return SignedAuthorization{}, transportErr
	}
	defer closeTransport()
	rctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, joinURL(o.Endpoint, "/mcp"), bytes.NewReader(body))
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization: failed to build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(decisionContractHeader, decisionContract)
	req.Header.Set(idempotencyIDHeader, idempotencyID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization failed: " + err.Error()}
	}
	defer resp.Body.Close()
	data, err := readBoundedBody(resp.Body)
	if err != nil {
		return SignedAuthorization{}, &TransportError{Msg: "clavenar authorization: failed to read response: " + err.Error(), Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		text := boundedErrorText(data)
		return SignedAuthorization{}, &TransportError{
			Msg:    fmt.Sprintf("clavenar authorization: unexpected status %d: %s", resp.StatusCode, text),
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
	if err := validateToolCall(ToolCall{
		ID:    prepared.IdempotencyID,
		Name:  prepared.Name,
		Input: prepared.Arguments,
	}); err != nil {
		return err
	}
	return nil
}

func validateGovernedOptions(opts GovernedExecutionOptions) error {
	if err := opts.Decision.validate(); err != nil {
		return err
	}
	if opts.ExecutorID == "" || opts.Executor == nil || opts.Store == nil || opts.Signer == nil || opts.AuthorizationVerify == nil {
		return &ConfigError{Msg: "clavenar: executor id, executor, recoverable durable store, receipt signer, and authorization verifier are required"}
	}
	if opts.FinalizationTimeout < 0 {
		return &ConfigError{Msg: "clavenar: finalization timeout must not be negative"}
	}
	return nil
}

func validateAuthorization(signed SignedAuthorization, prepared PreparedToolRequest, body []byte) error {
	auth := signed.Authorization
	if len(signed.IdentitySignature) == 0 || !json.Valid(signed.IdentitySignature) || bytes.Equal(bytes.TrimSpace(signed.IdentitySignature), []byte("null")) {
		return &ConfigError{Msg: "clavenar: authorization is missing a valid identity signature"}
	}
	if auth.Contract != ExecutionContract || auth.Stage != "authorization" {
		return &ConfigError{Msg: "clavenar: invalid governed execution authorization contract"}
	}
	if auth.IdempotencyID != prepared.IdempotencyID {
		return &ConfigError{Msg: "clavenar: authorization changed the idempotency identity"}
	}
	if !validUUID(auth.AuthorizationID) || !validUUID(auth.CorrelationID) {
		return &ConfigError{Msg: "clavenar: authorization contains an invalid UUID"}
	}
	if auth.AgentID == "" || auth.AgentSPIFFE == "" || auth.Tenant == "" || auth.CredentialFingerprint == "" ||
		auth.BrainVersion == "" || !validSHA256(auth.PayloadSHA256) || !validSHA256(auth.BrainEvidenceSHA256) {
		return &ConfigError{Msg: "clavenar: authorization is missing an execution binding"}
	}
	if !jsonObject(auth.DecisionPrincipal) || !jsonObject(auth.PolicyBundle) ||
		(len(auth.ModificationDiff) != 0 && !json.Valid(auth.ModificationDiff)) {
		return &ConfigError{Msg: "clavenar: authorization contains invalid decision evidence"}
	}
	if auth.Method != "tools/call" || auth.ToolName != prepared.Name {
		return &ConfigError{Msg: "clavenar: authorization changed the tool binding"}
	}
	var executionRequest inspectRequest
	decoder := json.NewDecoder(bytes.NewReader(auth.ExecutionPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&executionRequest); err != nil {
		return &ConfigError{Msg: "clavenar: authorization execution payload is invalid: " + err.Error()}
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if executionRequest.JSONRPC != "2.0" || executionRequest.Method != "tools/call" || executionRequest.ID != prepared.IdempotencyID || executionRequest.Params.Name != prepared.Name || !json.Valid(executionRequest.Params.Arguments) {
		return &ConfigError{Msg: "clavenar: authorization execution payload changed a protected request binding"}
	}
	payloadSHA256, err := hashCanonicalJSON(auth.ExecutionPayload)
	if err != nil {
		return err
	}
	if auth.PayloadSHA256 != payloadSHA256 {
		return &ConfigError{Msg: "clavenar: authorization payload digest does not match execution payload"}
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

func validSHA256(value string) bool {
	digest := strings.TrimPrefix(value, "sha256:")
	if digest == value || len(digest) != 64 {
		return false
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func jsonObject(raw json.RawMessage) bool {
	if !json.Valid(raw) {
		return false
	}
	var object map[string]any
	return json.Unmarshal(raw, &object) == nil && object != nil
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, &ConfigError{Msg: "clavenar: invalid JSON value: " + err.Error()}
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	value, err := normalizeJSONNumbers(value)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, &ConfigError{Msg: "clavenar: failed to canonicalize JSON: " + err.Error()}
	}
	return canonical, nil
}

func normalizeJSONNumbers(value any) (any, error) {
	switch typed := value.(type) {
	case json.Number:
		raw := typed.String()
		if !strings.ContainsAny(raw, ".eE") {
			if strings.HasPrefix(raw, "-") {
				if integer, err := strconv.ParseInt(raw, 10, 64); err == nil {
					return integer, nil
				}
			} else {
				if integer, err := strconv.ParseUint(raw, 10, 64); err == nil {
					return integer, nil
				}
			}
			return nil, &ConfigError{Msg: "clavenar: JSON integer is outside the supported 64-bit range: " + raw}
		}
		floating, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
			return nil, &ConfigError{Msg: "clavenar: JSON number is outside the supported range: " + raw}
		}
		return floating, nil
	case []any:
		for index := range typed {
			normalized, err := normalizeJSONNumbers(typed[index])
			if err != nil {
				return nil, err
			}
			typed[index] = normalized
		}
		return typed, nil
	case map[string]any:
		for key := range typed {
			normalized, err := normalizeJSONNumbers(typed[key])
			if err != nil {
				return nil, err
			}
			typed[key] = normalized
		}
		return typed, nil
	default:
		return value, nil
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return &ConfigError{Msg: "clavenar: invalid JSON value: multiple values"}
		}
		return &ConfigError{Msg: "clavenar: invalid JSON value: " + err.Error()}
	}
	return nil
}
