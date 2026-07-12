package clavenar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ConfigError is returned for malformed configuration — a missing or
// invalid endpoint, an unknown mode, and so on.
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// TransportError is returned when clavenar is unreachable or returns an
// unexpected response. Status is the HTTP status when one was received,
// or 0 for a network-level failure (which is retriable).
type TransportError struct {
	Msg    string
	Status int
}

func (e *TransportError) Error() string { return e.Msg }

// Denied is returned (enforce mode) when clavenar rejects a tool call.
type Denied struct {
	ToolName       string
	Reasons        []string
	ReviewReasons  []string
	IntentCategory string
	// Layer names the stage that produced the deny (brain, policy, hil,
	// egress, ...), when the server reports it.
	Layer string
	// CorrelationID is clavenar's join key for the audit ledger, when
	// the server sets the correlation header.
	CorrelationID string
	// Detail is the verbose-verdict per-detector breakdown, present only
	// when the gateway runs with CLAVENAR_PROXY_VERBOSE_VERDICTS=true.
	Detail *VerdictDetail
}

func (e *Denied) Error() string {
	return fmt.Sprintf("clavenar denied tool %q: %s", e.ToolName, strings.Join(e.Reasons, " | "))
}

// Pending is returned (enforce mode) when clavenar parks a tool call for
// human review. Call Resolve to block until an operator decides.
type Pending struct {
	ToolName      string
	CorrelationID string
	ReviewReasons []string
	pollOnce      func(context.Context) (PendingView, error)
}

func (e *Pending) Error() string {
	return fmt.Sprintf("clavenar parked tool %q for review (correlation_id=%s)", e.ToolName, e.CorrelationID)
}

// ResolveOptions tunes Pending.Resolve. Zero values use the defaults: a
// 2s poll interval and a 10-minute ceiling.
type ResolveOptions struct {
	PollInterval time.Duration
	Timeout      time.Duration
}

const (
	defaultPollInterval   = 2 * time.Second
	defaultResolveTimeout = 10 * time.Minute
)

// Resolve blocks until an operator decides the pending call. It polls
// GET /pending/{id} every PollInterval and returns nil on approve or
// *Denied on deny. Transient transport failures (5xx, network) are
// swallowed between polls; 401 / 404 are terminal. A blown deadline or a
// cancelled ctx returns an error.
func (e *Pending) Resolve(ctx context.Context, opts *ResolveOptions) error {
	pollInterval := defaultPollInterval
	timeout := defaultResolveTimeout
	if opts != nil {
		if opts.PollInterval != 0 {
			pollInterval = opts.PollInterval
		}
		if opts.Timeout != 0 {
			timeout = opts.Timeout
		}
	}
	if pollInterval <= 0 {
		return &TransportError{Msg: "clavenar: ResolveOptions.PollInterval must be positive"}
	}
	if timeout <= 0 {
		return &TransportError{Msg: "clavenar: ResolveOptions.Timeout must be positive"}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		view, err := e.pollOnce(ctx)
		if err != nil {
			var te *TransportError
			if errors.As(err, &te) {
				// 401 / 404 are terminal: auth misconfig, or the pending
				// vanished. Everything else (5xx, network blip) is
				// swallowed and retried next tick.
				if te.Status == 401 || te.Status == 404 {
					return err
				}
			} else {
				return err
			}
		} else if view.Decision != nil {
			switch *view.Decision {
			case "allow":
				return nil
			case "deny":
				reasons := []string{"operator denied"}
				if view.DeciderNote != nil && *view.DeciderNote != "" {
					reasons = []string{*view.DeciderNote}
				}
				return &Denied{
					ToolName:       e.ToolName,
					Reasons:        reasons,
					ReviewReasons:  e.ReviewReasons,
					IntentCategory: "PendingDenied",
					CorrelationID:  e.CorrelationID,
				}
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := pollInterval
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return &TransportError{Msg: fmt.Sprintf("clavenar pending %s not decided within %s", e.CorrelationID, timeout)}
}

// RateLimited is returned (enforce mode) when clavenar answers 429 — the
// call was rejected before evaluation, by the request-velocity gate
// ("rate_limited") or the per-tenant spend gate ("quota_exceeded"). The
// transport never retries a 429: honor RetryAfterSecs (set on
// "rate_limited" only) or fail the operation.
type RateLimited struct {
	ToolName string
	// Code is "rate_limited" (velocity gate) or "quota_exceeded" (spend
	// gate).
	Code    string
	Reasons []string
	// RetryAfterSecs is seconds to wait before retrying; nil on
	// "quota_exceeded".
	RetryAfterSecs *int
	// Layer names the stage that produced the verdict, when the server
	// reports it.
	Layer string
	// CorrelationID is clavenar's join key for the audit ledger, when
	// the server reports it.
	CorrelationID string
}

func (e *RateLimited) Error() string {
	msg := fmt.Sprintf("clavenar %s for tool %q", e.Code, e.ToolName)
	if e.RetryAfterSecs != nil {
		msg += fmt.Sprintf(" (retry after %ds)", *e.RetryAfterSecs)
	}
	return msg
}

func newDenied(call ToolCall, v Verdict) *Denied {
	return &Denied{
		ToolName:       call.Name,
		Reasons:        v.Reasons,
		ReviewReasons:  v.ReviewReasons,
		IntentCategory: v.IntentCategory,
		Layer:          v.Layer,
		CorrelationID:  v.CorrelationID,
		Detail:         v.Detail,
	}
}

func newPending(call ToolCall, v Verdict, opts Options) *Pending {
	return &Pending{
		ToolName:      call.Name,
		CorrelationID: v.CorrelationID,
		ReviewReasons: v.ReviewReasons,
		pollOnce: func(ctx context.Context) (PendingView, error) {
			return PollPendingOnce(ctx, v.CorrelationID, opts)
		},
	}
}

func newRateLimited(call ToolCall, v Verdict) *RateLimited {
	return &RateLimited{
		ToolName:       call.Name,
		Code:           v.RateLimitCode,
		Reasons:        v.Reasons,
		RetryAfterSecs: v.RetryAfterSecs,
		Layer:          v.Layer,
		CorrelationID:  v.CorrelationID,
	}
}
