package clavenar

import (
	"context"
	"errors"
)

// InspectAll submits the complete ordered sibling set as one atomic decision.
// In enforce mode, the first call in submission order represents a batch-level
// deny, pending, or rate-limit verdict. OnVerdict fires per covered call.
//
// In observe mode nothing blocks: deny passes through, and a per-call
// transport failure fires OnPolicyError and is treated as allowed so one
// clavenar outage doesn't abort the turn. In enforce mode the first
// transport error fails closed and OnPolicyError is not called.
func InspectAll(ctx context.Context, calls []ToolCall, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	o := opts.withDefaults()
	if len(calls) == 0 {
		return nil
	}
	enforce := o.Mode == ModeEnforce

	var v Verdict
	var err error
	if len(calls) == 1 {
		v, err = Inspect(ctx, calls[0], o)
	} else {
		v, err = InspectBatch(ctx, calls, o)
	}
	if err != nil {
		var te *TransportError
		if enforce || !errors.As(err, &te) {
			return err
		}
		for _, call := range calls {
			if o.OnPolicyError != nil {
				vctx := VerdictContext{ToolName: call.Name, ToolUseID: call.ID, ToolInput: call.Input}
				if callbackErr := o.OnPolicyError(te, vctx); callbackErr != nil {
					return callbackErr
				}
			}
		}
		return nil
	}

	for i := range calls {
		vctx := VerdictContext{ToolName: calls[i].Name, ToolUseID: calls[i].ID, ToolInput: calls[i].Input}
		if o.OnVerdict != nil {
			if e := o.OnVerdict(v, vctx); e != nil {
				return e
			}
		}
		if !enforce {
			continue
		}
		switch v.Kind {
		case VerdictDeny:
			denied := newDenied(calls[i], v)
			if o.DevMode {
				emitDenyPanel(denied)
			}
			return denied
		case VerdictPending:
			return newPending(calls[i], v, o)
		case VerdictRateLimited:
			return newRateLimited(calls[i], v)
		}
	}
	return nil
}
