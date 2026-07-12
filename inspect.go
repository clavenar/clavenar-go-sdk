package clavenar

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
)

// InspectAll inspects every tool call concurrently and, in enforce mode,
// returns the first *Denied / *Pending / *RateLimited in submission
// order — the first deny in calls[], not the first to come back over the
// wire. OnVerdict fires per call before any deny->error translation.
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

	type result struct {
		v   Verdict
		err *TransportError
	}
	results := make([]result, len(calls))

	g, gctx := errgroup.WithContext(ctx)
	for i := range calls {
		g.Go(func() error {
			v, err := Inspect(gctx, calls[i], o)
			if err != nil {
				var te *TransportError
				if !enforce && errors.As(err, &te) {
					results[i] = result{err: te}
					return nil
				}
				return err
			}
			results[i] = result{v: v}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	for i := range calls {
		vctx := VerdictContext{ToolName: calls[i].Name, ToolUseID: calls[i].ID, ToolInput: calls[i].Input}
		r := results[i]
		if r.err != nil {
			if o.OnPolicyError != nil {
				if e := o.OnPolicyError(r.err, vctx); e != nil {
					return e
				}
			}
			continue
		}
		if o.OnVerdict != nil {
			if e := o.OnVerdict(r.v, vctx); e != nil {
				return e
			}
		}
		if !enforce {
			continue
		}
		switch r.v.Kind {
		case VerdictDeny:
			denied := newDenied(calls[i], r.v)
			if o.DevMode {
				emitDenyPanel(denied)
			}
			return denied
		case VerdictPending:
			return newPending(calls[i], r.v, o)
		case VerdictRateLimited:
			return newRateLimited(calls[i], r.v)
		}
	}
	return nil
}
