package clavenar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const correlationHeader = "X-Clavenar-Correlation-Id"

type inspectRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  inspectParams `json:"params"`
	ID      string        `json:"id"`
}

type inspectParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Inspect submits one tool call to clavenar and returns its verdict. It
// does not block or translate a deny into an error — the caller branches
// on Verdict.Kind (InspectAll layers enforce / observe on top). Network
// errors and 5xx responses retry per opts.Retry; the last
// *TransportError is returned once retries are exhausted.
func Inspect(ctx context.Context, call ToolCall, opts Options) (Verdict, error) {
	if err := opts.validate(); err != nil {
		return Verdict{}, err
	}
	o := opts.withDefaults()
	if o.Retry.MaxAttempts < 1 {
		return Verdict{}, &TransportError{Msg: fmt.Sprintf("clavenar: Retry.MaxAttempts must be >= 1, got %d", o.Retry.MaxAttempts)}
	}

	var lastErr error
	for attempt := 0; attempt < o.Retry.MaxAttempts; attempt++ {
		v, err := inspectOnce(ctx, call, o)
		if err == nil {
			return v, nil
		}
		var te *TransportError
		if !errors.As(err, &te) {
			return Verdict{}, err
		}
		lastErr = err
		if !isRetriable(te) || attempt == o.Retry.MaxAttempts-1 {
			return Verdict{}, err
		}
		if sleepErr := sleepCtx(ctx, backoff(o.Retry.BaseDelay, attempt)); sleepErr != nil {
			return Verdict{}, sleepErr
		}
	}
	return Verdict{}, lastErr
}

func inspectOnce(ctx context.Context, call ToolCall, o Options) (Verdict, error) {
	body, err := json.Marshal(inspectRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  inspectParams{Name: call.Name, Arguments: call.Input},
		ID:      call.ID,
	})
	if err != nil {
		return Verdict{}, &TransportError{Msg: "clavenar inspect: failed to encode request: " + err.Error()}
	}

	rctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, joinURL(o.Endpoint, "/mcp"), bytes.NewReader(body))
	if err != nil {
		return Verdict{}, &TransportError{Msg: "clavenar inspect: failed to build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.Token)
	}

	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		if rctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			return Verdict{}, &TransportError{Msg: fmt.Sprintf("clavenar inspect timed out after %s", o.Timeout)}
		}
		return Verdict{}, &TransportError{Msg: "clavenar inspect failed: " + err.Error()}
	}
	defer resp.Body.Close()

	corr := resp.Header.Get(correlationHeader)
	switch resp.StatusCode {
	case http.StatusOK:
		return Verdict{Kind: VerdictAllow, CorrelationID: corr}, nil
	case http.StatusForbidden:
		return parseDeny(resp, corr)
	case http.StatusAccepted:
		return parsePending(resp, corr)
	case http.StatusTooManyRequests:
		return parseRateLimit(resp, corr)
	default:
		text := safeReadText(resp)
		msg := fmt.Sprintf("clavenar inspect: unexpected status %d", resp.StatusCode)
		if text != "" {
			msg += ": " + text
		}
		return Verdict{}, &TransportError{Msg: msg, Status: resp.StatusCode}
	}
}

// PollPendingOnce performs one GET /pending/{id}. 200 returns the parsed
// PendingView; any other status (and network failure) is a
// *TransportError carrying the status. The Resolve loop retries the
// transient ones between polls.
func PollPendingOnce(ctx context.Context, correlationID string, opts Options) (PendingView, error) {
	if err := opts.validate(); err != nil {
		return PendingView{}, err
	}
	o := opts.withDefaults()

	rctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	u := joinURL(o.Endpoint, "/pending/"+url.PathEscape(correlationID))
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return PendingView{}, &TransportError{Msg: "clavenar poll: failed to build request: " + err.Error()}
	}
	if o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.Token)
	}

	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		if rctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			return PendingView{}, &TransportError{Msg: fmt.Sprintf("clavenar poll timed out after %s", o.Timeout)}
		}
		return PendingView{}, &TransportError{Msg: "clavenar poll failed: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		text := safeReadText(resp)
		msg := fmt.Sprintf("clavenar poll: unexpected status %d", resp.StatusCode)
		if text != "" {
			msg += ": " + text
		}
		return PendingView{}, &TransportError{Msg: msg, Status: resp.StatusCode}
	}
	return parsePendingView(resp)
}

func parseDeny(resp *http.Response, corr string) (Verdict, error) {
	m, err := decodeObject(resp)
	if err != nil {
		return Verdict{}, &TransportError{Msg: "clavenar 403 with unparseable body: " + err.Error(), Status: http.StatusForbidden}
	}
	if _, ok := m["error"].(string); !ok {
		return Verdict{}, &TransportError{Msg: fmt.Sprintf("clavenar 403 with unexpected body shape: %v", m), Status: http.StatusForbidden}
	}
	v := Verdict{
		Kind:           VerdictDeny,
		CorrelationID:  corr,
		Reasons:        stringSlice(m["reasons"]),
		ReviewReasons:  stringSlice(m["review_reasons"]),
		IntentCategory: stringOr(m["intent_category"], ""),
	}
	if layer, ok := m["layer"].(string); ok {
		v.Layer = layer
	}
	v.Detail = parseVerdictDetail(m["detail"])
	return v, nil
}

// parseVerdictDetail extracts the optional verbose-verdict breakdown.
// Lenient: a missing or malformed block yields nil (the gateway omits it
// unless CLAVENAR_PROXY_VERBOSE_VERDICTS=true).
func parseVerdictDetail(raw any) *VerdictDetail {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	rawDetectors, ok := obj["detectors"].([]any)
	if !ok {
		return nil
	}
	d := &VerdictDetail{}
	for _, item := range rawDetectors {
		dm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, ok := dm["detector"].(string)
		if !ok {
			continue
		}
		score, ok := dm["score"].(float64) // encoding/json numbers decode to float64
		if !ok {
			continue
		}
		flagged, _ := dm["flagged"].(bool)
		d.Detectors = append(d.Detectors, DetectorScore{Detector: name, Score: score, Flagged: flagged})
	}
	d.Degraded = stringSlice(obj["degraded"])
	return d
}

func parsePending(resp *http.Response, corr string) (Verdict, error) {
	m, err := decodeObject(resp)
	if err != nil {
		return Verdict{}, &TransportError{Msg: "clavenar 202 with unparseable body: " + err.Error(), Status: http.StatusAccepted}
	}
	status, _ := m["status"].(string)
	bodyID, hasID := m["correlation_id"].(string)
	if status != "pending" || !hasID || !isJSONArray(m["review_reasons"]) {
		return Verdict{}, &TransportError{Msg: fmt.Sprintf("clavenar 202 with unexpected body shape: %v", m), Status: http.StatusAccepted}
	}
	// The header is authoritative; the body field is duplicated for
	// convenience.
	id := corr
	if id == "" {
		id = bodyID
	}
	if id == "" {
		return Verdict{}, &TransportError{Msg: "clavenar 202 missing correlation id (header and body both empty)", Status: http.StatusAccepted}
	}
	return Verdict{Kind: VerdictPending, CorrelationID: id, ReviewReasons: stringSlice(m["review_reasons"])}, nil
}

// parseRateLimit parses the 429 envelope. Lenient like the deny parser:
// only the string error code is required; the verdict falls back to
// "rate_limited" when the body omits it (both codes ride HTTP 429).
func parseRateLimit(resp *http.Response, corr string) (Verdict, error) {
	m, err := decodeObject(resp)
	if err != nil {
		return Verdict{}, &TransportError{Msg: "clavenar 429 with unparseable body: " + err.Error(), Status: http.StatusTooManyRequests}
	}
	if _, ok := m["error"].(string); !ok {
		return Verdict{}, &TransportError{Msg: fmt.Sprintf("clavenar 429 with unexpected body shape: %v", m), Status: http.StatusTooManyRequests}
	}
	code := "rate_limited"
	if m["verdict"] == "quota_exceeded" {
		code = "quota_exceeded"
	}
	id := corr
	if id == "" {
		id = stringOr(m["correlation_id"], "")
	}
	v := Verdict{
		Kind:          VerdictRateLimited,
		CorrelationID: id,
		Reasons:       stringSlice(m["reasons"]),
		RateLimitCode: code,
	}
	if layer, ok := m["layer"].(string); ok {
		v.Layer = layer
	}
	if secs, ok := m["retry_after_secs"].(float64); ok {
		s := int(secs)
		v.RetryAfterSecs = &s
	}
	return v, nil
}

func parsePendingView(resp *http.Response) (PendingView, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return PendingView{}, &TransportError{Msg: "clavenar poll with unparseable body: " + err.Error(), Status: http.StatusOK}
	}
	var view PendingView
	if err := json.Unmarshal(data, &view); err != nil {
		return PendingView{}, &TransportError{Msg: "clavenar poll with unparseable body: " + err.Error(), Status: http.StatusOK}
	}
	if view.Decision != nil && *view.Decision != "allow" && *view.Decision != "deny" {
		return PendingView{}, &TransportError{Msg: fmt.Sprintf("clavenar poll with unexpected decision: %q", *view.Decision), Status: http.StatusOK}
	}
	return view, nil
}

func decodeObject(resp *http.Response) (map[string]any, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("body is null")
	}
	return m, nil
}

func isRetriable(te *TransportError) bool {
	// Status 0 means the request never got an HTTP response (DNS,
	// connection refused, timeout) — retriable. 5xx is a server error,
	// also retriable. Everything else (401, 404, 400, and the 403 / 202 /
	// 429 verdict statuses) is terminal.
	if te.Status == 0 {
		return true
	}
	return te.Status >= 500 && te.Status < 600
}

func backoff(base time.Duration, attempt int) time.Duration {
	// Full jitter: random in [ceiling/2, ceiling] where ceiling =
	// base*2^attempt. Avoids synchronized-retry thundering herds.
	ceiling := base << attempt
	return time.Duration(float64(ceiling) * (0.5 + rand.Float64()*0.5))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// joinURL trims a trailing slash off base and a leading slash off path
// so both joinURL("http://x/", "/mcp") and joinURL("http://x", "mcp")
// yield "http://x/mcp". It deliberately avoids net/url resolution, which
// drops the base path for partners on an endpoint like
// "https://gw.example.com/clavenar".
func joinURL(base, path string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
}

func safeReadText(resp *http.Response) string {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func isJSONArray(v any) bool {
	_, ok := v.([]any)
	return ok
}
