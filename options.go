package clavenar

import (
	"net/http"
	"net/url"
	"time"
)

// Mode controls whether a deny / pending verdict blocks the agent.
type Mode int

const (
	// ModeEnforce (default): deny -> *Denied, pending -> *Pending; a
	// transport failure fails closed (returned as *TransportError).
	ModeEnforce Mode = iota
	// ModeObserve: nothing blocks. Verdicts surface via OnVerdict and
	// the call passes through; a transport failure fires OnPolicyError
	// and the call is treated as allowed.
	ModeObserve
)

// Retry is the per-inspection retry policy. Network errors and 5xx
// responses retry up to MaxAttempts with full-jitter exponential backoff
// (BaseDelay*2^attempt); 200 / 403 / other-4xx never retry.
type Retry struct {
	MaxAttempts int
	BaseDelay   time.Duration
}

// HTTPDoer is the slice of *http.Client the SDK needs. Inject a stub in
// tests; the default is a plain *http.Client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Options configures inspection. Endpoint is required; the rest default
// to enforce mode, a 10s per-request timeout, and 3 retries at a 100ms
// base delay.
type Options struct {
	Endpoint   string
	Token      string
	Mode       Mode
	Timeout    time.Duration
	Retry      Retry
	HTTPClient HTTPDoer
	// OnVerdict fires once per inspected call before any deny->error
	// translation, in both modes. A non-nil return aborts the batch.
	OnVerdict func(Verdict, VerdictContext) error
	// OnPolicyError fires (observe mode only) when an inspection fails
	// at the transport layer; the call is then treated as allowed.
	OnPolicyError func(*TransportError, VerdictContext) error
}

const (
	defaultTimeout     = 10 * time.Second
	defaultMaxAttempts = 3
	defaultBaseDelay   = 100 * time.Millisecond
)

func (o Options) withDefaults() Options {
	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}
	if o.Retry.MaxAttempts == 0 {
		o.Retry.MaxAttempts = defaultMaxAttempts
	}
	if o.Retry.BaseDelay == 0 {
		o.Retry.BaseDelay = defaultBaseDelay
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{}
	}
	return o
}

func (o Options) validate() error {
	if o.Endpoint == "" {
		return &ConfigError{Msg: "clavenar: Options.Endpoint is required"}
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return &ConfigError{Msg: "clavenar: Options.Endpoint is not a valid absolute URL: " + o.Endpoint}
	}
	if o.Timeout < 0 {
		return &ConfigError{Msg: "clavenar: Options.Timeout must not be negative"}
	}
	if o.Mode != ModeEnforce && o.Mode != ModeObserve {
		return &ConfigError{Msg: "clavenar: Options.Mode must be ModeEnforce or ModeObserve"}
	}
	return nil
}

// Option is a functional option for New.
type Option func(*Options)

// New builds Options from a required endpoint plus functional options.
func New(endpoint string, opts ...Option) Options {
	o := Options{Endpoint: endpoint}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// WithToken sets the bearer token sent on every request.
func WithToken(t string) Option { return func(o *Options) { o.Token = t } }

// WithMode sets enforce or observe.
func WithMode(m Mode) Option { return func(o *Options) { o.Mode = m } }

// WithObserve is shorthand for WithMode(ModeObserve).
func WithObserve() Option { return func(o *Options) { o.Mode = ModeObserve } }

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option { return func(o *Options) { o.Timeout = d } }

// WithRetry sets the retry policy.
func WithRetry(r Retry) Option { return func(o *Options) { o.Retry = r } }

// WithHTTPClient injects an HTTP client (tests, custom transports).
func WithHTTPClient(c HTTPDoer) Option { return func(o *Options) { o.HTTPClient = c } }

// WithOnVerdict registers the per-call verdict callback.
func WithOnVerdict(f func(Verdict, VerdictContext) error) Option {
	return func(o *Options) { o.OnVerdict = f }
}

// WithOnPolicyError registers the observe-mode transport-failure callback.
func WithOnPolicyError(f func(*TransportError, VerdictContext) error) Option {
	return func(o *Options) { o.OnPolicyError = f }
}
