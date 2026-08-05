package clavenar

import (
	"context"
	"net"
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

// Retry applies only to explicit side-effect-free decisions. Network errors
// and 5xx responses retry up to MaxAttempts with one stable pre-network
// idempotency ID and full-jitter exponential backoff (BaseDelay*2^attempt);
// effect-capable execution is outside this loop and never retries.
// 200 / 403 / 429 / other-4xx never retry.
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
	// AllowInsecureTransport permits credentials to be sent over plaintext
	// HTTP. It exists only for explicit localhost development and test setups;
	// production callers should leave it false.
	AllowInsecureTransport bool
	// SecureTransport reloads CA, client identity and token before each
	// request. It cannot be combined with Token or HTTPClient.
	SecureTransport *SecureTransportProfile
	// OnVerdict fires once per inspected call before any deny->error
	// translation, in both modes. A non-nil return aborts the batch.
	OnVerdict func(Verdict, VerdictContext) error
	// OnPolicyError fires (observe mode only) when an inspection fails
	// at the transport layer; the call is then treated as allowed.
	OnPolicyError func(*TransportError, VerdictContext) error
	// DevMode renders the gateway's verbose-verdict detail (per-detector
	// scores, degraded lanes, reasons, correlation id) to stderr on a
	// denied call before returning the error. Off by default. The detail
	// is present only when the gateway runs with
	// CLAVENAR_PROXY_VERBOSE_VERDICTS=true; otherwise a hint is printed.
	// Dev/staging only — detailed denials are an attacker oracle.
	DevMode bool
}

const (
	defaultTimeout     = 10 * time.Second
	defaultMaxAttempts = 3
	defaultBaseDelay   = 100 * time.Millisecond
	maxRetryAttempts   = 10
	maxRetryBaseDelay  = time.Minute
	maxRetryDelay      = time.Minute
)

func (o Options) withDefaults() Options {
	if o.SecureTransport != nil && o.SecureTransport.RequestTimeout != 0 {
		o.Timeout = o.SecureTransport.RequestTimeout
	}
	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}
	if o.Retry.MaxAttempts == 0 {
		o.Retry.MaxAttempts = defaultMaxAttempts
	}
	if o.Retry.BaseDelay == 0 {
		o.Retry.BaseDelay = defaultBaseDelay
	}
	if o.HTTPClient == nil && o.SecureTransport == nil {
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
		return &ConfigError{Msg: "clavenar: Options.Endpoint is not a valid absolute URL"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &ConfigError{Msg: "clavenar: Options.Endpoint must use http or https"}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return &ConfigError{Msg: "clavenar: Options.Endpoint must not contain user info, a query, or a fragment"}
	}
	if o.Timeout < 0 {
		return &ConfigError{Msg: "clavenar: Options.Timeout must not be negative"}
	}
	if o.Retry.MaxAttempts < 0 || o.Retry.MaxAttempts > maxRetryAttempts {
		return &ConfigError{Msg: "clavenar: Retry.MaxAttempts must be between 0 (default) and 10"}
	}
	if o.Retry.BaseDelay < 0 || o.Retry.BaseDelay > maxRetryBaseDelay {
		return &ConfigError{Msg: "clavenar: Retry.BaseDelay must be between 0 (default) and 1m"}
	}
	if o.Mode != ModeEnforce && o.Mode != ModeObserve {
		return &ConfigError{Msg: "clavenar: Options.Mode must be ModeEnforce or ModeObserve"}
	}
	if o.SecureTransport != nil && (o.HTTPClient != nil || o.Token != "") {
		return &ConfigError{Msg: "clavenar: SecureTransport cannot be combined with Token or HTTPClient"}
	}
	if u.Scheme == "http" && (o.Token != "" || o.SecureTransport != nil) {
		if !o.AllowInsecureTransport || !isLoopbackHost(u.Hostname()) {
			return &ConfigError{Msg: "clavenar: credentials require https; plaintext is available only for explicitly enabled loopback development"}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (o Options) requestTransport(ctx context.Context) (HTTPDoer, string, func(), error) {
	if o.SecureTransport == nil {
		return o.HTTPClient, o.Token, func() {}, nil
	}
	client, token, err := o.SecureTransport.client(ctx)
	if err != nil {
		return nil, "", func() {}, err
	}
	return client, token, client.CloseIdleConnections, nil
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

// WithInsecureLoopback permits bearer-token or secure-profile requests to a
// plaintext loopback-IP endpoint. It is intended only for local development
// and tests; hostnames and non-loopback HTTP endpoints remain rejected.
func WithInsecureLoopback() Option { return func(o *Options) { o.AllowInsecureTransport = true } }

// WithSecureTransport installs one reusable reload-before-request profile.
func WithSecureTransport(profile *SecureTransportProfile) Option {
	return func(o *Options) { o.SecureTransport = profile }
}

// WithOnVerdict registers the per-call verdict callback.
func WithOnVerdict(f func(Verdict, VerdictContext) error) Option {
	return func(o *Options) { o.OnVerdict = f }
}

// WithOnPolicyError registers the observe-mode transport-failure callback.
func WithOnPolicyError(f func(*TransportError, VerdictContext) error) Option {
	return func(o *Options) { o.OnPolicyError = f }
}
