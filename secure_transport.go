package clavenar

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TokenSource acquires the current bearer token for one request.
type TokenSource func(context.Context) (string, error)

// ProxyMode makes ambient proxy behavior explicit.
type ProxyMode string

const (
	ProxyDirect      ProxyMode = "direct"
	ProxyEnvironment ProxyMode = "environment"
	ProxyExplicit    ProxyMode = "explicit"
)

// ProxyPolicy selects direct, environment, or one explicit proxy URL.
type ProxyPolicy struct {
	Mode ProxyMode
	URL  string
}

// SecureTransportProfile reloads a complete mTLS snapshot before each request.
type SecureTransportProfile struct {
	CABundlePath          string
	ClientCertificatePath string
	PrivateKeyPath        string
	TokenSource           TokenSource
	ConnectTimeout        time.Duration
	RequestTimeout        time.Duration
	Proxy                 ProxyPolicy
}

func (p *SecureTransportProfile) client(ctx context.Context) (*http.Client, string, error) {
	if p == nil {
		return nil, "", errors.New("clavenar: secure transport profile is nil")
	}
	connectTimeout := p.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 5 * time.Second
	}
	requestTimeout := p.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 10 * time.Second
	}
	if connectTimeout < 0 || requestTimeout < 0 {
		return nil, "", &ConfigError{Msg: "clavenar: secure transport timeouts must be positive"}
	}

	caPEM, err := readRequired(p.CABundlePath, "CA bundle")
	if err != nil {
		return nil, "", err
	}
	cert, err := tls.LoadX509KeyPair(p.ClientCertificatePath, p.PrivateKeyPath)
	if err != nil {
		return nil, "", &ConfigError{Msg: fmt.Sprintf("clavenar: invalid secure transport client identity: %v", err)}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, "", &ConfigError{Msg: "clavenar: secure transport CA bundle contains no certificates"}
	}

	proxy, err := p.proxyFunc()
	if err != nil {
		return nil, "", err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		},
		DialContext: (&net.Dialer{Timeout: connectTimeout}).DialContext,
		Proxy:       proxy,
	}
	token := ""
	if p.TokenSource != nil {
		token, err = p.TokenSource(ctx)
		if err != nil {
			return nil, "", &TransportError{Msg: "clavenar: secure transport token acquisition failed: " + err.Error()}
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, "", &ConfigError{Msg: "clavenar: secure transport token source returned an empty token"}
		}
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}, token, nil
}

func (p *SecureTransportProfile) proxyFunc() (func(*http.Request) (*url.URL, error), error) {
	switch p.Proxy.Mode {
	case "", ProxyDirect:
		return nil, nil
	case ProxyEnvironment:
		return http.ProxyFromEnvironment, nil
	case ProxyExplicit:
		proxyURL, err := url.Parse(p.Proxy.URL)
		if err != nil || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") || proxyURL.Host == "" {
			return nil, &ConfigError{Msg: "clavenar: secure transport explicit proxy must use an absolute HTTP(S) URL"}
		}
		return http.ProxyURL(proxyURL), nil
	default:
		return nil, &ConfigError{Msg: "clavenar: unknown secure transport proxy mode"}
	}
}

func readRequired(path string, label string) ([]byte, error) {
	if path == "" {
		return nil, &ConfigError{Msg: "clavenar: secure transport " + label + " path is required"}
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{Msg: fmt.Sprintf("clavenar: cannot read secure transport %s %s: %v", label, path, err)}
	}
	if len(value) == 0 {
		return nil, &ConfigError{Msg: fmt.Sprintf("clavenar: secure transport %s %s is empty", label, path)}
	}
	return value, nil
}
