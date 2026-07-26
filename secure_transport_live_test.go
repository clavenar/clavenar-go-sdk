package clavenar

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestSecureTransportRealMTLSAndRotation(t *testing.T) {
	endpoint := os.Getenv("CLAVENAR_SECURE_TRANSPORT_ENDPOINT")
	if endpoint == "" {
		t.Skip("secure transport live endpoint not configured")
	}
	cert := requiredEnv(t, "CLAVENAR_SECURE_TRANSPORT_CLIENT_CERT")
	key := requiredEnv(t, "CLAVENAR_SECURE_TRANSPORT_CLIENT_KEY")
	generation := 0
	profile := &SecureTransportProfile{
		CABundlePath:          requiredEnv(t, "CLAVENAR_SECURE_TRANSPORT_CA"),
		ClientCertificatePath: cert,
		PrivateKeyPath:        key,
		TokenSource: func(context.Context) (string, error) {
			generation++
			return "matrix-token-" + string(rune('0'+generation)), nil
		},
	}
	options := New(endpoint, WithSecureTransport(profile), WithRetry(Retry{MaxAttempts: 1}))
	call := ToolCall{ID: "matrix", Name: "matrix_probe", Input: json.RawMessage(`{}`)}
	if verdict, err := Inspect(context.Background(), call, options); err != nil || verdict.Kind != VerdictAllow {
		t.Fatalf("initial mTLS request failed: verdict=%+v error=%v", verdict, err)
	}
	replaceFile(t, requiredEnv(t, "CLAVENAR_SECURE_TRANSPORT_NEXT_CERT"), cert)
	replaceFile(t, requiredEnv(t, "CLAVENAR_SECURE_TRANSPORT_NEXT_KEY"), key)
	if verdict, err := Inspect(context.Background(), call, options); err != nil || verdict.Kind != VerdictAllow {
		t.Fatalf("rotated mTLS request failed: verdict=%+v error=%v", verdict, err)
	}
	if generation != 2 {
		t.Fatalf("expected two token acquisitions, got %d", generation)
	}
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func replaceFile(t *testing.T, source string, target string) {
	t.Helper()
	value, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, value, 0o600); err != nil {
		t.Fatal(err)
	}
}
