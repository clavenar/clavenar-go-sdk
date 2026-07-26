package clavenar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecureTransportReloadsTokenAndCredentialSources(t *testing.T) {
	certPath, keyPath := writeTestIdentity(t)
	generation := 0
	profile := &SecureTransportProfile{
		CABundlePath:          certPath,
		ClientCertificatePath: certPath,
		PrivateKeyPath:        keyPath,
		TokenSource: func(context.Context) (string, error) {
			generation++
			return " token-" + string(rune('0'+generation)) + " ", nil
		},
		Proxy: ProxyPolicy{Mode: ProxyDirect},
	}
	first, token, err := profile.client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-1" || first.Transport == nil {
		t.Fatalf("unexpected first snapshot token=%q transport=%T", token, first.Transport)
	}
	_, token, err = profile.client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-2" {
		t.Fatalf("expected fresh token, got %q", token)
	}
}

func TestSecureTransportRejectsNegativeTimeoutBeforeReadingFiles(t *testing.T) {
	profile := &SecureTransportProfile{
		CABundlePath:          "missing",
		ClientCertificatePath: "missing",
		PrivateKeyPath:        "missing",
		ConnectTimeout:        -time.Second,
	}
	if _, _, err := profile.client(context.Background()); err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func writeTestIdentity(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
