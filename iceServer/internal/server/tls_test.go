package server

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCertificateGeneratesIPCertificateAndPreservesPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	const publicIP = "203.0.113.42"

	if err := ensureCertificate(certFile, keyFile, publicIP); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("generated certificate PEM is missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wantIP := net.ParseIP(publicIP)
	found := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(wantIP) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("generated certificate SAN does not contain %s", publicIP)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %04o, want 0600", info.Mode().Perm())
	}

	before, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCertificate(certFile, keyFile, "203.0.113.99"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing certificate pair was unexpectedly replaced")
	}
}

func TestLoadTLSRejectsMismatchedCertificateAndKey(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTLS(certFile, keyFile); err == nil {
		t.Fatal("expected invalid certificate/key error")
	}
}

func TestEnsureCertificateGeneratesIPv6SAN(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	const publicIP = "2001:db8::42"

	if err := ensureCertificate(certFile, keyFile, publicIP); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := net.ParseIP(publicIP)
	for _, got := range cert.IPAddresses {
		if got.Equal(want) {
			return
		}
	}
	t.Fatalf("generated certificate SAN does not contain IPv6 address %s", publicIP)
}
