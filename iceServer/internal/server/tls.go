package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func ensureCertificate(certFile, keyFile, advertiseIP string) error {
	_, certErr := os.Lstat(certFile)
	_, keyErr := os.Lstat(keyFile)
	certExists := certErr == nil
	keyExists := keyErr == nil
	if certErr != nil && !os.IsNotExist(certErr) {
		return fmt.Errorf("inspect TLS certificate %q: %w", certFile, certErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return fmt.Errorf("inspect TLS private key %q: %w", keyFile, keyErr)
	}
	if certExists && keyExists {
		return nil
	}
	if certExists != keyExists {
		return fmt.Errorf("TLS certificate/key pair is incomplete: both %q and %q must exist, or neither", certFile, keyFile)
	}
	if e := os.MkdirAll(filepath.Dir(certFile), 0750); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(keyFile), 0750); e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, e := rand.Int(rand.Reader, serialLimit)
	if e != nil {
		return e
	}
	now := time.Now()
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Overte ICE Server"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	if ip := net.ParseIP(advertiseIP); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, e := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if e != nil {
		return e
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if e = os.WriteFile(certFile, certPEM, 0644); e != nil {
		return e
	}
	if e = os.WriteFile(keyFile, keyPEM, 0600); e != nil {
		return e
	}
	sum := sha256.Sum256(der)
	fmt.Printf("Generated self-signed TLS certificate. SHA-256 fingerprint: %s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("Trust this certificate on the Directory Service host before registering it: %s\n", certFile)
	return nil
}
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, e
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
