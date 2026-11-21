package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"math/big"
	"strings"
	"testing"

	"github.com/overte-org/overte-ice-server/internal/registry"
)

func TestFetchPublicKeyRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxPublicKeyResponseSize+1)))
	}))
	defer server.Close()

	_, err := FetchPublicKey(server.Client(), registry.Directory{BaseURL: server.URL}, "4784f9dc-388c-47c3-8855-373d22f31ff4")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized-response error, got %v", err)
	}
}

func TestFetchPublicKeyAcceptsValidResponse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/4784f9dc-388c-47c3-8855-373d22f31ff4/public_key" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(der)},
		})
	}))
	defer server.Close()

	key, err := FetchPublicKey(server.Client(), registry.Directory{BaseURL: server.URL}, "4784f9dc-388c-47c3-8855-373d22f31ff4")
	if err != nil {
		t.Fatal(err)
	}
	if key.N.Cmp(privateKey.PublicKey.N) != 0 || key.E != privateKey.PublicKey.E {
		t.Fatal("fetched RSA public key does not match response")
	}
}

func TestParseHeartbeatQtStream(t *testing.T) {
	uuid := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4}
	sock := []byte{1, 192, 168, 1, 20, 0x1c, 0x9c}
	payload := append([]byte{}, uuid...)
	payload = append(payload, sock...)
	payload = append(payload, sock...)
	signedLen := len(payload)
	sig := []byte{1, 2, 3, 4}
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, uint32(len(sig)))
	payload = append(payload, n...)
	payload = append(payload, sig...)
	hb, e := ParseHeartbeat(payload)
	if e != nil {
		t.Fatal(e)
	}
	if hb.DomainID != "4784f9dc-388c-47c3-8855-373d22f31ff4" {
		t.Fatalf("unexpected UUID %s", hb.DomainID)
	}
	if hb.Public.Display != "192.168.1.20:7324" {
		t.Fatalf("unexpected public socket %s", hb.Public.Display)
	}
	if len(hb.Signed) != signedLen {
		t.Fatalf("signed length %d, want %d", len(hb.Signed), signedLen)
	}
	if string(hb.Signature) != string(sig) {
		t.Fatal("signature bytes changed")
	}
}

func TestParseQuery(t *testing.T) {
	uuid := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4}
	sock := []byte{1, 192, 168, 1, 20, 0x1c, 0x9c}
	payload := append([]byte{}, uuid...)
	payload = append(payload, sock...)
	payload = append(payload, sock...)
	payload = append(payload, uuid...)
	q, e := ParseQuery(payload)
	if e != nil {
		t.Fatal(e)
	}
	if q.SenderID != "4784f9dc-388c-47c3-8855-373d22f31ff4" || q.TargetID != q.SenderID {
		t.Fatalf("unexpected query: %#v", q)
	}
}


func TestParseQueryRejectsInvalidUUIDs(t *testing.T) {
	valid := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4}
	sock := []byte{1, 192, 168, 1, 20, 0x1c, 0x9c}
	makePayload := func(sender, target []byte) []byte {
		payload := append([]byte{}, sender...)
		payload = append(payload, sock...)
		payload = append(payload, sock...)
		payload = append(payload, target...)
		return payload
	}
	invalidVersion := append([]byte(nil), valid...)
	invalidVersion[6] = 0x08
	invalidVariant := append([]byte(nil), valid...)
	invalidVariant[8] = 0x08
	nilUUID := make([]byte, 16)
	tests := []struct {
		name string
		payload []byte
	}{
		{"nil sender UUID", makePayload(nilUUID, valid)},
		{"unsupported sender version", makePayload(invalidVersion, valid)},
		{"invalid sender variant", makePayload(invalidVariant, valid)},
		{"nil target UUID", makePayload(valid, nilUUID)},
		{"unsupported target version", makePayload(valid, invalidVersion)},
		{"invalid target variant", makePayload(valid, invalidVariant)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseQuery(tt.payload); err == nil {
				t.Fatal("expected invalid UUID to be rejected")
			}
		})
	}
}


func TestParseHeartbeatRejectsInvalidDomainUUIDs(t *testing.T) {
	valid := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4}
	sock := []byte{1, 192, 168, 1, 20, 0x1c, 0x9c}
	makePayload := func(domainID []byte) []byte {
		payload := append([]byte{}, domainID...)
		payload = append(payload, sock...)
		payload = append(payload, sock...)
		payload = append(payload, 0, 0, 0, 0) // Empty QByteArray signature.
		return payload
	}
	invalidVersion := append([]byte(nil), valid...)
	invalidVersion[6] = 0x08
	invalidVariant := append([]byte(nil), valid...)
	invalidVariant[8] = 0x08
	nilUUID := make([]byte, 16)
	tests := []struct {
		name string
		domainID []byte
	}{
		{"nil domain UUID", nilUUID},
		{"unsupported domain UUID version", invalidVersion},
		{"invalid domain UUID variant", invalidVariant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseHeartbeat(makePayload(tt.domainID)); err == nil {
				t.Fatal("expected invalid domain UUID to be rejected")
			}
		})
	}
}


func TestFetchPublicKeyRejectsNonOverteRSAParameters(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongExponent := &rsa.PublicKey{N: new(big.Int).Set(strongKey.N), E: 3}

	tests := []struct {
		name string
		key  *rsa.PublicKey
		der  []byte
	}{
		{
			name: "1024-bit modulus",
			key:  &weakKey.PublicKey,
			der:  x509.MarshalPKCS1PublicKey(&weakKey.PublicKey),
		},
		{
			name: "unexpected exponent",
			key:  wrongExponent,
			der:  mustMarshalPKIXPublicKey(t, wrongExponent),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "success",
					"data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(tt.der)},
				})
			}))
			defer server.Close()

			if _, err := FetchPublicKey(server.Client(), registry.Directory{BaseURL: server.URL}, "4784f9dc-388c-47c3-8855-373d22f31ff4"); err == nil {
				t.Fatal("expected non-Overte RSA parameters to be rejected")
			}
		})
	}
}

func mustMarshalPKIXPublicKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestFetchPublicKeyAcceptsOvertePKCS1PublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(der)},
		})
	}))
	defer server.Close()

	key, err := FetchPublicKey(server.Client(), registry.Directory{BaseURL: server.URL}, "4784f9dc-388c-47c3-8855-373d22f31ff4")
	if err != nil {
		t.Fatal(err)
	}
	if key.N.Cmp(privateKey.PublicKey.N) != 0 || key.E != privateKey.PublicKey.E {
		t.Fatal("fetched RSA public key does not match response")
	}
}
