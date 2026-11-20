package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresPublicIPv4AndLongToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e != nil {
		t.Fatal(e)
	}
	bad := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"example.org","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if e := os.WriteFile(p, []byte(bad), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e == nil {
		t.Fatal("expected invalid public IP error")
	}
}
