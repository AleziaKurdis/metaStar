package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresValidAddressFamilyAndLongToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	if _, err := Load(p); err != nil { t.Fatal(err) }
	loaded, err := Load(p)
	if err != nil { t.Fatal(err) }
	if loaded.UDPPort != 7337 || loaded.ControlPort != 443 {
		t.Fatalf("legacy port config migrated to UDP/TCP ports %d/%d, want 7337/443", loaded.UDPPort, loaded.ControlPort)
	}
	bad := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"example.org","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if err := os.WriteFile(p, []byte(bad), 0600); err != nil { t.Fatal(err) }
	if _, err := Load(p); err == nil { t.Fatal("expected invalid IP address error") }
}

func TestLoadAcceptsMatchingIPv6Addresses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"::","port":7337,"advertise_ip":"2001:db8::25","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	if _, err := Load(p); err != nil { t.Fatalf("matching IPv6 config rejected: %v", err) }
}

func TestLoadRejectsMismatchedAddressFamilies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"::","port":7337,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	if _, err := Load(p); err == nil { t.Fatal("expected mismatched address family to be rejected") }
}

func TestLoadRejectsNegativeHTTPTimeouts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	base := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"%s}`
	for _, field := range []string{"read_timeout_seconds", "write_timeout_seconds"} {
		t.Run(field, func(t *testing.T) {
			body := fmt.Sprintf(base, `, "`+field+`": -1`)
			if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
			if _, err := Load(p); err == nil {
				t.Fatalf("negative %s should be rejected", field)
			}
		})
	}
}

func TestLoadDefaultsZeroHTTPTimeouts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"0.0.0.0","port":7337,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567","read_timeout_seconds":0,"write_timeout_seconds":0}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	cfg, err := Load(p)
	if err != nil { t.Fatal(err) }
	if cfg.ReadTimeout != 10 || cfg.WriteTimeout != 10 {
		t.Fatalf("timeouts = %d/%d, want 10/10", cfg.ReadTimeout, cfg.WriteTimeout)
	}
}

func TestSocketNetworks(t *testing.T) {
	tests := []struct { address, udp, tcp string }{
		{"0.0.0.0", "udp4", "tcp4"},
		{"127.0.0.1", "udp4", "tcp4"},
		{"::", "udp6", "tcp6"},
		{"2001:db8::1", "udp6", "tcp6"},
	}
	for _, tt := range tests {
		udp, tcp, err := SocketNetworks(tt.address)
		if err != nil { t.Fatalf("%s: %v", tt.address, err) }
		if udp != tt.udp || tcp != tt.tcp { t.Errorf("%s: got %s/%s, want %s/%s", tt.address, udp, tcp, tt.udp, tt.tcp) }
	}
	if _, _, err := SocketNetworks("ice.example.org"); err == nil {
		t.Fatal("hostname should not be accepted as a bind address")
	}
}

func TestLoadUsesExplicitSeparatePorts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen_address":"0.0.0.0","udp_port":7337,"control_port":443,"advertise_ip":"203.0.113.4","tls_cert_file":"/tmp/cert","tls_key_file":"/tmp/key","enrollment_token":"012345678901234567890123456789012345678901234567"}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	cfg, err := Load(p)
	if err != nil { t.Fatal(err) }
	if cfg.UDPPort != 7337 || cfg.ControlPort != 443 {
		t.Fatalf("ports = UDP %d/TCP %d, want 7337/443", cfg.UDPPort, cfg.ControlPort)
	}
}
