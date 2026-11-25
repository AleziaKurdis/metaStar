package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

type Config struct {
	ListenAddress   string `json:"listen_address"`
	UDPPort         int    `json:"udp_port"`
	ControlPort     int    `json:"control_port"`
	Port            int    `json:"port,omitempty"` // Deprecated: legacy fallback for udp_port.
	AdvertiseIP     string `json:"advertise_ip"`
	DataFile        string `json:"data_file"`
	TLSCertFile     string `json:"tls_cert_file"`
	TLSKeyFile      string `json:"tls_key_file"`
	ReadTimeout     int    `json:"read_timeout_seconds"`
	WriteTimeout    int    `json:"write_timeout_seconds"`
	EnrollmentToken string `json:"enrollment_token"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "0.0.0.0"
	}
	if _, _, err := SocketNetworks(c.ListenAddress); err != nil {
		return Config{}, err
	}
	// Preserve the legacy "port" setting as the UDP port for existing installs.
	// The HTTPS control API now defaults to standard TCP 443.
	if c.UDPPort == 0 {
		if c.Port > 0 {
			c.UDPPort = c.Port
		} else {
			c.UDPPort = 7337
		}
	}
	if c.ControlPort == 0 {
		c.ControlPort = 443
	}
	if c.DataFile == "" {
		c.DataFile = "/var/lib/overte-ice/registry.json"
	}
	advertiseIP := net.ParseIP(c.AdvertiseIP)
	if advertiseIP == nil {
		return Config{}, errors.New("advertise_ip must be an IPv4 or IPv6 address literal")
	}
	listenIP := net.ParseIP(c.ListenAddress)
	if (listenIP.To4() != nil) != (advertiseIP.To4() != nil) {
		return Config{}, errors.New("advertise_ip and listen_address must use the same address family")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return Config{}, errors.New("tls_cert_file and tls_key_file must be configured")
	}
	if c.ReadTimeout < 0 {
		return Config{}, errors.New("read_timeout_seconds must be zero (default) or positive")
	}
	if c.WriteTimeout < 0 {
		return Config{}, errors.New("write_timeout_seconds must be zero (default) or positive")
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 10
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10
	}
	if c.UDPPort < 1 || c.UDPPort > 65535 {
		return Config{}, fmt.Errorf("invalid UDP port %d", c.UDPPort)
	}
	if c.ControlPort < 1 || c.ControlPort > 65535 {
		return Config{}, fmt.Errorf("invalid control TCP port %d", c.ControlPort)
	}
	if len(c.EnrollmentToken) < 48 {
		return Config{}, errors.New("enrollment_token must contain at least 48 characters")
	}
	return c, nil
}

// SocketNetworks returns the explicit UDP and TCP network names for an IP
// literal. Keeping the family explicit prevents an IPv6 configuration from
// silently binding an IPv4-only socket (or vice versa).
func SocketNetworks(address string) (string, string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", "", fmt.Errorf("listen_address must be an IPv4 or IPv6 address literal: %q", address)
	}
	if ip.To4() != nil {
		return "udp4", "tcp4", nil
	}
	return "udp6", "tcp6", nil
}
