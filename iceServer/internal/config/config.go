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
	Port            int    `json:"port"`
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
	if c.Port == 0 {
		c.Port = 7337
	}
	if c.DataFile == "" {
		c.DataFile = "/var/lib/overte-ice/registry.json"
	}
	if ip := net.ParseIP(c.AdvertiseIP); ip == nil || ip.To4() == nil {
		return Config{}, errors.New("advertise_ip must be a public IPv4 address")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return Config{}, errors.New("tls_cert_file and tls_key_file must be configured")
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 10
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10
	}
	if c.Port < 1 || c.Port > 65535 {
		return Config{}, fmt.Errorf("invalid port %d", c.Port)
	}
	if len(c.EnrollmentToken) < 48 {
		return Config{}, errors.New("enrollment_token must contain at least 48 characters")
	}
	return c, nil
}
