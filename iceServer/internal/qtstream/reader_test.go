package qtstream

import (
	"bytes"
	"testing"
)

func TestUUIDAndIPv4Socket(t *testing.T) {
	// Qt QUuid big-endian serialization is the RFC-4122 byte sequence.
	// QHostAddress IPv4 serialization is: qint8 protocol (0), quint32 IPv4
	// address (big-endian), followed by SockAddr's quint16 port (big-endian).
	b := []byte{
		0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3,
		0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4,
		0, 192, 168, 1, 20, 0x1c, 0x9c,
	}
	r := Reader{B: b}
	id, _, err := r.UUID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "4784f9dc-388c-47c3-8855-373d22f31ff4" {
		t.Fatalf("UUID: %s", id)
	}
	got, raw, err := r.Socket()
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.168.1.20:7324" {
		t.Fatalf("socket: %s", got)
	}
	if !bytes.Equal(raw, b[16:]) {
		t.Fatalf("raw IPv4 SockAddr changed: % x", raw)
	}
	if r.Off != len(b) {
		t.Fatalf("reader offset %d, want %d", r.Off, len(b))
	}
}

func TestCapturedIPv4Socket(t *testing.T) {
	// First public SockAddr from the live Domain Server heartbeat capture:
	// IPv4 protocol (0), 24.202.187.185, UDP port 40102.
	r := Reader{B: []byte{0x00, 0x18, 0xca, 0xbb, 0xb9, 0x9c, 0xa6}}
	got, _, err := r.Socket()
	if err != nil {
		t.Fatal(err)
	}
	if got != "24.202.187.185:40102" {
		t.Fatalf("captured socket: %s", got)
	}
	if r.Off != len(r.B) {
		t.Fatalf("reader offset %d, want %d", r.Off, len(r.B))
	}
}

func TestIPv6SocketWithScopeID(t *testing.T) {
	// QHostAddress IPv6 stream representation:
	// qint8 protocol (1), sixteen address octets, QString scope ID
	// (quint32 byte length + UTF-16BE code units), then SockAddr quint16 port.
	b := []byte{
		1,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x08,
		0x00, 0x65, 0x00, 0x74, 0x00, 0x68, 0x00, 0x30,
		0x1c, 0x9c,
	}
	r := Reader{B: b}
	got, raw, err := r.Socket()
	if err != nil {
		t.Fatal(err)
	}
	if got != "[2001:db8::1]:7324" {
		t.Fatalf("IPv6 socket: %s", got)
	}
	if !bytes.Equal(raw, b) {
		t.Fatalf("raw IPv6 SockAddr changed: % x", raw)
	}
	if r.Off != len(b) {
		t.Fatalf("reader offset %d, want %d", r.Off, len(b))
	}
}

func TestQStringDecodesSurrogatePairs(t *testing.T) {
	// U+1F680 ROCKET encoded as one UTF-16 surrogate pair.
	b := []byte{0x00, 0x00, 0x00, 0x04, 0xd8, 0x3d, 0xde, 0x80}
	r := Reader{B: b}
	got, err := r.QString()
	if err != nil {
		t.Fatal(err)
	}
	if got != "🚀" {
		t.Fatalf("QString = %q, want rocket character", got)
	}
}

func TestRejectUnsupportedHostAddressProtocol(t *testing.T) {
	r := Reader{B: []byte{3, 0, 0}}
	if _, _, err := r.Socket(); err == nil {
		t.Fatal("expected unsupported QHostAddress protocol to fail")
	}
}

func TestRejectTruncatedIPv6ScopeID(t *testing.T) {
	r := Reader{B: []byte{
		1,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x65,
	}}
	if _, _, err := r.Socket(); err == nil {
		t.Fatal("expected truncated IPv6 scope QString to fail")
	}
}


func TestSocketRejectsMulticastAndBroadcastAddresses(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"IPv4 multicast", []byte{0, 239, 1, 2, 3, 0x1c, 0x9c}},
		{"IPv4 limited broadcast", []byte{0, 255, 255, 255, 255, 0x1c, 0x9c}},
		{"IPv6 multicast", []byte{
			1,
			0xff, 0x02, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0x1c, 0x9c,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Reader{B: tt.data}
			if _, _, err := r.Socket(); err == nil {
				t.Fatal("expected multicast or broadcast SockAddr to be rejected")
			}
		})
	}
}

func TestSocketAllowsUnspecifiedAddressAndZeroPort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"IPv4 unspecified", []byte{0, 0, 0, 0, 0, 0, 0}, "0.0.0.0:0"},
		{"IPv6 unspecified", []byte{
			1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0,
		}, "[::]:0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Reader{B: tt.data}
			got, _, err := r.Socket()
			if err != nil {
				t.Fatalf("unspecified endpoint rejected: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Socket() = %q, want %q", got, tt.want)
			}
		})
	}
}
