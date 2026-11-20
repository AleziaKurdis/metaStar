package qtstream

import (
	"bytes"
	"testing"
)

func TestUUIDAndIPv4Socket(t *testing.T) {
	// Qt QUuid big-endian serialization is the RFC-4122 byte sequence.
	// QHostAddress IPv4 serialization is: qint8 protocol (1), quint32 IPv4
	// address (big-endian), followed by SockAddr's quint16 port (big-endian).
	b := []byte{
		0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3,
		0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4,
		1, 192, 168, 1, 20, 0x1c, 0x9c,
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

func TestIPv6SocketWithScopeID(t *testing.T) {
	// QHostAddress IPv6 stream representation:
	// qint8 protocol (2), sixteen address octets, QString scope ID
	// (quint32 byte length + UTF-16BE code units), then SockAddr quint16 port.
	b := []byte{
		2,
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
	r := Reader{B: []byte{4, 0, 0}}
	if _, _, err := r.Socket(); err == nil {
		t.Fatal("expected unsupported QHostAddress protocol to fail")
	}
}

func TestRejectTruncatedIPv6ScopeID(t *testing.T) {
	r := Reader{B: []byte{
		2,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x65,
	}}
	if _, _, err := r.Socket(); err == nil {
		t.Fatal("expected truncated IPv6 scope QString to fail")
	}
}
