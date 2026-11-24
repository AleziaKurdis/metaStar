// Package qtstream reads the subset of Qt QDataStream used by Overte ICE packets.
// QDataStream's default byte order is big-endian.
package qtstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unicode/utf16"
)

type Reader struct {
	B   []byte
	Off int
}

func (r *Reader) take(n int) ([]byte, error) {
	// Check the offset before doing arithmetic. Reader is intentionally a small
	// exported cursor type, so callers can construct it with an arbitrary Off.
	// The subtraction form also avoids integer overflow in Off+n.
	if n < 0 || r.Off < 0 || r.Off > len(r.B) || n > len(r.B)-r.Off {
		return nil, errors.New("truncated Qt stream")
	}
	b := r.B[r.Off : r.Off+n]
	r.Off += n
	return b, nil
}
func (r *Reader) UUID() (string, []byte, error) {
	b, e := r.take(16)
	if e != nil {
		return "", nil, e
	}
	s := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8]), binary.BigEndian.Uint16(b[8:10]), b[10:16])
	return s, b, nil
}
func (r *Reader) Socket() (string, []byte, error) {
	start := r.Off
	p, e := r.take(1)
	if e != nil {
		return "", nil, e
	}
	var ip net.IP
	switch p[0] {
	case 0: // QHostAddress::IPv4Protocol
		b, e := r.take(4)
		if e != nil {
			return "", nil, e
		}
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	case 1: // QHostAddress::IPv6Protocol
		b, e := r.take(16)
		if e != nil {
			return "", nil, e
		}
		ip = net.IP(append([]byte(nil), b...))
		// QHostAddress serializes the IPv6 scope id as a QString.
		if _, e = r.QString(); e != nil {
			return "", nil, e
		}
	case 2, 255: // AnyIPProtocol / UnknownNetworkLayerProtocol (-1 as qint8)
		ip = net.IPv4zero
	default:
		return "", nil, fmt.Errorf("unsupported QHostAddress protocol value %d", p[0])
	}
	pb, e := r.take(2)
	if e != nil {
		return "", nil, e
	}
	port := binary.BigEndian.Uint16(pb)
	// ICE peer endpoints must be unicast or unspecified. Broadcast and
	// multicast destinations cannot identify an individual Overte peer and
	// must not be propagated to other clients. Keep unspecified addresses
	// and port zero valid: Domain Servers can heartbeat before STUN has
	// completed its initial public-socket discovery.
	if ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return "", nil, fmt.Errorf("unsupported multicast or broadcast SockAddr %s", ip.String())
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), r.B[start:r.Off], nil
}
func (r *Reader) QByteArray() ([]byte, error) {
	b, e := r.take(4)
	if e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(b)
	if n == 0xffffffff {
		return nil, nil
	}
	if n > 65536 {
		return nil, fmt.Errorf("Qt byte array too large: %d", n)
	}
	return r.take(int(n))
}
func (r *Reader) QString() (string, error) {
	b, e := r.take(4)
	if e != nil {
		return "", e
	}
	n := binary.BigEndian.Uint32(b)
	if n == 0xffffffff {
		return "", nil
	}
	if n > 65536 || n%2 != 0 {
		return "", fmt.Errorf("invalid Qt QString byte length %d", n)
	}
	raw, e := r.take(int(n))
	if e != nil {
		return "", e
	}
	// QDataStream serializes QString as UTF-16 code units in stream byte order.
	units := make([]uint16, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		units[i/2] = binary.BigEndian.Uint16(raw[i : i+2])
	}
	return string(utf16.Decode(units)), nil
}
func UUIDBytes(s string) ([]byte, error) {
	// Canonical UUID parsing without accepting malformed separators.
	compact := make([]byte, 0, 16)
	for _, x := range s {
		if x == '-' {
			continue
		}
		var v byte
		if x >= '0' && x <= '9' {
			v = byte(x - '0')
		} else if x >= 'a' && x <= 'f' {
			v = byte(x - 'a' + 10)
		} else if x >= 'A' && x <= 'F' {
			v = byte(x - 'A' + 10)
		} else {
			return nil, fmt.Errorf("invalid UUID %q", s)
		}
		compact = append(compact, v)
	}
	if len(compact) != 32 {
		return nil, fmt.Errorf("invalid UUID %q", s)
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = (compact[i*2] << 4) | compact[i*2+1]
	}
	return out, nil
}
