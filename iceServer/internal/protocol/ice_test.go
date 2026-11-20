package protocol

import (
	"encoding/binary"
	"testing"
)

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
