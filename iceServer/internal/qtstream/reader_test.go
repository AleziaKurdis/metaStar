package qtstream

import "testing"

func TestUUIDAndIPv4Socket(t *testing.T) {
	b := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4, 1, 192, 168, 1, 20, 0x1c, 0x9c}
	r := Reader{B: b}
	id, _, e := r.UUID()
	if e != nil {
		t.Fatal(e)
	}
	if id != "4784f9dc-388c-47c3-8855-373d22f31ff4" {
		t.Fatalf("UUID: %s", id)
	}
	s, raw, e := r.Socket()
	if e != nil {
		t.Fatal(e)
	}
	if s != "192.168.1.20:7324" {
		t.Fatalf("socket: %s", s)
	}
	if len(raw) != 7 {
		t.Fatalf("raw socket length %d", len(raw))
	}
}
