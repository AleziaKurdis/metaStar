package protocol

import "testing"

func TestUDTEnvelopeRoundTrip(t *testing.T) {
	in := EncodeDatagram(123, PacketICEServerHeartbeat, VersionICEHeartbeat, []byte{1, 2, 3})
	p, e := DecodeDatagram(in)
	if e != nil {
		t.Fatal(e)
	}
	if p.Sequence != 123 || p.Type != PacketICEServerHeartbeat || p.Version != VersionICEHeartbeat || len(p.Payload) != 3 {
		t.Fatalf("unexpected packet: %#v", p)
	}
}
func TestRejectControlPacket(t *testing.T) {
	b := []byte{0, 0, 0, 0x80, 1, 17}
	if _, e := DecodeDatagram(b); e == nil {
		t.Fatal("expected control packet rejection")
	}
}
