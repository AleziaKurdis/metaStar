package protocol

import (
	"reflect"
	"testing"
)

func TestOvertePacketTypeIdentifiers(t *testing.T) {
	// Golden values taken from PacketTypeEnum::Value in the supplied
	// Overte source (PacketHeaders.h). These assertions deliberately use
	// numeric literals so tests cannot repeat a wrong production constant.
	tests := []struct {
		name string
		got  byte
		want byte
	}{
		{"ICEServerPeerInformation", PacketICEServerPeerInformation, 22},
		{"ICEServerQuery", PacketICEServerQuery, 23},
		{"ICEServerHeartbeat", PacketICEServerHeartbeat, 38},
		{"ICEServerHeartbeatDenied", PacketICEServerHeartbeatDenied, 60},
		{"ICEServerHeartbeatACK", PacketICEServerHeartbeatACK, 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("packet type = %d, want Overte enum value %d", tt.got, tt.want)
			}
		})
	}
	if VersionICEStandard != 17 {
		t.Fatalf("standard ICE packet version = %d, want 17", VersionICEStandard)
	}
	if VersionICEHeartbeat != 18 {
		t.Fatalf("heartbeat packet version = %d, want 18", VersionICEHeartbeat)
	}
}

func TestHeartbeatDatagramMatchesOverteWireLayout(t *testing.T) {
	// Overte udt::Packet writes a 32-bit little-endian sequence header,
	// followed by the one-byte NL packet type and one-byte packet version.
	// ICE heartbeat uses packet type 38 and version 18 in the supplied source.
	want := []byte{0x01, 0x00, 0x00, 0x00, 0x26, 0x12, 0xaa, 0xbb}
	got := EncodeDatagram(1, PacketICEServerHeartbeat, VersionICEHeartbeat, []byte{0xaa, 0xbb})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire datagram = % x, want % x", got, want)
	}

	packet, err := DecodeDatagram(want)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Sequence != 1 || packet.Type != 38 || packet.Version != 18 || !reflect.DeepEqual(packet.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("decoded packet does not match Overte fixture: %#v", packet)
	}
}

func TestUDTEnvelopeRoundTrip(t *testing.T) {
	in := EncodeDatagram(123, PacketICEServerHeartbeat, VersionICEHeartbeat, []byte{1, 2, 3})
	p, err := DecodeDatagram(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sequence != 123 || p.Type != PacketICEServerHeartbeat || p.Version != VersionICEHeartbeat || len(p.Payload) != 3 {
		t.Fatalf("unexpected packet: %#v", p)
	}
}

func TestRejectControlPacket(t *testing.T) {
	b := []byte{0, 0, 0, 0x80, 1, 17}
	if _, err := DecodeDatagram(b); err == nil {
		t.Fatal("expected control packet rejection")
	}
}

func TestRejectUnsupportedUDTDataFlags(t *testing.T) {
	for _, flag := range []uint32{1 << 30, 1 << 29, 1 << 27} {
		b := []byte{byte(flag), byte(flag >> 8), byte(flag >> 16), byte(flag >> 24), PacketICEServerHeartbeat, VersionICEHeartbeat}
		if _, err := DecodeDatagram(b); err == nil {
			t.Fatalf("expected unsupported UDT flag %#08x to be rejected", flag)
		}
	}
}
