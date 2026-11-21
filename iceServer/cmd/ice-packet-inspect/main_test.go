package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/overte-org/overte-ice-server/internal/protocol"
)

func TestInspectLineReportsKnownICEPacket(t *testing.T) {
	datagram := protocol.EncodeDatagram(0x12345, protocol.PacketICEServerHeartbeat, protocol.VersionICEHeartbeat, []byte{1, 2, 3})
	result, err := inspectLine(hex.EncodeToString(datagram), 7)
	if err != nil {
		t.Fatal(err)
	}
	if result.Line != 7 || result.Sequence != 0x12345 {
		t.Fatalf("line/sequence = %d/%d", result.Line, result.Sequence)
	}
	if result.PacketName != "ICEServerHeartbeat" || result.PacketType != 38 {
		t.Fatalf("packet = %s (%d)", result.PacketName, result.PacketType)
	}
	if result.Version != 18 || result.ExpectedVersion == nil || *result.ExpectedVersion != 18 {
		t.Fatalf("version metadata = %#v", result)
	}
	if result.VersionMatches == nil || !*result.VersionMatches {
		t.Fatalf("expected matching version, got %#v", result.VersionMatches)
	}
	if result.PayloadBytes != 3 {
		t.Fatalf("payload bytes = %d, want 3", result.PayloadBytes)
	}
}

func TestInspectLineAcceptsTsharkHexSeparators(t *testing.T) {
	datagram := protocol.EncodeDatagram(1, protocol.PacketICEServerQuery, protocol.VersionICEStandard, nil)
	encoded := "0x" + strings.ToUpper(hex.EncodeToString(datagram))
	encoded = encoded[:6] + ":" + encoded[6:]
	result, err := inspectLine(encoded, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.PacketName != "ICEServerQuery" || result.VersionMatches == nil || !*result.VersionMatches {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestInspectLineRejectsMalformedFrames(t *testing.T) {
	for _, input := range []string{"not-hex", "010203", ""} {
		if _, err := inspectLine(input, 1); err == nil {
			t.Errorf("inspectLine(%q) unexpectedly succeeded", input)
		}
	}
}

func TestInspectLineReportsVersionMismatch(t *testing.T) {
	datagram := protocol.EncodeDatagram(1, protocol.PacketICEServerHeartbeat, protocol.VersionICEStandard, nil)
	result, err := inspectLine(hex.EncodeToString(datagram), 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.VersionMatches == nil || *result.VersionMatches {
		t.Fatalf("expected version mismatch, got %#v", result.VersionMatches)
	}
}

func TestInspectLineRejectsUnsupportedUDTFlags(t *testing.T) {
	datagram := protocol.EncodeDatagram(1, protocol.PacketICEServerQuery, protocol.VersionICEStandard, nil)
	datagram[3] |= 0x40 // Set the reliable flag in the UDT header.
	if _, err := inspectLine(hex.EncodeToString(datagram), 1); err == nil {
		t.Fatal("expected unsupported UDT flag to be rejected")
	}
}
