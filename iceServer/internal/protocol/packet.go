package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	// MaxDatagramSize bounds the complete UDP payload accepted by the ICE
	// application protocol. Current Overte ICE heartbeat/query/peer packets
	// are far smaller; larger datagrams are rejected rather than truncated.
	MaxDatagramSize = 2048

	// Packet type identifiers are the numeric values of PacketTypeEnum::Value
	// in Overte's libraries/networking/src/udt/PacketHeaders.h.
	PacketICEServerPeerInformation byte = 22
	PacketICEServerQuery           byte = 23
	PacketICEServerHeartbeat       byte = 38
	PacketICEServerHeartbeatDenied byte = 60
	PacketICEServerHeartbeatACK    byte = 63

	VersionICEStandard   byte = 17
	VersionICEHeartbeat  byte = 18

	udtControlBit      uint32 = 1 << 31
	udtReliableBit     uint32 = 1 << 30
	udtMessageBit      uint32 = 1 << 29
	udtObfuscationMask uint32 = 3 << 27
	udtSequenceMask    uint32 = (1 << 27) - 1
)

type Packet struct {
	Sequence      uint32
	Type, Version byte
	Payload       []byte
}

// DecodeDatagram reads the subset of Overte's UDT data packet framing used
// by ICE: unreliable, unfragmented, unobfuscated NL packets. It intentionally
// does not implement Overte's reliable transport or control-packet protocol.
func DecodeDatagram(b []byte) (Packet, error) {
	if len(b) > MaxDatagramSize {
		return Packet{}, errors.New("ICE datagram exceeds maximum size")
	}
	if len(b) < 6 {
		return Packet{}, errors.New("datagram too short")
	}
	h := binary.LittleEndian.Uint32(b[:4])
	if h&udtControlBit != 0 {
		return Packet{}, errors.New("UDT control packet (not an ICE data packet)")
	}
	if h&(udtReliableBit|udtMessageBit|udtObfuscationMask) != 0 {
		return Packet{}, errors.New("unsupported UDT flags on ICE datagram")
	}
	return Packet{Sequence: h & udtSequenceMask, Type: b[4], Version: b[5], Payload: b[6:]}, nil
}

func EncodeDatagram(sequence uint32, typ, version byte, payload []byte) []byte {
	out := make([]byte, 6+len(payload))
	binary.LittleEndian.PutUint32(out[:4], sequence&udtSequenceMask)
	out[4] = typ
	out[5] = version
	copy(out[6:], payload)
	return out
}
