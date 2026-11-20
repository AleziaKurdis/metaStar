package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	PacketICEServerPeerInformation byte   = 23
	PacketICEServerQuery           byte   = 24
	PacketICEServerHeartbeat       byte   = 39
	PacketICEServerHeartbeatDenied byte   = 61
	PacketICEServerHeartbeatACK    byte   = 64
	VersionICEStandard             byte   = 17
	VersionICEHeartbeat            byte   = 18
	udtControlBit                  uint32 = 1 << 31
	udtReliableBit                 uint32 = 1 << 30
	udtMessageBit                  uint32 = 1 << 29
	udtObfuscationMask             uint32 = 3 << 27
	udtSequenceMask                uint32 = (1 << 27) - 1
)

type Packet struct {
	Sequence      uint32
	Type, Version byte
	Payload       []byte
}

func DecodeDatagram(b []byte) (Packet, error) {
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
