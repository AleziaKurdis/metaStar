package protocol

import "testing"

// FuzzICEProtocolInputs feeds arbitrary datagrams and payloads to the ICE
// parsers. Successful parses are not treated as proof of semantic validity;
// this target verifies that malformed wire input is handled without panics.
func FuzzICEProtocolInputs(f *testing.F) {
	uuid := []byte{0x47, 0x84, 0xf9, 0xdc, 0x38, 0x8c, 0x47, 0xc3, 0x88, 0x55, 0x37, 0x3d, 0x22, 0xf3, 0x1f, 0xf4}
	socket := []byte{1, 192, 0, 2, 1, 0x1c, 0x9c}

	heartbeat := append([]byte(nil), uuid...)
	heartbeat = append(heartbeat, socket...)
	heartbeat = append(heartbeat, socket...)
	heartbeat = append(heartbeat, 0, 0, 0, 0) // Empty QByteArray signature.

	query := append([]byte(nil), uuid...)
	query = append(query, socket...)
	query = append(query, socket...)
	query = append(query, uuid...)

	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, PacketICEServerHeartbeat, VersionICEHeartbeat})
	f.Add(EncodeDatagram(1, PacketICEServerHeartbeat, VersionICEHeartbeat, heartbeat))
	f.Add(EncodeDatagram(2, PacketICEServerQuery, VersionICEStandard, query))
	f.Add(heartbeat)
	f.Add(query)

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := DecodeDatagram(data)
		_, _ = ParseHeartbeat(data)
		_, _ = ParseQuery(data)
		if err == nil {
			_, _ = ParseHeartbeat(packet.Payload)
			_, _ = ParseQuery(packet.Payload)
		}
	})
}
