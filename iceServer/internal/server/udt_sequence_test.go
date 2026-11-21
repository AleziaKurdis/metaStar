package server

import (
	"net"
	"testing"
	"time"

	"github.com/overte-org/overte-ice-server/internal/protocol"
)

func TestSendPacketUsesPerDestinationSequenceNumbers(t *testing.T) {
	serverSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()

	firstDestination := listenSequenceTestUDP(t)
	defer firstDestination.Close()
	secondDestination := listenSequenceTestUDP(t)
	defer secondDestination.Close()

	server := &Server{
		udp:     serverSocket,
		sendSeq: make(map[string]uint32),
	}

	_ = firstDestination.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = secondDestination.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Overte keeps one unreliable sequence counter per destination SockAddr.
	// Different packet types sent to the same destination share that counter.
	server.sendPacket(firstDestination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerHeartbeatACK, protocol.VersionICEStandard, nil)
	server.sendPacket(firstDestination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, []byte{0xa1})
	server.sendPacket(secondDestination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerHeartbeatDenied, protocol.VersionICEStandard, nil)
	server.sendPacket(firstDestination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, []byte{0xa2})

	assertPacket := func(conn *net.UDPConn, wantSequence uint32, wantType byte, wantPayload []byte) {
		t.Helper()
		buf := make([]byte, 2048)
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			t.Fatal(readErr)
		}
		packet, decodeErr := protocol.DecodeDatagram(buf[:n])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if packet.Sequence != wantSequence {
			t.Errorf("sequence = %d, want %d", packet.Sequence, wantSequence)
		}
		if packet.Type != wantType {
			t.Errorf("packet type = %d, want %d", packet.Type, wantType)
		}
		if packet.Version != protocol.VersionICEStandard {
			t.Errorf("packet version = %d, want %d", packet.Version, protocol.VersionICEStandard)
		}
		if string(packet.Payload) != string(wantPayload) {
			t.Errorf("payload = % x, want % x", packet.Payload, wantPayload)
		}
	}

	// The first destination starts at 1 and increments across packet types.
	assertPacket(firstDestination, 1, protocol.PacketICEServerHeartbeatACK, nil)
	assertPacket(firstDestination, 2, protocol.PacketICEServerPeerInformation, []byte{0xa1})
	assertPacket(firstDestination, 3, protocol.PacketICEServerPeerInformation, []byte{0xa2})

	// A different destination has an independent counter that also starts at 1.
	assertPacket(secondDestination, 1, protocol.PacketICEServerHeartbeatDenied, nil)
}

func TestSendPacketSequenceNumberWrapsAt27Bits(t *testing.T) {
	serverSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()

	destination := listenSequenceTestUDP(t)
	defer destination.Close()
	_ = destination.SetReadDeadline(time.Now().Add(2 * time.Second))

	const sequenceMaximum = (1 << 27) - 1
	server := &Server{
		udp: serverSocket,
		sendSeq: map[string]uint32{
			destination.LocalAddr().String(): sequenceMaximum,
		},
	}

	server.sendPacket(destination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerHeartbeatACK, protocol.VersionICEStandard, nil)

	buf := make([]byte, 2048)
	n, _, err := destination.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := protocol.DecodeDatagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if packet.Sequence != 0 {
		t.Fatalf("sequence after 27-bit wrap = %d, want 0", packet.Sequence)
	}
}

func listenSequenceTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
