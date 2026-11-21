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
		udp:       serverSocket,
		sequences: newSequenceTracker(),
	}

	_ = firstDestination.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = secondDestination.SetReadDeadline(time.Now().Add(2 * time.Second))

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

	assertPacket(firstDestination, 1, protocol.PacketICEServerHeartbeatACK, nil)
	assertPacket(firstDestination, 2, protocol.PacketICEServerPeerInformation, []byte{0xa1})
	assertPacket(firstDestination, 3, protocol.PacketICEServerPeerInformation, []byte{0xa2})
	assertPacket(secondDestination, 1, protocol.PacketICEServerHeartbeatDenied, nil)
}

func TestSendPacketDropsNewDestinationWhenSequenceStateIsFull(t *testing.T) {
	serverSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()

	destination := listenSequenceTestUDP(t)
	defer destination.Close()
	server := &Server{udp: serverSocket, sequences: newSequenceTracker()}
	now := time.Now()
	for i := 0; i < sequenceMaxTargets; i++ {
		server.sequences.destinations[net.JoinHostPort("192.0.2.1", stringPort(i))] =
			destinationSequence{sequence: 4, lastSent: now}
	}
	_ = destination.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	server.sendPacket(destination.LocalAddr().(*net.UDPAddr), protocol.PacketICEServerHeartbeatACK, protocol.VersionICEStandard, nil)
	buf := make([]byte, 2048)
	if _, _, err := destination.ReadFromUDP(buf); err == nil {
		t.Fatal("packet to an untracked destination should be dropped at capacity")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("unexpected read error: %v", err)
	}
}

func stringPort(value int) string {
	return fmt.Sprintf("%d", value)
}

func listenSequenceTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
