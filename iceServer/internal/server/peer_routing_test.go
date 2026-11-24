package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/protocol"
	"github.com/overte-org/overte-ice-server/internal/qtstream"
)

// TestPeerInformationUsesCurrentObservedSocket verifies both halves of the
// original ICE server's query exchange and its active-socket behavior after
// the heartbeating peer's NAT source port changes.
func TestPeerInformationUsesCurrentObservedSocket(t *testing.T) {
	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	requesterID := "11111111-2222-4333-8444-555555555555"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/"+domainID+"/public_key" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]string{
				"public_key": base64.StdEncoding.EncodeToString(publicDER),
			},
		})
	}))
	defer directory.Close()

	tmp := t.TempDir()
	cfg := config.Config{
		ListenAddress: "127.0.0.1",
		Port: 17339,
		DataFile: filepath.Join(tmp, "registry.json"),
		EnrollmentToken: "012345678901234567890123456789012345678901234567",
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = directory.Client()
	if err = srv.registry.Register("test-directory", directory.URL, []string{domainID}); err != nil {
		t.Fatal(err)
	}
	// Start with the trusted public key already cached; this test concerns
	// peer address selection, not the asynchronous first-key-fetch behavior.
	srv.keys[domainID] = &privateKey.PublicKey

	srv.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.udp.Close()

	oldEndpoint := listenTestUDP(t)
	defer oldEndpoint.Close()
	currentEndpoint := listenTestUDP(t)
	defer currentEndpoint.Close()
	requester := listenTestUDP(t)
	defer requester.Close()

	domainPublic := []byte{0, 203, 0, 113, 10, 0x1c, 0x9c}
	domainLocal := []byte{0, 192, 168, 10, 20, 0x1c, 0x9c}
	requesterPublic := []byte{0, 198, 51, 100, 20, 0x1c, 0x9d}
	requesterLocal := []byte{0, 192, 168, 20, 30, 0x1c, 0x9d}

	heartbeat := makeSignedHeartbeat(t, domainID, domainPublic, domainLocal, privateKey)
	for _, endpoint := range []*net.UDPConn{oldEndpoint, currentEndpoint} {
		srv.handleDatagram(heartbeat, endpoint.LocalAddr().(*net.UDPAddr))
		_ = endpoint.SetReadDeadline(time.Now().Add(2 * time.Second))
		ack := readTestPacket(t, endpoint)
		if ack.Type != protocol.PacketICEServerHeartbeatACK {
			t.Fatalf("heartbeat from %s received packet type %d, want ACK", endpoint.LocalAddr(), ack.Type)
		}
		if ack.Version != protocol.VersionICEStandard {
			t.Fatalf("heartbeat ACK version = %d, want %d", ack.Version, protocol.VersionICEStandard)
		}
		if ack.Sequence != 1 {
			t.Fatalf("first heartbeat ACK sequence = %d, want 1", ack.Sequence)
		}
	}

	// The second heartbeat represents a new NAT mapping. The original C++
	// server activates the address from the latest heartbeat as the peer's
	// active socket. Go records that latest source as Observed.
	srv.peersMu.RLock()
	peer, ok := srv.peers[domainID]
	srv.peersMu.RUnlock()
	if !ok {
		t.Fatal("heartbeating peer was not stored")
	}
	if peer.Observed != currentEndpoint.LocalAddr().String() {
		t.Fatalf("observed endpoint = %q, want latest heartbeat source %q", peer.Observed, currentEndpoint.LocalAddr())
	}

	query := makeQuery(t, requesterID, requesterPublic, requesterLocal, domainID)
	_ = requester.SetReadDeadline(time.Now().Add(2 * time.Second))
	srv.handleDatagram(query, requester.LocalAddr().(*net.UDPAddr))

	// The requester gets the target's UUID and original public/local sockets.
	toRequester := readTestPacket(t, requester)
	if toRequester.Type != protocol.PacketICEServerPeerInformation {
		t.Fatalf("requester got packet type %d, want peer information", toRequester.Type)
	}
	if toRequester.Version != protocol.VersionICEStandard || toRequester.Sequence != 1 {
		t.Fatalf("requester peer-information header = version %d sequence %d, want version %d sequence 1",
			toRequester.Version, toRequester.Sequence, protocol.VersionICEStandard)
	}
	expectedTarget, err := peerPayload(domainID, domainPublic, domainLocal)
	if err != nil {
		t.Fatal(err)
	}
	if string(toRequester.Payload) != string(expectedTarget) {
		t.Fatalf("target peer payload = % x, want % x", toRequester.Payload, expectedTarget)
	}

	// The target's latest active endpoint gets the requester's information.
	// Its ACK already used sequence 1, so this packet must use sequence 2:
	// Overte shares one unreliable sequence counter across packet types per
	// destination SockAddr.
	_ = currentEndpoint.SetReadDeadline(time.Now().Add(2 * time.Second))
	toTarget := readTestPacket(t, currentEndpoint)
	if toTarget.Type != protocol.PacketICEServerPeerInformation {
		t.Fatalf("target got packet type %d, want peer information", toTarget.Type)
	}
	if toTarget.Version != protocol.VersionICEStandard || toTarget.Sequence != 2 {
		t.Fatalf("target peer-information header = version %d sequence %d, want version %d sequence 2",
			toTarget.Version, toTarget.Sequence, protocol.VersionICEStandard)
	}
	expectedRequester, err := peerPayload(requesterID, requesterPublic, requesterLocal)
	if err != nil {
		t.Fatal(err)
	}
	if string(toTarget.Payload) != string(expectedRequester) {
		t.Fatalf("requester peer payload = % x, want % x", toTarget.Payload, expectedRequester)
	}

	// The superseded NAT mapping must not be used for the reverse delivery.
	_ = oldEndpoint.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, _, err := oldEndpoint.ReadFromUDP(buf); err == nil {
		t.Fatal("peer information was incorrectly sent to the superseded NAT endpoint")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("unexpected error while checking superseded NAT endpoint: %v", err)
	}
}

func TestUnregisteredHeartbeatGetsVersionedDenial(t *testing.T) {
	tmp := t.TempDir()
	srv, err := New(config.Config{
		ListenAddress: "127.0.0.1",
		Port: 17340,
		DataFile: filepath.Join(tmp, "registry.json"),
		EnrollmentToken: "012345678901234567890123456789012345678901234567",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.udp.Close()

	endpoint := listenTestUDP(t)
	defer endpoint.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := makeSignedHeartbeat(t, "4784f9dc-388c-47c3-8855-373d22f31ff4",
		[]byte{0, 203, 0, 113, 10, 0x1c, 0x9c},
		[]byte{0, 192, 168, 10, 20, 0x1c, 0x9c}, key)

	_ = endpoint.SetReadDeadline(time.Now().Add(2 * time.Second))
	srv.handleDatagram(heartbeat, endpoint.LocalAddr().(*net.UDPAddr))
	denied := readTestPacket(t, endpoint)
	if denied.Type != protocol.PacketICEServerHeartbeatDenied {
		t.Fatalf("unregistered heartbeat response type = %d, want %d",
			denied.Type, protocol.PacketICEServerHeartbeatDenied)
	}
	if denied.Version != protocol.VersionICEStandard || denied.Sequence != 1 {
		t.Fatalf("heartbeat-denial header = version %d sequence %d, want version %d sequence 1",
			denied.Version, denied.Sequence, protocol.VersionICEStandard)
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func makeSignedHeartbeat(t *testing.T, domainID string, publicSocket, localSocket []byte, key *rsa.PrivateKey) []byte {
	t.Helper()
	signed, err := qtstream.UUIDBytes(domainID)
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, publicSocket...)
	signed = append(signed, localSocket...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), signed...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(signature)))
	payload = append(payload, length...)
	payload = append(payload, signature...)
	return protocol.EncodeDatagram(1, protocol.PacketICEServerHeartbeat, protocol.VersionICEHeartbeat, payload)
}

func makeQuery(t *testing.T, senderID string, publicSocket, localSocket []byte, targetID string) []byte {
	t.Helper()
	payload, err := qtstream.UUIDBytes(senderID)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, publicSocket...)
	payload = append(payload, localSocket...)
	target, err := qtstream.UUIDBytes(targetID)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, target...)
	return protocol.EncodeDatagram(2, protocol.PacketICEServerQuery, protocol.VersionICEStandard, payload)
}

func peerPayload(id string, publicSocket, localSocket []byte) ([]byte, error) {
	uuid, err := qtstream.UUIDBytes(id)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), uuid...)
	out = append(out, publicSocket...)
	out = append(out, localSocket...)
	return out, nil
}
