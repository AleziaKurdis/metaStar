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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/protocol"
	"github.com/overte-org/overte-ice-server/internal/qtstream"
)

func TestHeartbeatKeyFetchAckAndPeerQuery(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/4784f9dc-388c-47c3-8855-373d22f31ff4/public_key" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(publicDER)}})
	}))
	defer ds.Close()

	tmp := t.TempDir()
	cfg := config.Config{ListenAddress: "127.0.0.1", Port: 17337, DataFile: filepath.Join(tmp, "registry.json"), EnrollmentToken: "012345678901234567890123456789012345678901234567"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = ds.Client()
	if err = srv.registry.Register("test-directory", ds.URL, []string{"4784f9dc-388c-47c3-8855-373d22f31ff4"}); err != nil {
		t.Fatal(err)
	}
	srv.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.udp.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))

	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	clientID := "11111111-2222-4333-8444-555555555555"
	sock := []byte{1, 203, 0, 113, 10, 0x1c, 0x9c}
	signed, err := qtstream.UUIDBytes(domainID)
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, sock...)
	signed = append(signed, sock...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, cryptoHashSHA256(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	heartbeatPayload := append([]byte{}, signed...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(signature)))
	heartbeatPayload = append(heartbeatPayload, length...)
	heartbeatPayload = append(heartbeatPayload, signature...)
	heartbeat := protocol.EncodeDatagram(1, protocol.PacketICEServerHeartbeat, protocol.VersionICEHeartbeat, heartbeatPayload)

	srv.handleDatagram(heartbeat, client.LocalAddr().(*net.UDPAddr))
	first := readTestPacket(t, client)
	if first.Type != protocol.PacketICEServerHeartbeatDenied {
		t.Fatalf("first heartbeat should be denied while key is fetched, got %d", first.Type)
	}
	deadline := time.Now().Add(3 * time.Second)
	for srv.getKey(domainID) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.getKey(domainID) == nil {
		t.Fatal("public key was not fetched from the owning Directory Service")
	}

	srv.handleDatagram(heartbeat, client.LocalAddr().(*net.UDPAddr))
	second := readTestPacket(t, client)
	if second.Type != protocol.PacketICEServerHeartbeatACK {
		t.Fatalf("valid heartbeat should be acknowledged, got %d", second.Type)
	}

	queryPayload, err := qtstream.UUIDBytes(clientID)
	if err != nil {
		t.Fatal(err)
	}
	queryPayload = append(queryPayload, sock...)
	queryPayload = append(queryPayload, sock...)
	targetID, _ := qtstream.UUIDBytes(domainID)
	queryPayload = append(queryPayload, targetID...)
	query := protocol.EncodeDatagram(2, protocol.PacketICEServerQuery, protocol.VersionICEStandard, queryPayload)
	srv.handleDatagram(query, client.LocalAddr().(*net.UDPAddr))
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		p := readTestPacket(t, client)
		if p.Type != protocol.PacketICEServerPeerInformation {
			t.Fatalf("expected peer info packet, got %d", p.Type)
		}
		got[fmt.Sprintf("%x", p.Payload)] = true
	}
	targetExpected := append(append(append([]byte{}, targetID...), sock...), sock...)
	clientBytes, _ := qtstream.UUIDBytes(clientID)
	clientExpected := append(append(append([]byte{}, clientBytes...), sock...), sock...)
	if !got[fmt.Sprintf("%x", targetExpected)] || !got[fmt.Sprintf("%x", clientExpected)] {
		t.Fatal("peer information exchange did not return both peers")
	}
}

func cryptoHashSHA256() crypto.Hash { return crypto.SHA256 }
func readTestPacket(t *testing.T, conn *net.UDPConn) protocol.Packet {
	t.Helper()
	b := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := protocol.DecodeDatagram(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	return p
}


func TestHeartbeatRefreshesCachedKeyAfterSignatureFailure(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newDER, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	var derMu sync.RWMutex
	currentDER := newDER
	ds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/4784f9dc-388c-47c3-8855-373d22f31ff4/public_key" {
			http.NotFound(w, r)
			return
		}
		derMu.RLock()
		der := append([]byte(nil), currentDER...)
		derMu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(der)}})
	}))
	defer ds.Close()

	tmp := t.TempDir()
	cfg := config.Config{ListenAddress: "127.0.0.1", Port: 17338, DataFile: filepath.Join(tmp, "registry.json"), EnrollmentToken: "012345678901234567890123456789012345678901234567"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = ds.Client()
	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	if err = srv.registry.Register("test-directory", ds.URL, []string{domainID}); err != nil {
		t.Fatal(err)
	}

	srv.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.udp.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Simulate the ICE Server still caching a Domain Server's previous key.
	srv.keysMu.Lock()
	srv.keys[domainID] = &oldKey.PublicKey
	srv.keysMu.Unlock()

	sock := []byte{1, 203, 0, 113, 10, 0x1c, 0x9c}
	signed, err := qtstream.UUIDBytes(domainID)
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, sock...)
	signed = append(signed, sock...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, newKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{}, signed...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(signature)))
	payload = append(payload, length...)
	payload = append(payload, signature...)
	heartbeat := protocol.EncodeDatagram(1, protocol.PacketICEServerHeartbeat, protocol.VersionICEHeartbeat, payload)

	// The old cached key fails verification. The first heartbeat is denied
	// while the server refreshes the key from the Directory Service.
	srv.handleDatagram(heartbeat, client.LocalAddr().(*net.UDPAddr))
	denied := readTestPacket(t, client)
	if denied.Type != protocol.PacketICEServerHeartbeatDenied {
		t.Fatalf("expected denial while refreshing public key, got %d", denied.Type)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		key := srv.getKey(domainID)
		if key != nil && key.N.Cmp(newKey.N) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	key := srv.getKey(domainID)
	if key == nil || key.N.Cmp(newKey.N) != 0 {
		t.Fatal("cached public key was not refreshed after invalid heartbeat signature")
	}

	// The same heartbeat is accepted once the new public key is cached.
	srv.handleDatagram(heartbeat, client.LocalAddr().(*net.UDPAddr))
	ack := readTestPacket(t, client)
	if ack.Type != protocol.PacketICEServerHeartbeatACK {
		t.Fatalf("expected ACK after key refresh, got %d", ack.Type)
	}
}
