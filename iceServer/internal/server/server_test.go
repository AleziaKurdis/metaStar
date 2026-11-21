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
	if first.Type != protocol.PacketICEServerHeartbeatACK {
		t.Fatalf("heartbeat should be acknowledged while key is fetched, got %d", first.Type)
	}
	if _, exists := srv.peers[domainID]; exists {
		t.Fatal("domain was admitted before its heartbeat signature could be verified")
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
	requestCount := 0
	ds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/4784f9dc-388c-47c3-8855-373d22f31ff4/public_key" {
			http.NotFound(w, r)
			return
		}
		derMu.Lock()
		requestCount++
		der := append([]byte(nil), currentDER...)
		derMu.Unlock()
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

	// The old cached key fails verification. The ICE endpoint ACKs liveness
	// while refreshing the key, without admitting the unverified heartbeat.
	srv.handleDatagram(heartbeat, client.LocalAddr().(*net.UDPAddr))
	denied := readTestPacket(t, client)
	if denied.Type != protocol.PacketICEServerHeartbeatACK {
		t.Fatalf("expected liveness ACK while refreshing public key, got %d", denied.Type)
	}
	if _, exists := srv.peers[domainID]; exists {
		t.Fatal("domain was admitted with a heartbeat signed by the stale key")
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

	// A different stale signature must still be rejected, but the successful
	// refresh cooldown must prevent another Directory Service request.
	staleSignature, err := rsa.SignPKCS1v15(rand.Reader, oldKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	stalePayload := append([]byte{}, signed...)
	binary.BigEndian.PutUint32(length, uint32(len(staleSignature)))
	stalePayload = append(stalePayload, length...)
	stalePayload = append(stalePayload, staleSignature...)
	staleHeartbeat := protocol.EncodeDatagram(2, protocol.PacketICEServerHeartbeat, protocol.VersionICEHeartbeat, stalePayload)
	srv.handleDatagram(staleHeartbeat, client.LocalAddr().(*net.UDPAddr))
	staleAck := readTestPacket(t, client)
	if staleAck.Type != protocol.PacketICEServerHeartbeatACK {
		t.Fatalf("expected liveness ACK for stale signature, got %d", staleAck.Type)
	}

	// Give an unintended asynchronous fetch time to reach the test server.
	time.Sleep(100 * time.Millisecond)
	derMu.RLock()
	gotRequests := requestCount
	derMu.RUnlock()
	if gotRequests != 1 {
		t.Fatalf("Directory Service public-key requests = %d, want 1 during cooldown", gotRequests)
	}
}


func TestRequestKeyFetchConcurrencyIsBounded(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan string, 3)
	release := make(chan struct{}, 3)
	var mu sync.Mutex
	active, maxActive := 0, 0
	ds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		started <- r.URL.Path
		<-release

		mu.Lock()
		active--
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]string{"public_key": base64.StdEncoding.EncodeToString(der)},
		})
	}))
	defer ds.Close()

	cfg := config.Config{
		ListenAddress: "127.0.0.1",
		Port: 17339,
		DataFile: filepath.Join(t.TempDir(), "registry.json"),
		EnrollmentToken: "012345678901234567890123456789012345678901234567",
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = ds.Client()
	// Use a small capacity so the test can exercise saturation deterministically.
	srv.keyFetchSlots = make(chan struct{}, 2)

	domainIDs := []string{
		"4784f9dc-388c-47c3-8855-373d22f31ff4",
		"11111111-2222-4333-8444-555555555555",
		"22222222-3333-4333-8444-555555555555",
	}
	if err := srv.registry.Register("test-directory", ds.URL, domainIDs); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Unblock any handler still waiting if an assertion fails.
		for i := 0; i < cap(release); i++ {
			select {
			case release <- struct{}{}:
			default:
				return
			}
		}
	}()

	for _, id := range domainIDs[:2] {
		dir, ok := srv.registry.Owner(id)
		if !ok {
			t.Fatalf("missing owner for %s", id)
		}
		srv.requestKey(dir, id, false)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("expected two key fetches to start")
		}
	}

	thirdDirectory, _ := srv.registry.Owner(domainIDs[2])
	srv.requestKey(thirdDirectory, domainIDs[2], false)
	select {
	case <-started:
		t.Fatal("third key fetch started while both slots were occupied")
	case <-time.After(100 * time.Millisecond):
	}
	srv.keysMu.RLock()
	_, queued := srv.pending[domainIDs[2]]
	srv.keysMu.RUnlock()
	if queued {
		t.Fatal("a lookup that could not acquire a slot must not be marked pending")
	}

	// Free one slot, then retry the third domain as its next heartbeat would.
	release <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.keyFetchSlots) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(srv.keyFetchSlots) != 1 {
		t.Fatal("first key fetch did not release its concurrency slot")
	}
	srv.requestKey(thirdDirectory, domainIDs[2], false)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("third key fetch did not start after a slot became available")
	}

	// Let the remaining requests finish and verify all three keys were loaded.
	release <- struct{}{}
	release <- struct{}{}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		allLoaded := true
		for _, id := range domainIDs {
			if srv.getKey(id) == nil {
				allLoaded = false
				break
			}
		}
		if allLoaded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, id := range domainIDs {
		if srv.getKey(id) == nil {
			t.Fatalf("public key for %s was not loaded", id)
		}
	}
	mu.Lock()
	observedMax := maxActive
	mu.Unlock()
	if observedMax > cap(srv.keyFetchSlots) {
		t.Fatalf("observed %d concurrent key fetches, limit is %d", observedMax, cap(srv.keyFetchSlots))
	}
}
