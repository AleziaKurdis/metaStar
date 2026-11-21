package server

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/protocol"
	"github.com/overte-org/overte-ice-server/internal/registry"
)

type keyRequestOwner struct {
	directoryID string
	baseURL     string
}

type keyRetryState struct {
	owner       keyRequestOwner
	failures    uint
	nextAttempt time.Time
}

type keyRefreshCooldownState struct {
	owner       keyRequestOwner
	nextAttempt time.Time
}

const (
	maxConcurrentKeyFetches = 32
	// A successfully refreshed key followed by more invalid signatures must
	// not trigger an outbound Directory Service fetch on every heartbeat.
	keyRefreshCooldown = 30 * time.Second
	// A single consumer preserves UDP receive order while allowing the socket
	// reader to keep draining short bursts. The queue is intentionally finite.
	udpIngressQueueCapacity = 256
)

type inboundDatagram struct {
	data []byte
	addr *net.UDPAddr
}

func enqueueDatagram(queue chan inboundDatagram, data []byte, addr *net.UDPAddr) bool {
	// readUDP is the sole producer, so this capacity check avoids allocating
	// packet copies for traffic that is already known to be dropped.
	if len(queue) >= cap(queue) {
		return false
	}
	packet := inboundDatagram{
		data: append([]byte(nil), data...),
		addr: &net.UDPAddr{
			IP:   append(net.IP(nil), addr.IP...),
			Port: addr.Port,
			Zone: addr.Zone,
		},
	}
	select {
	case queue <- packet:
		return true
	default:
		return false
	}
}

type Server struct {
	cfg         config.Config
	registry    *registry.Store
	ownershipMu sync.RWMutex
	peersMu     sync.RWMutex
	peers       map[string]protocol.Peer
	keysMu      sync.RWMutex
	keys        map[string]*rsa.PublicKey
	pending     map[string]keyRequestOwner
	keyRetries  map[string]keyRetryState
	keyRefreshCooldowns map[string]keyRefreshCooldownState
	sequences   *sequenceTracker
	udp         *net.UDPConn
	httpServer  *http.Server
	keyClient        *http.Client
	keyFetchSlots    chan struct{}
	queryLimits      *queryLimiter
	heartbeatDenials *heartbeatDenialLimiter
}

type registerRequest struct {
	DirectoryID string   `json:"directory_id"`
	BaseURL     string   `json:"base_url"`
	Domains     []string `json:"domains"`
}
type apiResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func New(cfg config.Config) (*Server, error) {
	r, e := registry.New(cfg.DataFile)
	if e != nil {
		return nil, e
	}
	return &Server{cfg: cfg, registry: r, peers: map[string]protocol.Peer{}, keys: map[string]*rsa.PublicKey{}, pending: map[string]keyRequestOwner{}, keyRetries: map[string]keyRetryState{}, keyRefreshCooldowns: map[string]keyRefreshCooldownState{}, sequences: newSequenceTracker(), queryLimits: newQueryLimiter(), heartbeatDenials: newHeartbeatDenialLimiter(time.Now()), keyFetchSlots: make(chan struct{}, maxConcurrentKeyFetches), keyClient: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}}}, nil
}
func (s *Server) Run(ctx context.Context) error {
	if e := ensureCertificate(s.cfg.TLSCertFile, s.cfg.TLSKeyFile, s.cfg.AdvertiseIP); e != nil {
		return fmt.Errorf("TLS certificate: %w", e)
	}
	tlsCfg, e := loadTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if e != nil {
		return e
	}
	udpNetwork, tcpNetwork, e := config.SocketNetworks(s.cfg.ListenAddress)
	if e != nil {
		return e
	}
	addr := net.JoinHostPort(s.cfg.ListenAddress, fmt.Sprintf("%d", s.cfg.Port))
	udpAddr, e := net.ResolveUDPAddr(udpNetwork, addr)
	if e != nil {
		return e
	}
	s.udp, e = net.ListenUDP(udpNetwork, udpAddr)
	if e != nil {
		return fmt.Errorf("bind UDP %s: %w", addr, e)
	}
	tcpListener, e := net.Listen(tcpNetwork, addr)
	if e != nil {
		s.udp.Close()
		return fmt.Errorf("bind TCP %s: %w", addr, e)
	}
	tlsListener := tls.NewListener(tcpListener, tlsCfg)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/recover", s.handleRecover)
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("PUT /v1/register", s.handleRegister)
	s.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Duration(s.cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(s.cfg.WriteTimeout) * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("Overte ICE Server listening: %s UDP and %s HTTPS on %s", udpNetwork, tcpNetwork, addr)
	errCh := make(chan error, 2)
	go func() { errCh <- s.readUDP() }()
	go func() { errCh <- s.httpServer.Serve(tlsListener) }()
	go s.expirePeers(ctx)
	select {
	case <-ctx.Done():
		_ = s.httpServer.Shutdown(context.Background())
		_ = s.udp.Close()
		return nil
	case e := <-errCh:
		_ = s.httpServer.Close()
		_ = s.udp.Close()
		if errors.Is(e, http.ErrServerClosed) || errors.Is(e, net.ErrClosed) {
			return nil
		}
		return e
	}
}
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "overte-ice-server"})
}
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResponse{Status: "error", Message: "invalid JSON"})
		return
	}
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !secureEqual(provided, s.cfg.EnrollmentToken) {
		writeJSON(w, 401, apiResponse{Status: "error", Message: "invalid enrollment secret"})
		return
	}
	s.ownershipMu.Lock()
	previousOwners := s.registry.Snapshot().Owners
	token, err := s.registry.Enroll(req.DirectoryID, req.BaseURL, req.Domains)
	if err != nil {
		s.ownershipMu.Unlock()
		writeJSON(w, 409, apiResponse{Status: "error", Message: err.Error()})
		return
	}
	s.keysMu.Lock()
	for _, id := range req.Domains {
		delete(s.keys, id)
		delete(s.keyRefreshCooldowns, id)
	}
	s.keysMu.Unlock()
	s.evictPeersForOwnershipChanges(previousOwners)
	s.ownershipMu.Unlock()
	log.Printf("Directory %q enrolled with %d domains", req.DirectoryID, len(req.Domains))
	writeJSON(w, 200, map[string]string{"status": "success", "registration_token": token})
}
// handleRecover rotates a lost registration token for an existing directory.
// It is intentionally protected by the same out-of-band enrollment secret as
// initial enrollment; the endpoint does not create directories or alter owners.
func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		DirectoryID string `json:"directory_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "invalid JSON"})
		return
	}
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !secureEqual(provided, s.cfg.EnrollmentToken) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Status: "error", Message: "invalid enrollment secret"})
		return
	}
	s.ownershipMu.Lock()
	token, err := s.registry.Recover(req.DirectoryID)
	s.ownershipMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusConflict, apiResponse{Status: "error", Message: err.Error()})
		return
	}
	log.Printf("Registration credential recovered for directory %q", req.DirectoryID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "registration_token": token})
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req registerRequest
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "invalid JSON: " + e.Error()})
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	s.ownershipMu.Lock()
	previousOwners := s.registry.Snapshot().Owners
	authorized, e := s.registry.RegisterAuthorized(req.DirectoryID, token, req.BaseURL, req.Domains)
	if !authorized {
		s.ownershipMu.Unlock()
		writeJSON(w, http.StatusUnauthorized, apiResponse{Status: "error", Message: "invalid registration credentials"})
		return
	}
	if e != nil {
		s.ownershipMu.Unlock()
		writeJSON(w, http.StatusConflict, apiResponse{Status: "error", Message: e.Error()})
		return
	}
	// Invalidate only peers and keys whose Directory Service ownership changed.
	// Routine synchronization must not force every active domain through
	// public-key retrieval and heartbeat denial again.
	s.evictPeersForOwnershipChanges(previousOwners)
	s.ownershipMu.Unlock()
	log.Printf("Directory Service %q registered %d domains (%s)", req.DirectoryID, len(req.Domains), req.BaseURL)
	writeJSON(w, http.StatusOK, apiResponse{Status: "success", Message: fmt.Sprintf("registered %d domains", len(req.Domains))})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) readUDP() error {
	// Keep socket reception independent from packet processing. A single
	// consumer preserves packet order (important for heartbeat/NAT endpoint
	// updates), while the finite queue bounds memory during short bursts.
	queue := make(chan inboundDatagram, udpIngressQueueCapacity)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for packet := range queue {
			s.handleDatagramInternal(packet.data, packet.addr, true)
		}
	}()
	defer func() {
		close(queue)
		<-workerDone
	}()

	// Read the largest possible UDP payload so ReadFromUDP cannot silently
	// truncate an oversized datagram into a valid-looking ICE packet prefix.
	buf := make([]byte, 65535)
	for {
		n, addr, e := s.udp.ReadFromUDP(buf)
		if e != nil {
			return e
		}
		if n > protocol.MaxDatagramSize {
			continue
		}
		packet, e := protocol.DecodeDatagram(buf[:n])
		if e != nil {
			continue
		}

		// Reject unsupported or malformed ICE payloads before they consume
		// queue space. Query abuse control is applied at ingress so a flood of
		// unauthenticated queries cannot occupy the heartbeat processing queue.
		switch packet.Type {
		case protocol.PacketICEServerHeartbeat:
			if packet.Version != protocol.VersionICEHeartbeat {
				continue
			}
			heartbeat, e := protocol.ParseHeartbeat(packet.Payload)
			if e != nil {
				continue
			}
			// Unknown UUIDs cannot become peers and need no expensive worker
			// time. Answer them here under the separate denial-response budget
			// so spoofed unknown-domain traffic cannot fill the ingress queue.
			s.ownershipMu.RLock()
			_, registered := s.registry.Owner(heartbeat.DomainID)
			s.ownershipMu.RUnlock()
			if !registered {
				if s.heartbeatDenials.allow(time.Now()) {
					s.sendSimple(addr, protocol.PacketICEServerHeartbeatDenied)
				}
				continue
			}
		case protocol.PacketICEServerQuery:
			if packet.Version != protocol.VersionICEStandard {
				continue
			}
			if _, e := protocol.ParseQuery(packet.Payload); e != nil {
				continue
			}
			if !s.queryLimits.allow(addr, time.Now()) {
				continue
			}
		default:
			continue
		}

		// When saturated, drop the newest datagram rather than spawning work
		// or growing memory without bound. Existing queued packets keep order.
		enqueueDatagram(queue, buf[:n], addr)
	}
}

func (s *Server) handleDatagram(data []byte, addr *net.UDPAddr) {
	s.handleDatagramInternal(data, addr, false)
}

func (s *Server) handleDatagramInternal(data []byte, addr *net.UDPAddr, queryAdmitted bool) {
	p, e := protocol.DecodeDatagram(data)
	if e != nil {
		return
	}
	switch p.Type {
	case protocol.PacketICEServerHeartbeat:
		if p.Version != protocol.VersionICEHeartbeat {
			return
		}
		hb, e := protocol.ParseHeartbeat(p.Payload)
		if e != nil {
			log.Printf("discard malformed ICE heartbeat from %s: %v", addr, e)
			return
		}
		s.ownershipMu.RLock()
		dir, ok := s.registry.Owner(hb.DomainID)
		if !ok {
			s.ownershipMu.RUnlock()
			log.Printf("heartbeat from unregistered domain %s (%s)", hb.DomainID, addr)
			// Unknown-domain heartbeats are unauthenticated. Bound denial replies
			// globally to prevent a spoofed UUID flood from turning the ICE server
			// into a response generator. This is not per-IP throttling and does
			// not affect ACKs for registered domains sharing a NAT.
			if s.heartbeatDenials.allow(time.Now()) {
				s.sendSimple(addr, protocol.PacketICEServerHeartbeatDenied)
			}
			return
		}
		key := s.getKey(hb.DomainID)
		if key == nil {
			s.requestKey(dir, hb.DomainID, false)
			s.ownershipMu.RUnlock()
			// ACK confirms that this ICE endpoint is alive and should remain
			// selected while the asynchronous identity lookup is in flight.
			// The domain is not added to the peer registry until a later
			// heartbeat has a signature verified against the fetched key.
			s.sendSimple(addr, protocol.PacketICEServerHeartbeatACK)
			return
		}
		if e = protocol.VerifyHeartbeat(key, hb.Signed, hb.Signature); e != nil {
			log.Printf("invalid heartbeat signature for domain %s; refreshing public key", hb.DomainID)
			// Match the original ICE server: a failed signature can mean the
			// Domain Server rotated its keypair. Refresh from this UUID's owner.
			s.requestKey(dir, hb.DomainID, true)
			s.ownershipMu.RUnlock()
			// A stale key may simply mean the Domain Server rotated its keypair.
			// Keep the ICE endpoint selected while the replacement key is fetched;
			// this ACK does not admit or register the unverified peer.
			s.sendSimple(addr, protocol.PacketICEServerHeartbeatACK)
			return
		}
		peer := protocol.Peer{ID: hb.DomainID, Public: hb.Public, Local: hb.Local, Observed: addr.String(), LastSeen: time.Now()}
		s.peersMu.Lock()
		s.peers[hb.DomainID] = peer
		s.peersMu.Unlock()
		s.ownershipMu.RUnlock()
		s.sendSimple(addr, protocol.PacketICEServerHeartbeatACK)
	case protocol.PacketICEServerQuery:
		if p.Version != protocol.VersionICEStandard {
			return
		}
		q, e := protocol.ParseQuery(p.Payload)
		if e != nil {
			log.Printf("discard malformed ICE query from %s: %v", addr, e)
			return
		}
		// ICE queries have no client authentication in the Overte wire
		// protocol. Bound relay work by the observed source IP without
		// changing the packet format or requiring client changes.
		if !queryAdmitted && !s.queryLimits.allow(addr, time.Now()) {
			return
		}
		s.ownershipMu.RLock()
		s.peersMu.RLock()
		target, ok := s.peers[q.TargetID]
		s.peersMu.RUnlock()
		if !ok {
			s.ownershipMu.RUnlock()
			return
		}
		targetPayload, e := protocol.PeerPayload(target)
		if e != nil {
			s.ownershipMu.RUnlock()
			return
		}
		s.sendPacket(addr, protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, targetPayload)
		requester := protocol.Peer{ID: q.SenderID, Public: q.Public, Local: q.Local}
		requesterPayload, e := protocol.PeerPayload(requester)
		if e != nil {
			s.ownershipMu.RUnlock()
			return
		}
		targetAddr, e := net.ResolveUDPAddr("udp", target.Observed)
		if e == nil {
			s.sendPacket(targetAddr, protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, requesterPayload)
		}
		s.ownershipMu.RUnlock()
	}
}
func (s *Server) sendSimple(addr *net.UDPAddr, typ byte) {
	s.sendPacket(addr, typ, protocol.VersionICEStandard, nil)
}
func (s *Server) sendPacket(addr *net.UDPAddr, typ, version byte, payload []byte) {
	seq, ok := s.sequences.next(addr.String(), time.Now())
	if !ok {
		// Preserve sequence continuity for tracked destinations. When the
		// bounded tracker is full, do not send to a new destination until
		// an idle entry expires rather than evicting an active counter.
		return
	}
	_, e := s.udp.WriteToUDP(protocol.EncodeDatagram(seq, typ, version, payload), addr)
	if e != nil {
		log.Printf("send UDP packet to %s: %v", addr, e)
	}
}
// evictPeersForOwnershipChanges removes active peers whose Directory Service owner
// changed during an enrollment or registration update. The caller must hold
// ownershipMu for writing so heartbeat and query handling cannot race the update.
func (s *Server) evictPeersForOwnershipChanges(previousOwners map[string]string) {
	currentOwners := s.registry.Snapshot().Owners
	changed := make(map[string]struct{})
	for id, previousOwner := range previousOwners {
		if currentOwners[id] != previousOwner {
			changed[id] = struct{}{}
		}
	}
	for id, currentOwner := range currentOwners {
		if previousOwners[id] != currentOwner {
			changed[id] = struct{}{}
		}
	}
	if len(changed) == 0 {
		return
	}

	s.peersMu.Lock()
	for id := range changed {
		delete(s.peers, id)
	}
	s.peersMu.Unlock()

	// Keys and retry state belong to a specific Directory Service owner.
	// Clear both even if the domain has not yet become an active peer.
	s.keysMu.Lock()
	for id := range changed {
		delete(s.keys, id)
		delete(s.keyRetries, id)
		delete(s.keyRefreshCooldowns, id)
	}
	s.keysMu.Unlock()
}

func (s *Server) getKey(id string) *rsa.PublicKey {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.keys[id]
}
func keyFetchRetryDelay(failures uint) time.Duration {
	delay := time.Second
	for attempt := uint(1); attempt < failures && delay < 30*time.Second; attempt++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func (s *Server) requestKey(dir registry.Directory, id string, refresh bool) {
	// Do not create an unbounded number of goroutines or outbound HTTPS
	// requests when heartbeats arrive for many uncached registered domains.
	// If all slots are busy, the next heartbeat can retry this lookup.
	select {
	case s.keyFetchSlots <- struct{}{}:
	default:
		return
	}

	requestOwner := keyRequestOwner{directoryID: dir.ID, baseURL: dir.BaseURL}
	now := time.Now()

	s.keysMu.Lock()
	if pendingOwner, ok := s.pending[id]; ok && pendingOwner == requestOwner {
		s.keysMu.Unlock()
		<-s.keyFetchSlots
		return
	}
	if refresh {
		if cooldown, ok := s.keyRefreshCooldowns[id]; ok && cooldown.owner == requestOwner && now.Before(cooldown.nextAttempt) {
			s.keysMu.Unlock()
			<-s.keyFetchSlots
			return
		}
	}
	if retry, ok := s.keyRetries[id]; ok && retry.owner == requestOwner && now.Before(retry.nextAttempt) {
		s.keysMu.Unlock()
		<-s.keyFetchSlots
		return
	}
	s.pending[id] = requestOwner
	s.keysMu.Unlock()

	go func() {
		defer func() { <-s.keyFetchSlots }()
		key, err := protocol.FetchPublicKey(s.keyClient, dir, id)
		if err != nil {
			s.ownershipMu.RLock()
			currentOwner, stillOwned := s.registry.Owner(id)
			ownerMatches := stillOwned && currentOwner.ID == dir.ID && currentOwner.BaseURL == dir.BaseURL
			s.keysMu.Lock()
			if pendingOwner, ok := s.pending[id]; ok && pendingOwner == requestOwner {
				delete(s.pending, id)
				if ownerMatches {
					retry := s.keyRetries[id]
					if retry.owner != requestOwner {
						retry = keyRetryState{owner: requestOwner}
					}
					retry.failures++
					delay := keyFetchRetryDelay(retry.failures)
					retry.nextAttempt = time.Now().Add(delay)
					s.keyRetries[id] = retry
					log.Printf("could not retrieve public key for %s from %s: %v (retry in %s)", id, dir.ID, err, delay)
				} else {
					delete(s.keyRetries, id)
					log.Printf("discarded failed public key lookup for domain %s after Directory Service ownership changed", id)
				}
			}
			s.keysMu.Unlock()
			s.ownershipMu.RUnlock()
			return
		}

		s.ownershipMu.RLock()
		currentOwner, stillOwned := s.registry.Owner(id)
		if !stillOwned || currentOwner.ID != dir.ID || currentOwner.BaseURL != dir.BaseURL {
			s.ownershipMu.RUnlock()
			s.keysMu.Lock()
			if pendingOwner, ok := s.pending[id]; ok && pendingOwner == requestOwner {
				delete(s.pending, id)
			}
			if retry, ok := s.keyRetries[id]; ok && retry.owner == requestOwner {
				delete(s.keyRetries, id)
			}
			if cooldown, ok := s.keyRefreshCooldowns[id]; ok && cooldown.owner == requestOwner {
				delete(s.keyRefreshCooldowns, id)
			}
			s.keysMu.Unlock()
			log.Printf("discarded stale public key response for domain %s (directory ownership changed)", id)
			return
		}

		s.keysMu.Lock()
		s.keys[id] = key
		if pendingOwner, ok := s.pending[id]; ok && pendingOwner == requestOwner {
			delete(s.pending, id)
		}
		if retry, ok := s.keyRetries[id]; ok && retry.owner == requestOwner {
			delete(s.keyRetries, id)
		}
		if refresh {
			s.keyRefreshCooldowns[id] = keyRefreshCooldownState{
				owner:       requestOwner,
				nextAttempt: time.Now().Add(keyRefreshCooldown),
			}
		}
		s.keysMu.Unlock()
		s.ownershipMu.RUnlock()
		log.Printf("loaded RSA public key for domain %s (directory %s)", id, dir.ID)
	}()
}

func (s *Server) expirePeers(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.peersMu.Lock()
			for id, p := range s.peers {
				if now.Sub(p.LastSeen) > 5*time.Second {
					delete(s.peers, id)
					s.keysMu.Lock()
					delete(s.keys, id)
					s.keysMu.Unlock()
				}
			}
			s.peersMu.Unlock()
		}
	}
}
