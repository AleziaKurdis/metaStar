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

type Server struct {
	cfg        config.Config
	registry   *registry.Store
	peersMu    sync.RWMutex
	peers      map[string]protocol.Peer
	keysMu     sync.RWMutex
	keys       map[string]*rsa.PublicKey
	pending    map[string]bool
	seqMu      sync.Mutex
	sendSeq    map[string]uint32
	udp        *net.UDPConn
	httpServer *http.Server
	keyClient  *http.Client
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
	return &Server{cfg: cfg, registry: r, peers: map[string]protocol.Peer{}, keys: map[string]*rsa.PublicKey{}, pending: map[string]bool{}, sendSeq: map[string]uint32{}, keyClient: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
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
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddress, s.cfg.Port)
	udpAddr, e := net.ResolveUDPAddr("udp4", addr)
	if e != nil {
		return e
	}
	s.udp, e = net.ListenUDP("udp4", udpAddr)
	if e != nil {
		return fmt.Errorf("bind UDP %s: %w", addr, e)
	}
	tcpListener, e := net.Listen("tcp4", addr)
	if e != nil {
		s.udp.Close()
		return fmt.Errorf("bind TCP %s: %w", addr, e)
	}
	tlsListener := tls.NewListener(tcpListener, tlsCfg)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("PUT /v1/register", s.handleRegister)
	s.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Duration(s.cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(s.cfg.WriteTimeout) * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("Overte ICE Server listening: UDP %s and HTTPS %s", addr, addr)
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
	token, err := s.registry.Enroll(req.DirectoryID, req.BaseURL, req.Domains)
	if err != nil {
		writeJSON(w, 409, apiResponse{Status: "error", Message: err.Error()})
		return
	}
	s.keysMu.Lock()
	for _, id := range req.Domains {
		delete(s.keys, id)
	}
	s.keysMu.Unlock()
	log.Printf("Directory %q enrolled with %d domains", req.DirectoryID, len(req.Domains))
	writeJSON(w, 200, map[string]string{"status": "success", "registration_token": token})
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
	if !s.registry.TokenValid(req.DirectoryID, token) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Status: "error", Message: "invalid registration credentials"})
		return
	}
	if e := s.registry.Register(req.DirectoryID, req.BaseURL, req.Domains); e != nil {
		writeJSON(w, http.StatusConflict, apiResponse{Status: "error", Message: e.Error()})
		return
	}
	// Drop cached keys when a directory changes its advertised domain list.
	s.keysMu.Lock()
	s.keys = map[string]*rsa.PublicKey{}
	s.keysMu.Unlock()
	log.Printf("Directory Service %q registered %d domains (%s)", req.DirectoryID, len(req.Domains), req.BaseURL)
	writeJSON(w, http.StatusOK, apiResponse{Status: "success", Message: fmt.Sprintf("registered %d domains", len(req.Domains))})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) readUDP() error {
	buf := make([]byte, 2048)
	for {
		n, addr, e := s.udp.ReadFromUDP(buf)
		if e != nil {
			return e
		}
		data := append([]byte(nil), buf[:n]...)
		s.handleDatagram(data, addr)
	}
}
func (s *Server) handleDatagram(data []byte, addr *net.UDPAddr) {
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
		dir, ok := s.registry.Owner(hb.DomainID)
		if !ok {
			log.Printf("heartbeat from unregistered domain %s (%s)", hb.DomainID, addr)
			s.sendSimple(addr, protocol.PacketICEServerHeartbeatDenied)
			return
		}
		key := s.getKey(hb.DomainID)
		if key == nil {
			s.requestKey(dir, hb.DomainID)
			s.sendSimple(addr, protocol.PacketICEServerHeartbeatDenied)
			return
		}
		if e = protocol.VerifyHeartbeat(key, hb.Signed, hb.Signature); e != nil {
			log.Printf("invalid heartbeat signature for domain %s; refreshing public key", hb.DomainID)
			// Match the original ICE server: a failed signature can mean the
			// Domain Server rotated its keypair. Refresh from this UUID's owner.
			s.requestKey(dir, hb.DomainID)
			s.sendSimple(addr, protocol.PacketICEServerHeartbeatDenied)
			return
		}
		peer := protocol.Peer{ID: hb.DomainID, Public: hb.Public, Local: hb.Local, Observed: addr.String(), LastSeen: time.Now()}
		s.peersMu.Lock()
		s.peers[hb.DomainID] = peer
		s.peersMu.Unlock()
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
		s.peersMu.RLock()
		target, ok := s.peers[q.TargetID]
		s.peersMu.RUnlock()
		if !ok {
			return
		}
		targetPayload, e := protocol.PeerPayload(target)
		if e != nil {
			return
		}
		s.sendPacket(addr, protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, targetPayload)
		requester := protocol.Peer{ID: q.SenderID, Public: q.Public, Local: q.Local}
		requesterPayload, e := protocol.PeerPayload(requester)
		if e != nil {
			return
		}
		targetAddr, e := net.ResolveUDPAddr("udp", target.Observed)
		if e == nil {
			s.sendPacket(targetAddr, protocol.PacketICEServerPeerInformation, protocol.VersionICEStandard, requesterPayload)
		}
	}
}
func (s *Server) sendSimple(addr *net.UDPAddr, typ byte) {
	s.sendPacket(addr, typ, protocol.VersionICEStandard, nil)
}
func (s *Server) sendPacket(addr *net.UDPAddr, typ, version byte, payload []byte) {
	key := addr.String()
	s.seqMu.Lock()
	s.sendSeq[key] = (s.sendSeq[key] + 1) & ((1 << 27) - 1)
	seq := s.sendSeq[key]
	s.seqMu.Unlock()
	_, e := s.udp.WriteToUDP(protocol.EncodeDatagram(seq, typ, version, payload), addr)
	if e != nil {
		log.Printf("send UDP packet to %s: %v", addr, e)
	}
}
func (s *Server) getKey(id string) *rsa.PublicKey {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.keys[id]
}
func (s *Server) requestKey(dir registry.Directory, id string) {
	s.keysMu.Lock()
	if s.pending[id] {
		s.keysMu.Unlock()
		return
	}
	s.pending[id] = true
	s.keysMu.Unlock()
	go func() {
		defer func() { s.keysMu.Lock(); delete(s.pending, id); s.keysMu.Unlock() }()
		key, e := protocol.FetchPublicKey(s.keyClient, dir, id)
		if e != nil {
			log.Printf("could not retrieve public key for %s from %s: %v", id, dir.ID, e)
			return
		}
		s.keysMu.Lock()
		s.keys[id] = key
		s.keysMu.Unlock()
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
