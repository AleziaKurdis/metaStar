package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/protocol"
)

const (
	removedDomainID = "4784f9dc-388c-47c3-8855-373d22f31ff4"
	keptDomainID    = "11111111-2222-4333-8444-555555555555"
)

func TestRegisterEvictsPeersWhoseDirectoryOwnershipWasRemoved(t *testing.T) {
	srv, err := New(config.Config{
		DataFile: filepath.Join(t.TempDir(), "registry.json"),
		EnrollmentToken: "bootstrap-secret-for-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	removedToken, err := srv.registry.Enroll("directory-one", "https://one.example", []string{removedDomainID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.registry.Enroll("directory-two", "https://two.example", []string{keptDomainID}); err != nil {
		t.Fatal(err)
	}

	srv.peers[removedDomainID] = protocol.Peer{ID: removedDomainID, Observed: "192.0.2.10:40000"}
	srv.peers[keptDomainID] = protocol.Peer{ID: keptDomainID, Observed: "192.0.2.20:40000"}
	srv.keys[removedDomainID] = &rsa.PublicKey{}
	srv.keys[keptDomainID] = &rsa.PublicKey{}

	body, err := json.Marshal(registerRequest{
		DirectoryID: "directory-one",
		BaseURL:     "https://one.example",
		Domains:     []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/v1/register", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+removedToken)
	response := httptest.NewRecorder()

	srv.handleRegister(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if _, exists := srv.peers[removedDomainID]; exists {
		t.Fatal("peer remained active after its Directory Service removed its ownership")
	}
	if _, exists := srv.peers[keptDomainID]; !exists {
		t.Fatal("registration update incorrectly removed a peer owned by another Directory Service")
	}
	if _, exists := srv.keys[removedDomainID]; exists {
		t.Fatal("public key remained cached for the removed domain")
	}
	if _, ok := srv.registry.Owner(removedDomainID); ok {
		t.Fatal("removed domain still has a Directory Service owner")
	}
	if owner, ok := srv.registry.Owner(keptDomainID); !ok || owner.ID != "directory-two" {
		t.Fatalf("unrelated domain ownership changed: owner=%#v exists=%v", owner, ok)
	}
}

func TestEnrollEvictsStalePeerWhenUUIDReceivesItsFirstOwner(t *testing.T) {
	srv, err := New(config.Config{
		DataFile: filepath.Join(t.TempDir(), "registry.json"),
		EnrollmentToken: "bootstrap-secret-for-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Model an in-memory peer entry left over from an earlier ownership state.
	// The new enrollment must not allow that old endpoint to answer queries.
	srv.peers[removedDomainID] = protocol.Peer{ID: removedDomainID, Observed: "192.0.2.10:40000"}
	srv.keys[removedDomainID] = &rsa.PublicKey{}

	body, err := json.Marshal(registerRequest{
		DirectoryID: "new-directory",
		BaseURL:     "https://new.example",
		Domains:     []string{removedDomainID},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer bootstrap-secret-for-test")
	response := httptest.NewRecorder()

	srv.handleEnroll(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("enrollment status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if _, exists := srv.peers[removedDomainID]; exists {
		t.Fatal("stale peer remained active after a new Directory Service claimed its UUID")
	}
	if _, exists := srv.keys[removedDomainID]; exists {
		t.Fatal("stale public key remained cached after a new Directory Service claimed its UUID")
	}
	if owner, ok := srv.registry.Owner(removedDomainID); !ok || owner.ID != "new-directory" {
		t.Fatalf("new owner was not recorded: owner=%#v exists=%v", owner, ok)
	}
}


func TestRegisterPreservesCachedKeysAndPeersForUnchangedOwnership(t *testing.T) {
	srv, err := New(config.Config{
		DataFile: filepath.Join(t.TempDir(), "registry.json"),
		EnrollmentToken: "bootstrap-secret-for-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := srv.registry.Enroll("directory-one", "https://one.example", []string{removedDomainID})
	if err != nil {
		t.Fatal(err)
	}

	key := &rsa.PublicKey{}
	peer := protocol.Peer{ID: removedDomainID, Observed: "192.0.2.10:40000"}
	srv.keys[removedDomainID] = key
	srv.peers[removedDomainID] = peer

	body, err := json.Marshal(registerRequest{
		DirectoryID: "directory-one",
		BaseURL:     "https://one.example",
		Domains:     []string{removedDomainID},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/v1/register", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	srv.handleRegister(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := srv.keys[removedDomainID]; got != key {
		t.Fatal("routine registration discarded the cached public key")
	}
	if got, exists := srv.peers[removedDomainID]; !exists || got.Observed != peer.Observed {
		t.Fatal("routine registration discarded or changed the active peer")
	}
}
