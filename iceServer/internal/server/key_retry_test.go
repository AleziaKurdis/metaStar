package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/registry"
)

const retryTestDomainID = "4784f9dc-388c-47c3-8855-373d22f31ff4"

func TestKeyFetchFailureUsesExponentialBackoff(t *testing.T) {
	var countMu sync.Mutex
	requests := 0
	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countMu.Lock()
		requests++
		countMu.Unlock()
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer directory.Close()

	srv, err := New(config.Config{
		DataFile: filepath.Join(t.TempDir(), "registry.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = directory.Client()
	owner := registry.Directory{ID: "directory-one", BaseURL: directory.URL}
	if err := srv.registry.Register(owner.ID, owner.BaseURL, []string{retryTestDomainID}); err != nil {
		t.Fatal(err)
	}

	srv.requestKey(owner, retryTestDomainID, false)
	waitForKeyFetchToFinish(t, srv, retryTestDomainID)

	srv.keysMu.RLock()
	first := srv.keyRetries[retryTestDomainID]
	srv.keysMu.RUnlock()
	if first.failures != 1 {
		t.Fatalf("first failure count = %d, want 1", first.failures)
	}
	if remaining := time.Until(first.nextAttempt); remaining <= 0 || remaining > time.Second {
		t.Fatalf("first retry delay remaining = %s, want a future time within one second", remaining)
	}

	srv.requestKey(owner, retryTestDomainID, false)
	time.Sleep(100 * time.Millisecond)
	countMu.Lock()
	gotRequests := requests
	countMu.Unlock()
	if gotRequests != 1 {
		t.Fatalf("request count during backoff = %d, want 1", gotRequests)
	}

	// Expire the retry window without waiting in real time.
	srv.keysMu.Lock()
	retry := srv.keyRetries[retryTestDomainID]
	retry.nextAttempt = time.Now().Add(-time.Second)
	srv.keyRetries[retryTestDomainID] = retry
	srv.keysMu.Unlock()

	srv.requestKey(owner, retryTestDomainID, false)
	waitForKeyFetchToFinish(t, srv, retryTestDomainID)
	countMu.Lock()
	gotRequests = requests
	countMu.Unlock()
	if gotRequests != 2 {
		t.Fatalf("request count after retry window = %d, want 2", gotRequests)
	}

	srv.keysMu.RLock()
	second := srv.keyRetries[retryTestDomainID]
	srv.keysMu.RUnlock()
	if second.failures != 2 {
		t.Fatalf("second failure count = %d, want 2", second.failures)
	}
	if remaining := time.Until(second.nextAttempt); remaining <= time.Second || remaining > 2*time.Second {
		t.Fatalf("second retry delay remaining = %s, want approximately two seconds", remaining)
	}
}

func TestKeyFetchRetryDelayCapsAtThirtySeconds(t *testing.T) {
	tests := []struct {
		failures uint
		want     time.Duration
	}{
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 30 * time.Second},
		{20, 30 * time.Second},
	}
	for _, tt := range tests {
		if got := keyFetchRetryDelay(tt.failures); got != tt.want {
			t.Errorf("keyFetchRetryDelay(%d) = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestOwnershipChangeClearsKeyRetryState(t *testing.T) {
	srv, err := New(config.Config{DataFile: filepath.Join(t.TempDir(), "registry.json")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.registry.Enroll("directory-one", "https://one.example", []string{retryTestDomainID}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.registry.Enroll("directory-two", "https://two.example", nil); err != nil {
		t.Fatal(err)
	}
	previousOwners := srv.registry.Snapshot().Owners

	if err := srv.registry.Register("directory-one", "https://one.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := srv.registry.Register("directory-two", "https://two.example", []string{retryTestDomainID}); err != nil {
		t.Fatal(err)
	}

	srv.keysMu.Lock()
	srv.keyRetries[retryTestDomainID] = keyRetryState{
		owner: keyRequestOwner{directoryID: "directory-one", baseURL: "https://one.example"},
		failures: 3,
		nextAttempt: time.Now().Add(30 * time.Second),
	}
	srv.keysMu.Unlock()

	srv.evictPeersForOwnershipChanges(previousOwners)

	srv.keysMu.RLock()
	_, exists := srv.keyRetries[retryTestDomainID]
	_, cooldownExists := srv.keyRefreshCooldowns[retryTestDomainID]
	srv.keysMu.RUnlock()
	if exists || cooldownExists {
		t.Fatal("retry state for the previous Directory Service owner was retained")
	}
}

func waitForKeyFetchToFinish(t *testing.T, srv *Server, domainID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.keysMu.RLock()
		_, pending := srv.pending[domainID]
		_, retry := srv.keyRetries[domainID]
		srv.keysMu.RUnlock()
		if !pending && retry {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("key fetch did not finish and record retry state")
}

func TestSuccessfulInvalidSignatureRefreshHasCooldown(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	var countMu sync.Mutex
	requests := 0
	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countMu.Lock()
		requests++
		countMu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]string{
				"public_key": base64.StdEncoding.EncodeToString(publicDER),
			},
		})
	}))
	defer directory.Close()

	srv, err := New(config.Config{DataFile: filepath.Join(t.TempDir(), "registry.json")})
	if err != nil {
		t.Fatal(err)
	}
	srv.keyClient = directory.Client()
	owner := registry.Directory{ID: "directory-one", BaseURL: directory.URL}
	if err := srv.registry.Register(owner.ID, owner.BaseURL, []string{retryTestDomainID}); err != nil {
		t.Fatal(err)
	}

	srv.requestKey(owner, retryTestDomainID, true)
	waitForSuccessfulKeyFetch(t, srv, retryTestDomainID)

	// Repeated invalid signatures during the cooldown must not cause another
	// outbound request to the Directory Service.
	srv.requestKey(owner, retryTestDomainID, true)
	time.Sleep(100 * time.Millisecond)
	countMu.Lock()
	gotRequests := requests
	countMu.Unlock()
	if gotRequests != 1 {
		t.Fatalf("requests during refresh cooldown = %d, want 1", gotRequests)
	}

	// Once the cooldown expires, a later signature failure may refresh again.
	srv.keysMu.Lock()
	cooldown := srv.keyRefreshCooldowns[retryTestDomainID]
	cooldown.nextAttempt = time.Now().Add(-time.Second)
	srv.keyRefreshCooldowns[retryTestDomainID] = cooldown
	srv.keysMu.Unlock()

	srv.requestKey(owner, retryTestDomainID, true)
	waitForSuccessfulKeyFetchCount(t, srv, retryTestDomainID, 2)
	countMu.Lock()
	gotRequests = requests
	countMu.Unlock()
	if gotRequests != 2 {
		t.Fatalf("requests after cooldown expiry = %d, want 2", gotRequests)
	}
}

func waitForSuccessfulKeyFetch(t *testing.T, srv *Server, domainID string) {
	t.Helper()
	waitForSuccessfulKeyFetchCount(t, srv, domainID, 1)
}

func waitForSuccessfulKeyFetchCount(t *testing.T, srv *Server, domainID string, wantRequests int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.keysMu.RLock()
		_, pending := srv.pending[domainID]
		key := srv.keys[domainID]
		_, cooldown := srv.keyRefreshCooldowns[domainID]
		srv.keysMu.RUnlock()
		if !pending && key != nil && cooldown {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("successful key refresh did not finish (expected request count %d)", wantRequests)
}
