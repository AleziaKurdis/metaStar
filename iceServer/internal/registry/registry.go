package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Directory struct {
	ID      string   `json:"id"`
	BaseURL string   `json:"base_url"`
	Domains []string `json:"domains"`
}
type Snapshot struct {
	CredentialHashes map[string]string    `json:"credential_hashes"`
	Directories      map[string]Directory `json:"directories"`
	Owners           map[string]string    `json:"owners"`
}

// Match the UUID version and RFC variant requirements enforced by the PHP
// Directory Server before it sends its complete domain ownership list.
var validUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Store struct {
	mu   sync.RWMutex
	path string
	data Snapshot
}

func New(path string) (*Store, error) {
	s := &Store{path: path, data: Snapshot{Directories: map[string]Directory{}, Owners: map[string]string{}, CredentialHashes: map[string]string{}}}
	b, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(b, &s.data); e != nil {
			return nil, e
		}
		if s.data.Directories == nil {
			s.data.Directories = map[string]Directory{}
		}
		if s.data.Owners == nil {
			s.data.Owners = map[string]string{}
		}
		if s.data.CredentialHashes == nil {
			s.data.CredentialHashes = map[string]string{}
		}
		if err := s.rebuildOwners(); err != nil {
			return nil, fmt.Errorf("invalid persisted directory ownership: %w", err)
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}
func (s *Store) rebuildOwners() error {
	owners := make(map[string]string)
	for id, d := range s.data.Directories {
		if id == "" || d.ID != id {
			return fmt.Errorf("directory registry key %q does not match saved directory ID %q", id, d.ID)
		}
		base, err := url.Parse(d.BaseURL)
		if err != nil || base.Scheme != "https" || base.Host == "" || base.Hostname() == "" ||
			base.User != nil || base.RawQuery != "" || base.Fragment != "" {
			return fmt.Errorf("directory %q has an invalid or insecure base_url %q", id, d.BaseURL)
		}
		for _, domain := range d.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if !validUUIDPattern.MatchString(domain) {
				return fmt.Errorf("directory %q contains invalid domain UUID %q", id, domain)
			}
			if previousOwner, exists := owners[domain]; exists {
				if previousOwner == id {
					return fmt.Errorf("domain %s is listed more than once by directory %q", domain, id)
				}
				return fmt.Errorf("domain %s is listed by both directory %q and directory %q", domain, previousOwner, id)
			}
			owners[domain] = id
		}
	}
	s.data.Owners = owners
	return nil
}
func (s *Store) saveLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	// Keep the temporary file beside the registry so rename remains atomic.
	// CreateTemp also avoids following a pre-existing .tmp symlink and gives
	// concurrent service instances distinct temporary names.
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err = tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}
func (s *Store) Register(id, base string, domains []string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("directory_id is required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base_url must be a valid HTTPS URL without credentials, query or fragment")
	}
	base = u.String()

	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !validUUIDPattern.MatchString(d) {
			return fmt.Errorf("invalid domain UUID %q", d)
		}
		if seen[d] {
			return fmt.Errorf("duplicate domain UUID %q", d)
		}
		seen[d] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registerLocked(id, base, domains, "")
}
func (s *Store) registerLocked(id, base string, domains []string, credentialHash string) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return errors.New("base_url must be a valid HTTPS URL")
	}
	if len(domains) > 10000 {
		return errors.New("too many domains")
	}
	seen := map[string]bool{}
	normalized := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !validUUIDPattern.MatchString(d) || seen[d] {
			return fmt.Errorf("invalid or duplicate domain UUID %q", d)
		}
		seen[d] = true
		if owner, ok := s.data.Owners[d]; ok && owner != id {
			return fmt.Errorf("domain %s is already registered to directory %s", d, owner)
		}
		normalized = append(normalized, d)
	}

	// Keep the previous values so a failed disk commit cannot leave the
	// in-memory owner map ahead of the durable registry file.
	previousDirectory, hadDirectory := s.data.Directories[id]
	previousCredential, hadCredential := s.data.CredentialHashes[id]

	s.data.Directories[id] = Directory{ID: id, BaseURL: strings.TrimRight(u.String(), "/"), Domains: normalized}
	if credentialHash != "" {
		s.data.CredentialHashes[id] = credentialHash
	}
	if err := s.rebuildOwners(); err != nil {
		if hadDirectory {
			s.data.Directories[id] = previousDirectory
		} else {
			delete(s.data.Directories, id)
		}
		if hadCredential {
			s.data.CredentialHashes[id] = previousCredential
		} else {
			delete(s.data.CredentialHashes, id)
		}
		_ = s.rebuildOwners()
		return err
	}

	if err := s.saveLocked(); err != nil {
		if hadDirectory {
			s.data.Directories[id] = previousDirectory
		} else {
			delete(s.data.Directories, id)
		}
		if hadCredential {
			s.data.CredentialHashes[id] = previousCredential
		} else {
			delete(s.data.CredentialHashes, id)
		}
		_ = s.rebuildOwners()
		return err
	}
	return nil
}
func (s *Store) Owner(domain string) (Directory, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.data.Owners[strings.ToLower(domain)]
	if !ok {
		return Directory{}, false
	}
	d, ok := s.data.Directories[id]
	return d, ok
}

// Enroll creates a distinct credential for a previously unknown directory.
// Caller must first authenticate with the server's enrollment secret.
func (s *Store) Enroll(id, base string, domains []string) (string, error) {
	id = strings.TrimSpace(id)
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`).MatchString(id) {
		return "", errors.New("invalid directory identifier")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.CredentialHashes[id]; ok {
		return "", errors.New("directory already enrolled")
	}
	if _, ok := s.data.Directories[id]; ok {
		return "", errors.New("directory already exists")
	}
	// Commit directory ownership and its credential in one registry-file write.
	// This prevents a partial enrollment from leaving an owner without a token.
	if err := s.registerLocked(id, base, domains, hex.EncodeToString(hash[:])); err != nil {
		return "", err
	}
	return token, nil
}
// Recover rotates the credential for an already-enrolled directory. The caller
// must authenticate with the ICE Server's enrollment secret. Directory
// ownership is deliberately left unchanged so recovery cannot alter routing.
func (s *Store) Recover(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !regexp.MustCompile("^[A-Za-z0-9._-]{1,128}$").MatchString(id) {
		return "", errors.New("invalid directory identifier")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Directories[id]; !ok {
		return "", errors.New("directory is not enrolled")
	}
	previousHash, hadCredential := s.data.CredentialHashes[id]
	if !hadCredential {
		return "", errors.New("directory registration credential is missing")
	}
	s.data.CredentialHashes[id] = hex.EncodeToString(hash[:])
	if err := s.saveLocked(); err != nil {
		s.data.CredentialHashes[id] = previousHash
		return "", err
	}
	return token, nil
}
// RegisterAuthorized validates the current credential and applies the
// registration update under the same lock. This prevents a credential rotated
// by Recover between an HTTP handler's check and update from being accepted.
func (s *Store) RegisterAuthorized(id, token, base string, domains []string) (bool, error) {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	expected, ok := s.data.CredentialHashes[id]
	if !ok || len(token) < 32 {
		return false, nil
	}
	sum := sha256.Sum256([]byte(token))
	actual := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		return false, nil
	}
	if err := s.registerLocked(id, base, domains, ""); err != nil {
		return true, err
	}
	return true, nil
}

func (s *Store) TokenValid(id, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expected, ok := s.data.CredentialHashes[id]
	if !ok || len(token) < 32 {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	actual := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.data)
	var x Snapshot
	_ = json.Unmarshal(b, &x)
	return x
}
