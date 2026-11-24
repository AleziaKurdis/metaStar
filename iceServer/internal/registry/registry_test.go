package registry

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirectoryOwnershipAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	s, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	id := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	if e = s.Register("ds-one", "https://directory.example", []string{id}); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Owner(id); !ok {
		t.Fatal("owner not stored")
	}
	if e = s.Register("ds-two", "https://other.example", []string{id}); e == nil {
		t.Fatal("expected duplicate ownership conflict")
	}
	s2, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	d, ok := s2.Owner(id)
	if !ok || d.ID != "ds-one" {
		t.Fatalf("persisted owner incorrect: %#v %v", d, ok)
	}
}
func TestRegistrationToken(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Enroll("one", "https://directory.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.TokenValid("one", token) {
		t.Fatal("valid token rejected")
	}
	if s.TokenValid("one", "wrong") {
		t.Fatal("invalid token accepted")
	}
	if _, err := s.Enroll("one", "https://directory.example", nil); err == nil {
		t.Fatal("duplicate enrollment allowed")
	}
	restored, err := New(filepath.Join(filepath.Dir(s.path), "registry.json"))
	if err != nil || !restored.TokenValid("one", token) {
		t.Fatal("credential persistence failed", err)
	}
}

func TestRegisterRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	registryDir := filepath.Join(t.TempDir(), "registry-data")
	path := filepath.Join(registryDir, "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	token, err := s.Enroll("directory-one", "https://one.example", []string{domainID})
	if err != nil {
		t.Fatal(err)
	}

	// Replace the registry file with a directory. saveLocked can write its
	// temporary file, but the final atomic rename onto this directory fails.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}

	err = s.Register("directory-one", "https://one.example", nil)
	if err == nil {
		t.Fatal("expected persistence failure")
	}

	owner, ok := s.Owner(domainID)
	if !ok || owner.ID != "directory-one" {
		t.Fatalf("failed update changed in-memory owner: owner=%#v exists=%v", owner, ok)
	}
	snapshot := s.Snapshot()
	directory, ok := snapshot.Directories["directory-one"]
	if !ok || len(directory.Domains) != 1 || directory.Domains[0] != domainID {
		t.Fatalf("failed update changed in-memory directory: %#v", directory)
	}
	if !s.TokenValid("directory-one", token) {
		t.Fatal("failed update discarded the existing enrollment credential")
	}
}

func TestEnrollRollsBackOwnershipAndCredentialWhenPersistenceFails(t *testing.T) {
	registryDir := filepath.Join(t.TempDir(), "registry-data")
	path := filepath.Join(registryDir, "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	// Force the final atomic rename to fail, after the temporary file can be
	// written. Enrollment must not leave an in-memory owner without a token.
	if err := os.MkdirAll(registryDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}

	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	if _, err := s.Enroll("directory-one", "https://one.example", []string{domainID}); err == nil {
		t.Fatal("expected enrollment persistence failure")
	}

	if _, ok := s.Owner(domainID); ok {
		t.Fatal("failed enrollment left domain ownership in memory")
	}
	snapshot := s.Snapshot()
	if _, ok := snapshot.Directories["directory-one"]; ok {
		t.Fatal("failed enrollment left a directory in memory")
	}
	if _, ok := snapshot.CredentialHashes["directory-one"]; ok {
		t.Fatal("failed enrollment left a credential hash in memory")
	}
}

func TestDomainUUIDValidationMatchesDirectoryServer(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	valid := []string{
		"4784f9dc-388c-47c3-8855-373d22f31ff4",
		"11111111-2222-1333-8444-555555555555",
		"aaaaaaaa-bbbb-8ccc-9ddd-eeeeeeeeeeee",
	}
	for _, id := range valid {
		if err := s.Register("directory", "https://directory.example", []string{id}); err != nil {
			t.Errorf("valid UUID %q rejected: %v", id, err)
		}
	}
	invalid := []string{
		"11111111-2222-0333-8444-555555555555", // unsupported UUID version
		"11111111-2222-4333-7444-555555555555", // invalid RFC variant
		"not-a-domain-id",
	}
	for i, id := range invalid {
		if err := s.Register("invalid-"+string(rune('a'+i)), "https://directory.example", []string{id}); err == nil {
			t.Errorf("invalid UUID %q accepted", id)
		}
	}
}

func TestRecoverRotatesCredentialAndPreservesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	oldToken, err := s.Enroll("directory-one", "https://directory.example", []string{domainID})
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := s.Recover("directory-one")
	if err != nil {
		t.Fatal(err)
	}
	if oldToken == newToken {
		t.Fatal("recovery returned the same token")
	}
	if s.TokenValid("directory-one", oldToken) {
		t.Fatal("old token remains valid")
	}
	if !s.TokenValid("directory-one", newToken) {
		t.Fatal("new token is not valid")
	}
	owner, ok := s.Owner(domainID)
	if !ok || owner.ID != "directory-one" || owner.BaseURL != "https://directory.example" {
		t.Fatalf("recovery changed directory ownership: %#v %v", owner, ok)
	}
	restarted, err := New(path)
	if err != nil || !restarted.TokenValid("directory-one", newToken) {
		t.Fatalf("recovered credential did not persist across restart: %v", err)
	}
}

func TestRecoverRejectsUnknownDirectory(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover("not-enrolled"); err == nil {
		t.Fatal("recovery created an unknown directory")
	}
}

func TestRecoverRollsBackCredentialWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := s.Enroll("directory-one", "https://directory.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover("directory-one"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if !s.TokenValid("directory-one", oldToken) {
		t.Fatal("failed recovery invalidated the previous token")
	}
}

func TestLoadRejectsAmbiguousPersistedDomainOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	data := `{
		"directories": {
			"directory-one": {
				"id": "directory-one",
				"base_url": "https://one.example",
				"domains": ["4784f9dc-388c-47c3-8855-373d22f31ff4"]
			},
			"directory-two": {
				"id": "directory-two",
				"base_url": "https://two.example",
				"domains": ["4784f9dc-388c-47c3-8855-373d22f31ff4"]
			}
		},
		"owners": {},
		"credential_hashes": {}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("registry with a domain assigned to two directories was loaded")
	}
}

func TestLoadRejectsInvalidPersistedDomainUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	data := `{
		"directories": {
			"directory-one": {
				"id": "directory-one",
				"base_url": "https://one.example",
				"domains": ["not-a-domain-uuid"]
			}
		},
		"owners": {},
		"credential_hashes": {}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("registry with an invalid domain UUID was loaded")
	}
}

func TestRegisterAuthorizedRejectsRotatedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	oldToken, err := s.Enroll("directory-one", "https://one.example", []string{domainID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover("directory-one"); err != nil {
		t.Fatal(err)
	}
	authorized, err := s.RegisterAuthorized("directory-one", oldToken, "https://attacker.example", nil)
	if err != nil {
		t.Fatalf("stale credential should be rejected as unauthorized, not as a registration error: %v", err)
	}
	if authorized {
		t.Fatal("registration accepted a credential that had already been rotated")
	}
	owner, ok := s.Owner(domainID)
	if !ok || owner.BaseURL != "https://one.example" {
		t.Fatalf("stale credential changed directory state: %#v, exists=%v", owner, ok)
	}
}

func TestLoadRejectsInsecurePersistedDirectoryURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	data := `{
		"directories": {
			"directory-one": {
				"id": "directory-one",
				"base_url": "http://directory.example",
				"domains": ["4784f9dc-388c-47c3-8855-373d22f31ff4"]
			}
		},
		"owners": {},
		"credential_hashes": {}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("registry with an HTTP Directory Service URL was loaded")
	}
}

func TestLoadRejectsMismatchedPersistedDirectoryID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	data := `{
		"directories": {
			"directory-one": {
				"id": "directory-two",
				"base_url": "https://directory.example",
				"domains": []
			}
		},
		"owners": {},
		"credential_hashes": {}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("registry with a mismatched Directory Service ID was loaded")
	}
}


func TestSaveUsesPrivateUniqueTemporaryFileAndCleansItUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register("directory-one", "https://one.example", nil); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Fatalf("registry file mode = %04o, want 0640", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "registry.json" {
		t.Fatalf("temporary registry files were not cleaned up: %v", entries)
	}
}


func TestSaveDoesNotFollowLegacyTemporaryFileSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated privileges on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	legacyTempPath := path + ".tmp"
	targetPath := filepath.Join(dir, "sentinel")
	original := []byte("do not overwrite this file")

	if err := os.WriteFile(targetPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, legacyTempPath); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register("directory-one", "https://one.example", nil); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("pre-existing temporary-file symlink target was modified: got %q, want %q", got, original)
	}

	info, err := os.Lstat(legacyTempPath)
	if err != nil {
		t.Fatalf("pre-existing temporary-file symlink was removed or replaced: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("pre-existing temporary-file symlink was replaced")
	}
}


func TestUnregisterAuthorizedReleasesOwnershipAndCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	domainOne := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	domainTwo := "11111111-2222-4333-8444-555555555555"
	token, err := store.Enroll("directory-one", "https://one.example", []string{domainOne, domainTwo})
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := store.Enroll("directory-two", "https://two.example", nil)
	if err != nil {
		t.Fatal(err)
	}

	authorized, removed, err := store.UnregisterAuthorized("directory-one", "incorrect-token")
	if err != nil || authorized || len(removed) != 0 {
		t.Fatalf("invalid credential result: authorized=%v removed=%v err=%v", authorized, removed, err)
	}
	if _, ok := store.Owner(domainOne); !ok {
		t.Fatal("invalid credential changed domain ownership")
	}

	authorized, removed, err = store.UnregisterAuthorized("directory-one", token)
	if err != nil || !authorized {
		t.Fatalf("valid unregistration failed: authorized=%v err=%v", authorized, err)
	}
	if len(removed) != 2 || removed[0] != domainOne || removed[1] != domainTwo {
		t.Fatalf("removed domains = %v, want sorted domain IDs", removed)
	}
	if _, ok := store.Owner(domainOne); ok {
		t.Fatal("unregistered directory still owns its first domain")
	}
	if _, ok := store.Owner(domainTwo); ok {
		t.Fatal("unregistered directory still owns its second domain")
	}
	if store.TokenValid("directory-one", token) {
		t.Fatal("unregistered directory credential remains valid")
	}
	if !store.TokenValid("directory-two", otherToken) {
		t.Fatal("unregistering one directory affected another directory's credential")
	}

	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Snapshot().Directories["directory-one"]; ok {
		t.Fatal("unregistration did not persist")
	}
	if !restarted.TokenValid("directory-two", otherToken) {
		t.Fatal("other directory credential did not persist")
	}
}

func TestUnregisterAuthorizedRollsBackWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	domainID := "4784f9dc-388c-47c3-8855-373d22f31ff4"
	token, err := store.Enroll("directory-one", "https://one.example", []string{domainID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}

	authorized, _, err := store.UnregisterAuthorized("directory-one", token)
	if !authorized || err == nil {
		t.Fatalf("expected authorized persistence failure, got authorized=%v err=%v", authorized, err)
	}
	owner, ok := store.Owner(domainID)
	if !ok || owner.ID != "directory-one" {
		t.Fatalf("failed unregistration changed domain ownership: %#v exists=%v", owner, ok)
	}
	if !store.TokenValid("directory-one", token) {
		t.Fatal("failed unregistration invalidated the previous credential")
	}
}
