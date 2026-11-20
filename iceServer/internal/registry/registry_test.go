package registry

import (
	"path/filepath"
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
