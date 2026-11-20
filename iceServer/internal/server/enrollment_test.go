package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/overte-org/overte-ice-server/internal/config"
)

func TestEnrollmentAndRegistration(t *testing.T) {
	secret := "0123456789012345678901234567890123456789012345678901234567890123"
	srv, err := New(config.Config{DataFile: filepath.Join(t.TempDir(), "registry.json"), EnrollmentToken: secret})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"directory_id":"dir-one","base_url":"https://directory.example","domains":[]}`)
	request := func(path, token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		if path == "/v1/enroll" {
			srv.handleEnroll(w, r)
		} else {
			srv.handleRegister(w, r)
		}
		return w
	}
	if w := request("/v1/enroll", "invalid", payload); w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bootstrap: %d", w.Code)
	}
	w := request("/v1/enroll", secret, payload)
	if w.Code != http.StatusOK {
		t.Fatalf("enrollment: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		RegistrationToken string `json:"registration_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.RegistrationToken) != 64 {
		t.Fatal("missing issued credential")
	}
	if w = request("/v1/enroll", secret, payload); w.Code != http.StatusConflict {
		t.Fatal("duplicate enrollment allowed")
	}
	updated := []byte(`{"directory_id":"dir-one","base_url":"https://directory.example","domains":["4784f9dc-388c-47c3-8855-373d22f31ff4"]}`)
	if w = request("/v1/register", "wrong", updated); w.Code != http.StatusUnauthorized {
		t.Fatal("unauthorized registration allowed")
	}
	if w = request("/v1/register", resp.RegistrationToken, updated); w.Code != http.StatusOK {
		t.Fatalf("update failed: %s", w.Body.String())
	}
	if _, ok := srv.registry.Owner("4784f9dc-388c-47c3-8855-373d22f31ff4"); !ok {
		t.Fatal("ownership not synchronized")
	}
}
