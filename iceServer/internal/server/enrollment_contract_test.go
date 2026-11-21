package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/overte-org/overte-ice-server/internal/config"
)

const contractDomainOne = "4784f9dc-388c-47c3-8855-373d22f31ff4"
const contractDomainTwo = "11111111-2222-4333-8444-555555555555"

func newContractServer(t *testing.T) (*Server, string) {
	t.Helper()
	secret := "0123456789012345678901234567890123456789012345678901234567890123"
	srv, err := New(config.Config{
		DataFile:        filepath.Join(t.TempDir(), "registry.json"),
		EnrollmentToken: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, secret
}

func callContractHandler(srv *Server, method, path, token string, payload []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	switch path {
	case "/v1/enroll":
		srv.handleEnroll(response, req)
	case "/v1/register":
		srv.handleRegister(response, req)
	default:
		panic("unexpected contract path")
	}
	return response
}

func contractPayload(directoryID, baseURL string, domains ...string) []byte {
	body, err := json.Marshal(registerRequest{DirectoryID: directoryID, BaseURL: baseURL, Domains: domains})
	if err != nil {
		panic(err)
	}
	return body
}

func TestEnrollmentHTTPContract(t *testing.T) {
	srv, enrollmentSecret := newContractServer(t)
	payload := contractPayload("directory-one", "https://directory.example", contractDomainOne, contractDomainTwo)

	if got := callContractHandler(srv, http.MethodPost, "/v1/enroll", "incorrect", payload).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong enrollment secret: got HTTP %d, want 401", got)
	}

	response := callContractHandler(srv, http.MethodPost, "/v1/enroll", enrollmentSecret, payload)
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment: HTTP %d: %s", response.Code, response.Body.String())
	}
	var decoded struct {
		Status           string `json:"status"`
		RegistrationToken string `json:"registration_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "success" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(decoded.RegistrationToken) {
		t.Fatalf("unexpected enrollment response contract: %#v", decoded)
	}
	if got := callContractHandler(srv, http.MethodPost, "/v1/enroll", enrollmentSecret, payload).Code; got != http.StatusConflict {
		t.Fatalf("duplicate enrollment: got HTTP %d, want 409", got)
	}

	// The token is returned only by the successful one-time enrollment and
	// can authenticate a subsequent complete ownership-list synchronization.
	update := contractPayload("directory-one", "https://directory.example", contractDomainTwo)
	response = callContractHandler(srv, http.MethodPost, "/v1/register", decoded.RegistrationToken, update)
	if response.Code != http.StatusOK {
		t.Fatalf("registration: HTTP %d: %s", response.Code, response.Body.String())
	}
	var registered struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.Status != "success" || registered.Message == "" {
		t.Fatalf("unexpected registration response: %#v", registered)
	}
	if _, ok := srv.registry.Owner(contractDomainOne); ok {
		t.Fatal("domain removed from the complete list is still owned")
	}
	owner, ok := srv.registry.Owner(contractDomainTwo)
	if !ok || owner.ID != "directory-one" {
		t.Fatalf("updated domain owner missing: %#v, exists=%v", owner, ok)
	}
}

func TestRegistrationContractRejectsInvalidAndConflictingOwnership(t *testing.T) {
	srv, secret := newContractServer(t)
	enroll := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-one", "https://one.example", contractDomainOne))
	if enroll.Code != http.StatusOK {
		t.Fatalf("first enrollment failed: %d %s", enroll.Code, enroll.Body.String())
	}
	var first struct {
		RegistrationToken string `json:"registration_token"`
	}
	if err := json.Unmarshal(enroll.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	second := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-two", "https://two.example", contractDomainOne))
	if second.Code != http.StatusConflict {
		t.Fatalf("cross-directory ownership conflict: got HTTP %d, want 409", second.Code)
	}

	invalidUUID := "11111111-2222-0333-8444-555555555555"
	invalid := callContractHandler(srv, http.MethodPost, "/v1/register", first.RegistrationToken,
		contractPayload("directory-one", "https://one.example", invalidUUID))
	if invalid.Code != http.StatusConflict {
		t.Fatalf("invalid UUID: got HTTP %d, want 409", invalid.Code)
	}

	duplicate := callContractHandler(srv, http.MethodPost, "/v1/register", first.RegistrationToken,
		contractPayload("directory-one", "https://one.example", contractDomainOne, contractDomainOne))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate UUID: got HTTP %d, want 409", duplicate.Code)
	}
}

func TestRegistrationContractRejectsMalformedAndOversizedBodies(t *testing.T) {
	srv, secret := newContractServer(t)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "malformed JSON", body: []byte(`{"directory_id":`)},
		{name: "oversized JSON", body: bytes.Repeat([]byte("x"), (1<<20)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret, tc.body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRegistrationCredentialSurvivesServerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	secret := "0123456789012345678901234567890123456789012345678901234567890123"
	first, err := New(config.Config{DataFile: path, EnrollmentToken: secret})
	if err != nil {
		t.Fatal(err)
	}
	response := callContractHandler(first, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-one", "https://directory.example", contractDomainOne))
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d %s", response.Code, response.Body.String())
	}
	var enrolled struct {
		RegistrationToken string `json:"registration_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(config.Config{DataFile: path, EnrollmentToken: secret})
	if err != nil {
		t.Fatal(err)
	}
	response = callContractHandler(restarted, http.MethodPost, "/v1/register", enrolled.RegistrationToken,
		contractPayload("directory-one", "https://directory.example", contractDomainTwo))
	if response.Code != http.StatusOK {
		t.Fatalf("registration after restart: HTTP %d: %s", response.Code, response.Body.String())
	}
	if _, ok := restarted.registry.Owner(contractDomainOne); ok {
		t.Fatal("old domain remains after post-restart full-list synchronization")
	}
	if owner, ok := restarted.registry.Owner(contractDomainTwo); !ok || owner.ID != "directory-one" {
		t.Fatalf("new domain ownership not persisted after restart: %#v %v", owner, ok)
	}
}

func TestRegistrationContractUnauthorizedAndWrongDirectory(t *testing.T) {
	srv, secret := newContractServer(t)
	response := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-one", "https://directory.example"))
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d %s", response.Code, response.Body.String())
	}
	var enrolled struct {
		RegistrationToken string `json:"registration_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		token  string
		domain string
	}{
		{name: "missing token", token: "", domain: "directory-one"},
		{name: "wrong token", token: "wrong-token", domain: "directory-one"},
		{name: "wrong directory id", token: enrolled.RegistrationToken, domain: "directory-two"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := contractPayload(tc.domain, "https://directory.example")
			response := callContractHandler(srv, http.MethodPost, "/v1/register", tc.token, body)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("got HTTP %d, want 401: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRegistrationContractRejectsNonHTTPSBaseURL(t *testing.T) {
	srv, secret := newContractServer(t)
	response := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-one", "http://directory.example", contractDomainOne))
	if response.Code != http.StatusConflict {
		t.Fatalf("HTTP base URL: got %d, want 409: %s", response.Code, response.Body.String())
	}
	if _, ok := srv.registry.Owner(contractDomainOne); ok {
		t.Fatal("invalid enrollment created domain ownership")
	}
}

func TestRegistrationContractResponseIsJSON(t *testing.T) {
	srv, secret := newContractServer(t)
	response := callContractHandler(srv, http.MethodPost, "/v1/enroll", secret,
		contractPayload("directory-one", "https://directory.example"))
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if !json.Valid(response.Body.Bytes()) {
		t.Fatalf("response is not valid JSON: %s", fmt.Sprint(response.Body.String()))
	}
}
