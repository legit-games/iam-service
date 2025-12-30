package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
)

// helper to create a test server with memory stores and a client
func newTestServer() (*Server, *manage.Manager) {
	mgr := manage.NewDefaultManager()
	mgr.MustTokenStorage(store.NewMemoryTokenStore())
	clientStore := store.NewClientStore()
	clientStore.Set("test-client", &models.Client{
		ID:     "test-client",
		Secret: "test-secret",
		Domain: "http://localhost",
	})
	mgr.MapClientStorage(clientStore)
	return NewServer(NewConfig(), mgr), mgr
}

func TestHandleIntrospectionRequest_ActiveToken(t *testing.T) {
	srv, _ := newTestServer()
	// issue a token via token store by creating token through manager
	// create a token by using client credentials grant
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// authenticate client via basic
	r.SetBasicAuth("test-client", "test-secret")
	w := httptest.NewRecorder()
	if err := srv.HandleTokenRequest(w, r); err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	access := tokenResp["access_token"].(string)

	// introspect the access token
	form := url.Values{
		"token":           {access},
		"token_type_hint": {"access_token"},
	}
	ir := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	ir.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// allow basic or form auth
	srv.SetClientInfoHandler(ClientBasicOrFormHandler)
	ir.SetBasicAuth("test-client", "test-secret")
	iw := httptest.NewRecorder()
	if err := srv.HandleIntrospectionRequest(iw, ir); err != nil {
		t.Fatalf("introspection failed: %v", err)
	}
	if iw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", iw.Code)
	}
	var introspect map[string]interface{}
	if err := json.Unmarshal(iw.Body.Bytes(), &introspect); err != nil {
		t.Fatalf("invalid introspect response: %v", err)
	}
	if active, ok := introspect["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true, got %v", introspect["active"])
	}
}

func TestHandleRevocationRequest_RevokesAccessToken(t *testing.T) {
	srv, _ := newTestServer()
	// issue a token
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("test-client", "test-secret")
	w := httptest.NewRecorder()
	if err := srv.HandleTokenRequest(w, r); err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	access := tokenResp["access_token"].(string)

	// revoke the access token
	form := url.Values{
		"token":           {access},
		"token_type_hint": {"access_token"},
	}
	rv := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	rv.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.SetClientInfoHandler(ClientBasicOrFormHandler)
	rv.SetBasicAuth("test-client", "test-secret")
	rw := httptest.NewRecorder()
	if err := srv.HandleRevocationRequest(rw, rv); err != nil {
		t.Fatalf("revocation failed: %v", err)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}

	// introspect again to ensure inactive
	iform := url.Values{
		"token":           {access},
		"token_type_hint": {"access_token"},
	}
	ir := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(iform.Encode()))
	ir.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.SetClientInfoHandler(ClientBasicOrFormHandler)
	ir.SetBasicAuth("test-client", "test-secret")
	iw := httptest.NewRecorder()
	if err := srv.HandleIntrospectionRequest(iw, ir); err != nil {
		t.Fatalf("introspection failed: %v", err)
	}
	var introspect map[string]interface{}
	if err := json.Unmarshal(iw.Body.Bytes(), &introspect); err != nil {
		t.Fatalf("invalid introspect response: %v", err)
	}
	if active, ok := introspect["active"].(bool); !ok || active {
		t.Fatalf("expected active=false after revocation, got %v", introspect["active"])
	}
}

func TestHandleIntrospectionRequest_InvalidMethod(t *testing.T) {
	srv, _ := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/oauth/introspect", nil)
	w := httptest.NewRecorder()
	_ = srv.HandleIntrospectionRequest(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("expected non-200 for invalid method, got %d", w.Code)
	}
}

func TestHandleClientRegistrationRequest_NotImplemented(t *testing.T) {
	srv, _ := newTestServer()
	body, _ := json.Marshal(map[string]interface{}{
		"client_id":     "new-client",
		"client_secret": "new-secret",
		"redirect_uris": []string{"http://localhost/cb"},
	})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if err := srv.HandleClientRegistrationRequest(w, req); err != nil {
		t.Fatalf("registration handler returned error: %v", err)
	}
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 Not Implemented, got %d", w.Code)
	}
}
