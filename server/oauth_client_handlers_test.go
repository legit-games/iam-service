package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/store"
)

// helper to build engine for client registration tests
func newClientRegEngine(t *testing.T) *gin.Engine {
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	srv := NewServer(NewConfig(), m)
	return NewGinEngine(srv)
}

func TestClientRegistration_MethodNotAllowed(t *testing.T) {
	engine := newClientRegEngine(t)
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/oauth/clients", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	// Endpoint removed: expect 404
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestClientRegistration_NotImplementedWhenDSNUnset(t *testing.T) {
	engine := newClientRegEngine(t)
	payload := map[string]interface{}{"name": "test-client", "client_secret": "secret", "redirect_uris": []string{"http://localhost/callback"}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	// Endpoint removed: expect 404 instead of 501
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body=%s", w.Code, w.Body.String())
	}
}

func TestClientRegistration_Success(t *testing.T) {
	engine := newClientRegEngine(t)
	payload := map[string]interface{}{
		"name":          "client-name",
		"redirect_uris": []string{"http://localhost/callback"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	// Endpoint removed: expect 404
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body=%s", w.Code, w.Body.String())
	}
}
