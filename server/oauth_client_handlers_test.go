package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestClientRegistration_BadJSON(t *testing.T) {
	engine := newClientRegEngine(t)
	prev := os.Getenv("REG_DB_DSN")
	dsn, err := getTestDSN()
	if err == nil {
		os.Setenv("REG_DB_DSN", dsn)
	}
	defer func() {
		if prev != "" {
			os.Setenv("REG_DB_DSN", prev)
		} else {
			os.Unsetenv("REG_DB_DSN")
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestClientRegistration_MissingRedirectURIs(t *testing.T) {
	engine := newClientRegEngine(t)
	prev := os.Getenv("REG_DB_DSN")
	dsn, err := getTestDSN()
	if err == nil {
		os.Setenv("REG_DB_DSN", dsn)
	}
	defer func() {
		if prev != "" {
			os.Setenv("REG_DB_DSN", prev)
		} else {
			os.Unsetenv("REG_DB_DSN")
		}
	}()
	payload := map[string]interface{}{"name": "test-client", "client_secret": "secret"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body=%s", w.Code, w.Body.String())
	}
}

func TestClientRegistration_NotImplementedWhenDSNUnset(t *testing.T) {
	engine := newClientRegEngine(t)
	prev := os.Getenv("REG_DB_DSN")
	_ = os.Unsetenv("REG_DB_DSN")
	defer func() {
		if prev != "" {
			os.Setenv("REG_DB_DSN", prev)
		} else {
			os.Unsetenv("REG_DB_DSN")
		}
	}()
	payload := map[string]interface{}{"name": "test-client", "client_secret": "secret", "redirect_uris": []string{"http://localhost/callback"}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d; body=%s", w.Code, w.Body.String())
	}
}

func TestClientRegistration_Success(t *testing.T) {
	engine := newClientRegEngine(t)
	prev := os.Getenv("REG_DB_DSN")
	dsn, err := getTestDSN()
	if err != nil {
		t.Fatalf("getTestDSN: %v", err)
	}
	os.Setenv("REG_DB_DSN", dsn)
	defer func() {
		if prev != "" {
			os.Setenv("REG_DB_DSN", prev)
		} else {
			os.Unsetenv("REG_DB_DSN")
		}
	}()
	payload := map[string]interface{}{
		"name":          "client-name",
		"redirect_uris": []string{"http://localhost/callback"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/oauth/clients", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body=%s", w.Code, w.Body.String())
	}
	// basic sanity: response contains client_id
	if !contains(w.Body.String(), "client_id") {
		t.Fatalf("response missing client_id: %s", w.Body.String())
	}
}
