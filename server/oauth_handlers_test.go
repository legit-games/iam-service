package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
)

// build engine with memory token store and a test client
func newOAuthTestEngine(t *testing.T) *gin.Engine {
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("client", &models.Client{ID: "client", Secret: "secret", Domain: "http://localhost/callback"})
	m.MapClientStorage(cs)
	srv := NewServer(NewConfig(), m)
	// allow client_credentials
	srv.SetClientAuthorizedHandler(func(clientID string, gt oauth2.GrantType) (bool, error) { return true, nil })
	// for scope allow all
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (bool, error) { return true, nil })
	return NewGinEngine(srv)
}

func TestAuthorize_InvalidRequest(t *testing.T) {
	engine := newOAuthTestEngine(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body, got: %q", w.Body.String())
	}
}

func TestToken_ClientCredentials(t *testing.T) {
	engine := newOAuthTestEngine(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client", "secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "access_token") {
		t.Fatalf("token response missing access_token: %s", w.Body.String())
	}
}

func TestIntrospect_Inactive(t *testing.T) {
	engine := newOAuthTestEngine(t)
	form := url.Values{}
	form.Set("token", "nonexistent")
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client", "secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !contains(w.Body.String(), "\"active\":false") {
		t.Fatalf("expected inactive=false, got: %s", w.Body.String())
	}
}

func TestRevocation_Always200(t *testing.T) {
	engine := newOAuthTestEngine(t)
	form := url.Values{}
	form.Set("token", "nonexistent")
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client", "secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
