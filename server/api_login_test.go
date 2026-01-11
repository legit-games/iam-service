package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"golang.org/x/crypto/bcrypt"
)

// helper to build engine with mocked client info handler
func newTestEngine(t *testing.T) *gin.Engine {
	m := manage.NewDefaultManager()
	// use memory token store for tests
	m.MustTokenStorage(store.NewMemoryTokenStore())
	// seed client store with test client
	cs := store.NewClientStore()
	cs.Set("test-client", &models.Client{ID: "test-client", Secret: "secret", Domain: "http://localhost"})
	m.MapClientStorage(cs)

	srv := NewServer(NewConfig(), m)
	// mock client info handler to avoid requiring Basic header
	srv.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		return "test-client", "secret", nil
	})
	return NewGinEngine(srv)
}

func TestAPILogin_MethodNotAllowed(t *testing.T) {
	engine := newTestEngine(t)
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/public/login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAPILogin_BadJSON(t *testing.T) {
	engine := newTestEngine(t)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAPILogin_MissingFields(t *testing.T) {
	engine := newTestEngine(t)
	// Missing namespace
	body := []byte(`{"username":"test","password":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing namespace, got %d", w.Code)
	}

	// Missing all fields
	body2 := []byte(`{"username":"","password":"","namespace":""}`)
	req2 := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty fields, got %d", w2.Code)
	}
}

func TestAPILogin_Success(t *testing.T) {
	engine := newTestEngine(t)
	db, err := openTestDB()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer db.Close()
	// generate legit id (hyphenless UUID) and insert user with unique username
	hash, _ := bcrypt.GenerateFromPassword([]byte("p@ssw0rd"), bcrypt.DefaultCost)
	uid := models.LegitID()
	uname := fmt.Sprintf("tester_%s", uid)
	// Set email_verified=TRUE so login succeeds (email verification is required)
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash, email_verified) VALUES ($1, $2, $3, TRUE)`, uid, uname, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	body := []byte(fmt.Sprintf(`{"username":"%s","password":"p@ssw0rd","namespace":"TESTNS"}`, uname))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "access_token") || !contains(w.Body.String(), "refresh_token") {
		t.Fatalf("token response missing fields: %s", w.Body.String())
	}
}

// contains helper reused from swagger test
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool { return stringIndex(s, substr) >= 0 })()
}

func stringIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
