package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	body := []byte(`{"username":"","password":""}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAPILogin_DSNNotSet(t *testing.T) {
	engine := newTestEngine(t)
	// backup envs and unset
	prevUser := os.Getenv("USER_DB_DSN")
	prevReg := os.Getenv("REG_DB_DSN")
	_ = os.Unsetenv("USER_DB_DSN")
	_ = os.Unsetenv("REG_DB_DSN")
	defer func() {
		if prevUser != "" {
			os.Setenv("USER_DB_DSN", prevUser)
		} else {
			os.Unsetenv("USER_DB_DSN")
		}
		if prevReg != "" {
			os.Setenv("REG_DB_DSN", prevReg)
		} else {
			os.Unsetenv("REG_DB_DSN")
		}
	}()

	body := []byte(`{"username":"test","password":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d; body=%s", w.Code, w.Body.String())
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
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash) VALUES ($1, $2, $3)`, uid, uname, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	body := []byte(fmt.Sprintf(`{"username":"%s","password":"p@ssw0rd"}`, uname))
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
