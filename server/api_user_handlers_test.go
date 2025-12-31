package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/store"
	_ "github.com/lib/pq"
)

func newRegisterTestEngine(t *testing.T) *gin.Engine {
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	srv := NewServer(NewConfig(), m)
	return NewGinEngine(srv)
}

func TestAPIRegisterUser_Success(t *testing.T) {
	engine := newRegisterTestEngine(t)
	// Use a normal, human-readable username with a unique suffix to avoid conflicts
	uname := uniqueUsername()
	body := []byte(fmt.Sprintf(`{"username":"%s","password":"P@ssw0rd!"}`, uname))

	// Pre-clean: delete user if it somehow exists from previous runs
	db, err := openTestDB()
	if err == nil {
		defer db.Close()
		_, _ = db.Exec(`DELETE FROM accounts WHERE username=$1`, uname)
	}

	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body=%s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "user_id") {
		t.Fatalf("expected user_id in response; body=%s", w.Body.String())
	}
}

func uniqueUsername() string {
	return fmt.Sprintf("testuser_%d", NewUniqueCounter())
}

var _counter = make(chan int64, 1)

func init() { _counter <- 1 }

func NewUniqueCounter() int64 {
	v := <-_counter
	_counter <- v + 1
	return v
}
