package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4/manage"
)

func TestSwaggerIncludesAPILogin(t *testing.T) {
	m := manage.NewDefaultManager()
	srv := NewServer(NewConfig(), m)
	r := NewGinEngine(srv)

	req := httptest.NewRequest(http.MethodGet, "/swagger.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/api/login") {
		t.Fatalf("swagger.json does not include /api/login, body=%s", w.Body.String())
	}
}
