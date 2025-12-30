package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-oauth2/oauth2/v4/manage"
)

func TestHandleSwaggerJSON_OK(t *testing.T) {
	srv := NewServer(NewConfig(), manage.NewDefaultManager())
	r := httptest.NewRequest(http.MethodGet, "/swagger.json", nil)
	w := httptest.NewRecorder()
	if err := srv.HandleSwaggerJSON(w, r); err != nil {
		t.Fatalf("swagger json handler error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct == "" || ct[:16] != "application/json" {
		t.Fatalf("expected application/json content-type, got %s", ct)
	}
	if w.Body.Len() == 0 {
		t.Fatalf("expected non-empty body")
	}
}

func TestHandleSwaggerUI_OK(t *testing.T) {
	srv := NewServer(NewConfig(), manage.NewDefaultManager())
	r := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	w := httptest.NewRecorder()
	if err := srv.HandleSwaggerUI(w, r); err != nil {
		t.Fatalf("swagger ui handler error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct == "" || ct[:9] != "text/html" {
		t.Fatalf("expected text/html content-type, got %s", ct)
	}
	if w.Body.Len() == 0 {
		t.Fatalf("expected non-empty body")
	}
}
