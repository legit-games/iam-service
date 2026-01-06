package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
)

func TestDebugPasswordGrant(t *testing.T) {
	// Create manager with memory stores
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewAccessGenerate())

	// Create client store
	cliStore := store.NewClientStore()
	client := &models.Client{
		ID:     "test-client",
		Secret: "test-secret",
	}
	_ = cliStore.Set("test-client", client)
	m.MapClientStorage(cliStore)

	// Create minimal config
	cfg := &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
	}

	// Create server
	s := NewServer(cfg, m)
	s.SetClientInfoHandler(ClientFormHandler)
	s.SetAllowedGrantType(oauth2.PasswordCredentials)

	// Set password handler
	s.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		fmt.Printf("Password auth called: clientID=%s, username=%s\n", clientID, username)
		if username == "testuser" && password == "testpass" {
			return "user-123", nil
		}
		return "", fmt.Errorf("invalid credentials")
	})

	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)
		if r.URL.Path == "/token" {
			err := s.HandleTokenRequest(w, r)
			if err != nil {
				fmt.Printf("HandleTokenRequest error: %v\n", err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Create form data
	form := "grant_type=password&username=testuser&password=testpass&client_id=test-client&client_secret=test-secret"

	// Make request
	resp, err := http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %d\n", resp.StatusCode)

	// Read response body
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	fmt.Printf("Response body: %s\n", string(body[:n]))
}
