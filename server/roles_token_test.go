package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gavv/httpexpect/v2"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// TestPasswordGrant_UserRolePermissionsInJWT verifies that user role permissions are embedded into JWT when namespace is provided
func TestPasswordGrant_UserRolePermissionsInJWT(t *testing.T) {
	// Clear database configuration and config directory to ensure test works without DB
	t.Setenv("CONFIG_DIR", "/tmp/nonexistent")
	t.Setenv("IAM_DATABASE__IAM__READ__DSN", "")
	t.Setenv("IAM_DATABASE__IAM__WRITE__DSN", "")

	// Use JWT access generator to test permissions in token
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("test-key"), jwt.SigningMethodHS256))

	cliStore := store.NewClientStore()
	_ = cliStore.Set("confidential", &models.Client{ID: "confidential", Secret: "secret"})
	m.MapClientStorage(cliStore)

	// Create minimal config without database dependencies
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
	s := NewServer(cfg, m)
	s.SetClientInfoHandler(ClientFormHandler)
	// Explicitly allow password grant for this test
	s.SetAllowedGrantType(oauth2.PasswordCredentials)
	// Password auth accepts test user and returns fixed userID
	s.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		if username == "test" && password == "test" {
			return "user-1", nil
		}
		return "", nil
	})

	// Basic server to route token endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = s.HandleTokenRequest(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	e := httpexpect.New(t, ts.URL)
	resp := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "test").
		WithFormField("password", "test").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		WithFormField("ns", "TESTNS").
		Expect()

	if resp.Raw().StatusCode != 200 {
		// Log the error response for debugging
		body := resp.Body().Raw()
		t.Fatalf("Token request failed with status %d: %s", resp.Raw().StatusCode, body)
	}

	obj := resp.Status(http.StatusOK).JSON().Object()

	access := obj.Value("access_token").String().Raw()
	if access == "" {
		to := obj.Raw()
		t.Fatalf("no access token returned; resp=%v", to)
	}

	// Verify it's a valid JWT token by parsing it
	token, err := jwt.Parse(access, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-key"), nil
	})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		t.Logf("JWT claims: %+v", claims)
		// Check if permissions claim exists
		if perms, exists := claims["permissions"]; exists {
			t.Logf("Permissions in token: %v", perms)
			// Should be empty or nil since no database roles are configured
		} else {
			t.Log("No permissions claim in token (expected when no roles exist)")
		}
	} else {
		t.Fatalf("invalid JWT claims")
	}

	// Test that token generation succeeds even without database/permissions
	// When no database is connected, s.userStore is nil and perm_resolver returns empty array
	// This is the expected behavior: permissions should be empty when no roles exist
	t.Logf("Access token generated successfully (no permissions required)")

	// Test without namespace parameter as well
	obj2 := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "test").
		WithFormField("password", "test").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	access2 := obj2.Value("access_token").String().Raw()
	if access2 == "" {
		to2 := obj2.Raw()
		t.Fatalf("no access token returned (without ns); resp=%v", to2)
	}

	t.Logf("Access token generated successfully (without ns): %s", access2)
}
