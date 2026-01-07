package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// TestScopeAuthorization tests that endpoints properly check OAuth 2.0 scopes
func TestScopeAuthorization(t *testing.T) {
	// Clear database configuration to ensure test works without DB
	t.Setenv("CONFIG_DIR", "/tmp/nonexistent")
	t.Setenv("IAM_DATABASE__IAM__READ__DSN", "")
	t.Setenv("IAM_DATABASE__IAM__WRITE__DSN", "")

	// Create JWT access generator
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS256))

	// Setup client store with scopes
	cliStore := store.NewClientStore()

	// Client with specific scopes
	clientWithScopes := &models.Client{
		ID:     "scoped-client",
		Secret: "secret",
		Scopes: []string{"client:read", "client:write", "admin"},
	}
	_ = cliStore.Set("scoped-client", clientWithScopes)

	// Client without admin scope
	limitedClient := &models.Client{
		ID:     "limited-client",
		Secret: "secret",
		Scopes: []string{"client:read"},
	}
	_ = cliStore.Set("limited-client", limitedClient)

	m.MapClientStorage(cliStore)

	// Create server config
	cfg := &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.ClientCredentials,
		},
	}

	// Create server manually to bypass DB initialization
	s := &Server{
		Config:  cfg,
		Manager: m,
	}
	s.SetClientInfoHandler(ClientFormHandler)
	s.SetAllowedGrantType(oauth2.ClientCredentials)

	// Create Gin engine with routes
	router := NewGinEngine(s)

	// Helper function to generate access token with specific scopes and permissions
	generateToken := func(clientID string, scopes string, permissions []string) string {
		// Create JWT claims with both scopes and permissions
		claims := jwt.MapClaims{
			"aud":         []string{clientID},
			"client_id":   clientID,
			"scope":       scopes,
			"permissions": permissions,
			"exp":         time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("00000000"))
		return tokenString
	}

	t.Run("ValidScope_ClientRead", func(t *testing.T) {
		// Generate token with client:read scope and required permissions
		token := generateToken("scoped-client", "client:read", []string{"ADMIN:NAMESPACE:*:CLIENT_READ"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Test endpoint that requires client:read scope
		// Scope middleware should pass. The final status depends on DB availability:
		// - 503: DB not available (scope passed)
		// - 200: DB available and client exists (scope passed)
		// - 404: DB available but client not found (scope passed)
		// Any of these prove scope authorization succeeded (401/403 would mean scope check failed)
		resp := e.GET("/iam/v1/admin/clients/scoped-client").
			WithHeader("Authorization", "Bearer "+token).
			Expect()
		status := resp.Raw().StatusCode
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			t.Errorf("Expected scope check to pass, but got %d", status)
		}
	})

	t.Run("InvalidScope_InsufficientScope", func(t *testing.T) {
		// Generate token with only client:read scope but the endpoint needs client:admin
		token := generateToken("limited-client", "client:read", []string{"ADMIN:NAMESPACE:*:CLIENT_UPDATE"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Test endpoint that requires client:admin scope (for scopes update)
		e.PUT("/iam/v1/admin/clients/limited-client/scopes").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(map[string]interface{}{"scopes": []string{"read", "write"}}).
			Expect().
			Status(http.StatusForbidden). // Should fail with 403
			JSON().Object().
			ValueEqual("error", "insufficient_scope")
	})

	t.Run("ValidScope_AdminScope", func(t *testing.T) {
		// Generate token with admin scope (admin scope allows access to all endpoints)
		token := generateToken("scoped-client", "admin", []string{"ADMIN:NAMESPACE:*:CLIENT_UPDATE"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Test endpoint that requires client:admin scope
		// Scope middleware should pass. The final status depends on DB availability:
		// - 503: DB not available (scope passed)
		// - 200: DB available and update succeeded (scope passed)
		// - 500: DB error (scope passed)
		// Any of these prove scope authorization succeeded (401/403 would mean scope check failed)
		resp := e.PUT("/iam/v1/admin/clients/scoped-client/scopes").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(map[string]interface{}{"scopes": []string{"read", "write"}}).
			Expect()
		status := resp.Raw().StatusCode
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			t.Errorf("Expected scope check to pass, but got %d", status)
		}
	})

	t.Run("NoAuthorizationHeader", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Test endpoint without Authorization header
		e.GET("/iam/v1/admin/clients/scoped-client").
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			ValueEqual("error", "unauthorized")
	})

	t.Run("InvalidToken", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Test endpoint with invalid token
		e.GET("/iam/v1/admin/clients/scoped-client").
			WithHeader("Authorization", "Bearer invalid-token").
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			ValueEqual("error", "unauthorized")
	})
}

// TestScopeMiddlewareLogic tests the scope validation logic
func TestScopeMiddlewareLogic(t *testing.T) {
	tests := []struct {
		name        string
		userScopes  []string
		requirement ScopeRequirement
		shouldPass  bool
	}{
		{
			name:        "HasRequiredScope_OR",
			userScopes:  []string{"read", "write"},
			requirement: ScopeRequirement{Required: []string{"read", "admin"}},
			shouldPass:  true, // User has "read" which is one of the required
		},
		{
			name:        "MissingRequiredScope_OR",
			userScopes:  []string{"profile"},
			requirement: ScopeRequirement{Required: []string{"read", "admin"}},
			shouldPass:  false, // User doesn't have any required scope
		},
		{
			name:        "HasAllRequiredScopes_AND",
			userScopes:  []string{"read", "write", "admin"},
			requirement: ScopeRequirement{All: []string{"read", "write"}},
			shouldPass:  true, // User has both required scopes
		},
		{
			name:        "MissingOneRequiredScope_AND",
			userScopes:  []string{"read"},
			requirement: ScopeRequirement{All: []string{"read", "write"}},
			shouldPass:  false, // User missing "write" scope
		},
		{
			name:        "ComplexRequirement",
			userScopes:  []string{"read", "admin"},
			requirement: ScopeRequirement{Required: []string{"read", "write"}, All: []string{"admin"}},
			shouldPass:  true, // User has "read" (OR) and "admin" (AND)
		},
		{
			name:        "EmptyRequirement",
			userScopes:  []string{"read"},
			requirement: ScopeRequirement{},
			shouldPass:  true, // No requirements = allow access
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRequiredScopes(tt.userScopes, tt.requirement)
			if result != tt.shouldPass {
				t.Errorf("hasRequiredScopes() = %v, want %v", result, tt.shouldPass)
			}
		})
	}
}
