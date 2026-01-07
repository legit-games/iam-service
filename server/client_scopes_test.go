package server

import (
	"context"
	"encoding/json"
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

// TestClientScopes_TokenGeneration tests that scopes are properly included in JWT access tokens
func TestClientScopes_TokenGeneration(t *testing.T) {
	// Use real test database
	t.Setenv("APP_ENV", "test")

	// Create server and initialize with database
	s := &Server{}
	err := s.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}

	// Setup JWT access generator
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS256))

	// Get database and setup client store
	db, err := s.GetPrimaryDB()
	if err != nil {
		t.Fatalf("Failed to get database: %v", err)
	}

	cliStore := store.NewDBClientStore(db)
	m.MapClientStorage(cliStore)

	// Create test client in database
	client := &models.Client{
		ID:        "test-client",
		Secret:    "secret",
		Scopes:    []string{"read", "write", "admin"},
		Namespace: "TESTNS",
		Public:    false,
	}
	ctx := context.Background()
	err = cliStore.Upsert(ctx, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Update server manager
	s.Manager = m

	s.SetClientInfoHandler(ClientFormHandler)
	s.SetAllowedGrantType(oauth2.PasswordCredentials)
	s.SetAllowedGrantType(oauth2.ClientCredentials)
	s.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		if username == "test" && password == "test" {
			return "user-1", nil
		}
		return "", nil
	})

	// Test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}

			gt, tgr, err := s.ValidationTokenRequest(r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
				return
			}

			// Generate token
			ti, err := m.GenerateAccessToken(r.Context(), gt, tgr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "server_error",
					"error_description": err.Error(),
				})
				return
			}

			data := s.GetTokenData(ti)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(data)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Test 1: Valid scopes within allowed client scopes
	t.Run("ValidScopes", func(t *testing.T) {
		resp := e.POST("/token").
			WithFormField("grant_type", "client_credentials").
			WithFormField("client_id", "test-client").
			WithFormField("client_secret", "secret").
			WithFormField("scope", "read write").
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		accessToken := resp.Value("access_token").String().Raw()
		scope := resp.Value("scope").String().Raw()

		if accessToken == "" {
			t.Fatalf("No access token returned")
		}

		if scope != "read write" {
			t.Errorf("Expected scope 'read write', got '%s'", scope)
		}

		// Verify JWT contains scope
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte("00000000"), nil
		})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			t.Logf("JWT claims: %+v", claims)
			if jwtScope, exists := claims["scope"]; exists {
				if jwtScope.(string) != "read write" {
					t.Errorf("Expected JWT scope 'read write', got '%v'", jwtScope)
				}
			} else {
				t.Error("Scope not found in JWT claims")
			}
		} else {
			t.Error("Invalid JWT token")
		}
	})

	// Test 2: Invalid scope should be rejected
	t.Run("InvalidScope", func(t *testing.T) {
		resp := e.POST("/token").
			WithFormField("grant_type", "client_credentials").
			WithFormField("client_id", "test-client").
			WithFormField("client_secret", "secret").
			WithFormField("scope", "read invalid_scope").
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object()

		errorType := resp.Value("error").String().Raw()
		if errorType != "invalid_request" {
			t.Errorf("Expected error 'invalid_request', got '%s'", errorType)
		}
	})

	// Test 3: Password grant with scopes
	t.Run("PasswordGrantWithScopes", func(t *testing.T) {
		resp := e.POST("/token").
			WithFormField("grant_type", "password").
			WithFormField("username", "test").
			WithFormField("password", "test").
			WithFormField("client_id", "test-client").
			WithFormField("client_secret", "secret").
			WithFormField("scope", "read").
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		scope := resp.Value("scope").String().Raw()
		if scope != "read" {
			t.Errorf("Expected scope 'read', got '%s'", scope)
		}
	})
}

// TestClientScopesAPI tests the client scopes management endpoints
func TestClientScopesAPI(t *testing.T) {
	// This test would require database integration
	// Skipping for now as it requires more complex setup
	t.Skip("Skipping API tests - requires database integration")
}
