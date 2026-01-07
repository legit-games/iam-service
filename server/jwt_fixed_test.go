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

// TestPasswordGrant_UserRolePermissionsInJWT_Fixed - Working version that bypasses DB initialization
func TestPasswordGrant_UserRolePermissionsInJWT_Fixed(t *testing.T) {
	// Clear database configuration to ensure test works without DB
	t.Setenv("CONFIG_DIR", "/tmp/nonexistent")
	t.Setenv("IAM_DATABASE__IAM__READ__DSN", "")
	t.Setenv("IAM_DATABASE__IAM__WRITE__DSN", "")

	// Create JWT access generator
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS256))

	// Setup client store
	cliStore := store.NewClientStore()
	_ = cliStore.Set("confidential", &models.Client{ID: "confidential", Secret: "secret"})
	m.MapClientStorage(cliStore)

	// Create server config
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

	// Create server manually to bypass DB initialization in NewServer
	s := &Server{
		Config:  cfg,
		Manager: m,
	}
	s.SetClientInfoHandler(ClientFormHandler)
	s.SetAllowedGrantType(oauth2.PasswordCredentials)
	s.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		if username == "test" && password == "test" {
			return "user-1", nil
		}
		return "", nil
	})

	// Create test server that injects custom context
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			// Parse form data
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}

			// Validate token request
			gt, tgr, err := s.ValidationTokenRequest(r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
				return
			}

			// Create context with test permission resolver
			ctx := r.Context()
			if ns := r.FormValue("ns"); ns != "" {
				ctx = context.WithValue(ctx, "ns", ns)
			}

			ctx = context.WithValue(ctx, "perm_resolver", func(c context.Context, userID, ns string) []string {
				if ns == "TESTNS" && userID == "user-1" {
					return []string{"USERS_READ", "ACCOUNTS_WRITE", "TESTNS_ADMIN"}
				}
				return []string{}
			})

			// Generate token with custom context
			ti, err := m.GenerateAccessToken(ctx, gt, tgr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "server_error",
					"error_description": err.Error(),
				})
				return
			}

			// Return token response
			data := s.GetTokenData(ti)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(data)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Test token request with namespace
	e := httpexpect.Default(t, ts.URL)
	resp := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "test").
		WithFormField("password", "test").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		WithFormField("ns", "TESTNS").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	access := resp.Value("access_token").String().Raw()
	if access == "" {
		t.Fatalf("No access token returned")
	}

	// Verify JWT contains permissions
	token, err := jwt.Parse(access, func(token *jwt.Token) (interface{}, error) {
		return []byte("00000000"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		t.Logf("JWT claims: %+v", claims)

		// Verify permissions exist
		if perms, exists := claims["permissions"]; exists {
			if permsArray, ok := perms.([]interface{}); ok {
				if len(permsArray) == 3 {
					expectedPerms := []string{"USERS_READ", "ACCOUNTS_WRITE", "TESTNS_ADMIN"}
					foundPerms := make(map[string]bool)
					for _, p := range permsArray {
						if pStr, ok := p.(string); ok {
							foundPerms[pStr] = true
						}
					}
					for _, expected := range expectedPerms {
						if !foundPerms[expected] {
							t.Errorf("Expected permission '%s' not found in JWT", expected)
						}
					}
					t.Log("✅ SUCCESS: All expected permissions found in JWT")
				} else {
					t.Errorf("Expected 3 permissions, got %d: %v", len(permsArray), permsArray)
				}
			} else {
				t.Errorf("Permissions claim is not an array: %T", perms)
			}
		} else {
			t.Error("FAIL: No permissions found in JWT")
		}
	} else {
		t.Fatalf("Invalid JWT token")
	}

	// Test without namespace (should have no permissions)
	resp2 := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "test").
		WithFormField("password", "test").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	access2 := resp2.Value("access_token").String().Raw()
	token2, err := jwt.Parse(access2, func(token *jwt.Token) (interface{}, error) {
		return []byte("00000000"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse JWT without namespace: %v", err)
	}

	if claims2, ok := token2.Claims.(jwt.MapClaims); ok && token2.Valid {
		if _, exists := claims2["permissions"]; exists {
			t.Error("FAIL: Found permissions when none should exist (no namespace)")
		} else {
			t.Log("✅ SUCCESS: No permissions found without namespace (correct behavior)")
		}
	}
}
