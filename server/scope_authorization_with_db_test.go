package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// TestScopeAuthorizationWithDB tests scope + permission authorization with real database
func TestScopeAuthorizationWithDB(t *testing.T) {
	// Use real test database
	t.Setenv("APP_ENV", "test")

	// Create server
	s := &Server{}
	err := s.Initialize()
	if err != nil {
		t.Skipf("Skipping test - database not available: %v", err)
	}

	// Get database connection
	db, err := s.GetPrimaryDB()
	if err != nil {
		t.Fatalf("Failed to get database: %v", err)
	}

	// Create test clients in database
	dbStore := store.NewDBClientStore(db)
	ctx := context.Background()

	// Client with admin scopes
	adminClient := &models.Client{
		ID:        "admin-client",
		Secret:    "admin-secret",
		Scopes:    []string{"admin", "client:read", "client:admin"},
		Namespace: "TESTNS",
		Public:    false,
	}
	err = dbStore.Upsert(ctx, adminClient)
	if err != nil {
		t.Fatalf("Failed to create admin client: %v", err)
	}

	// Client with limited scopes
	limitedClient := &models.Client{
		ID:        "limited-client",
		Secret:    "limited-secret",
		Scopes:    []string{"client:read"},
		Namespace: "TESTNS",
		Public:    false,
	}
	err = dbStore.Upsert(ctx, limitedClient)
	if err != nil {
		t.Fatalf("Failed to create limited client: %v", err)
	}

	// Create test user and assign permissions (simplified for testing)
	// Note: In a real test, you would create accounts and users through proper APIs
	testUserID := "test-user-1"

	// Create router
	router := NewGinEngine(s)

	// Helper to generate JWT with both scopes and permissions
	generateJWT := func(clientID, scopes string, permissions []string, userID string) string {
		claims := jwt.MapClaims{
			"aud":         []string{clientID},
			"sub":         userID,
			"client_id":   clientID,
			"scope":       scopes,
			"permissions": permissions,
			"accountId":   "test-account-123",
			"namespace":   "TESTNS",
			"exp":         time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("00000000"))
		return tokenString
	}

	t.Run("AdminScope_Success", func(t *testing.T) {
		// Token with admin scope - should bypass other checks
		// Permission uses wildcard to match route requirement
		token := generateJWT("admin-client", "admin", []string{"ADMIN:NAMESPACE:*:CLIENT_READ"}, testUserID)

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Should succeed because admin scope allows everything
		e.GET("/iam/v1/admin/clients/admin-client").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK)
	})

	t.Run("ValidScopeAndPermission_Success", func(t *testing.T) {
		// Token with correct scope AND permission
		// Permission uses wildcard to match route requirement
		token := generateJWT("admin-client", "client:read", []string{"ADMIN:NAMESPACE:*:CLIENT_READ"}, testUserID)

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/iam/v1/admin/clients/admin-client").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK)
	})

	t.Run("InsufficientScope_Failure", func(t *testing.T) {
		// Token with insufficient scope (client:read for admin operation)
		token := generateJWT("limited-client", "client:read", []string{"ADMIN:NAMESPACE:TESTNS:CLIENT_UPDATE"}, testUserID)

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Should fail at scope check (first gate)
		e.PUT("/iam/v1/admin/clients/limited-client/scopes").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(map[string]interface{}{"scopes": []string{"read", "write"}}).
			Expect().
			Status(http.StatusForbidden).
			JSON().Object().
			ValueEqual("error", "insufficient_scope")
	})

	t.Run("ValidScope_InvalidPermission_Failure", func(t *testing.T) {
		// Token with valid scope but invalid permission
		token := generateJWT("admin-client", "client:admin", []string{"WRONG:PERMISSION_READ"}, testUserID)

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Should pass scope check but fail permission check
		e.PUT("/iam/v1/admin/clients/admin-client/scopes").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(map[string]interface{}{"scopes": []string{"read", "write"}}).
			Expect().
			Status(http.StatusForbidden) // Fail at permission stage
	})

	t.Run("NoAuthHeader_Failure", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/iam/v1/admin/clients/admin-client").
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			ValueEqual("error", "unauthorized")
	})

	t.Run("InvalidToken_Failure", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/iam/v1/admin/clients/admin-client").
			WithHeader("Authorization", "Bearer invalid-token").
			Expect().
			Status(http.StatusUnauthorized)
	})

	// Cleanup
	t.Cleanup(func() {
		dbStore.Delete(ctx, "admin-client")
		dbStore.Delete(ctx, "limited-client")
	})
}
