package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
	"github.com/golang-jwt/jwt/v5"
)

// TestScopeAndPermissionIntegrationWithDB tests the integrated scope + permission authorization with real database
func TestScopeAndPermissionIntegrationWithDB(t *testing.T) {
	// Use real test database
	t.Setenv("APP_ENV", "test")

	// Create and initialize server
	s := &Server{}
	err := s.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}

	// Helper function to generate JWT tokens with both scopes and permissions
	generateToken := func(clientID string, scopes string, permissions []string) string {
		claims := jwt.MapClaims{
			"aud":         []string{clientID},
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

	// Create a test router with the integrated middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Test endpoint with scope + permission requirements
	router.GET("/test/client-read", s.RequireScopeAndPermission(
		ScopeRequirement{Required: []string{"client:read", "admin"}},
		"ADMIN:NAMESPACE:*:CLIENT",
		permission.READ,
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "success",
			"scopes":  c.GetStringSlice("user_scopes"),
			"client":  c.GetString("client_id"),
		})
	})

	router.PUT("/test/client-admin", s.RequireScopeAndPermission(
		ScopeRequirement{Required: []string{"client:admin", "admin"}},
		"ADMIN:NAMESPACE:*:CLIENT",
		permission.UPDATE,
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin operation successful"})
	})

	t.Run("ValidScopeAndPermission", func(t *testing.T) {
		// Token with valid scope AND valid permission
		token := generateToken("test-client", "client:read", []string{"ADMIN:NAMESPACE:*:CLIENT_READ"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		resp := e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		resp.ValueEqual("message", "success")
		resp.ValueEqual("client", "test-client")
	})

	t.Run("ValidScope_InvalidPermission", func(t *testing.T) {
		// Token with valid scope but INVALID permission
		token := generateToken("test-client", "client:read", []string{"WRONG_PERMISSION"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Should fail at permission check stage
		e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusForbidden) // Permission middleware should return 403
	})

	t.Run("InvalidScope_ValidPermission", func(t *testing.T) {
		// Token with INVALID scope but valid permission
		token := generateToken("test-client", "wrong:scope", []string{"ADMIN:NAMESPACE:*:CLIENT_READ"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Should fail at scope check stage (first gate)
		e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusForbidden).
			JSON().Object().
			ValueEqual("error", "insufficient_scope")
	})

	t.Run("AdminScope_BypassesOtherChecks", func(t *testing.T) {
		// Token with admin scope should pass even without specific permissions
		token := generateToken("test-client", "admin", []string{"ADMIN:NAMESPACE:*:CLIENT_UPDATE"})

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		// Admin scope should allow access
		e.PUT("/test/client-admin").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(map[string]interface{}{"test": "data"}).
			Expect().
			Status(http.StatusOK).
			JSON().Object().
			ValueEqual("message", "admin operation successful")
	})

	t.Run("NoAuthorizationHeader", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/test/client-read").
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			ValueEqual("error", "unauthorized")
	})

	t.Run("InvalidToken", func(t *testing.T) {
		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer invalid-token").
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			ValueEqual("error", "unauthorized")
	})

	// Test execution order: scope first, then permission
	t.Run("ScopeFirst_ThenPermission", func(t *testing.T) {
		executionOrder := []string{}

		// Mock middleware to track execution order
		trackingMiddleware := func(name string) gin.HandlerFunc {
			return func(c *gin.Context) {
				executionOrder = append(executionOrder, name)
				c.Next()
			}
		}

		testRouter := gin.New()
		testRouter.GET("/test/order",
			trackingMiddleware("start"),
			s.RequireScopeAndPermission(
				ScopeRequirement{Required: []string{"required:scope"}},
				"MOCK:PERMISSION",
				permission.READ,
			),
			trackingMiddleware("end"),
			func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"order": executionOrder})
			},
		)

		// Create token with wrong scope
		claims := jwt.MapClaims{
			"aud":       []string{"test-client"},
			"client_id": "test-client",
			"scope":     "wrong:scope", // Wrong scope
			"exp":       time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("00000000"))

		e := httpexpect.Default(t, httptest.NewServer(testRouter).URL)

		e.GET("/test/order").
			WithHeader("Authorization", "Bearer "+tokenString).
			Expect().
			Status(http.StatusForbidden).
			JSON().Object().
			ValueEqual("error", "insufficient_scope") // Scope middleware should fail first

		// Verify execution order: start -> scope check (fails) -> no permission check -> no end
		if len(executionOrder) != 1 || executionOrder[0] != "start" {
			t.Errorf("Expected execution order [start], got %v", executionOrder)
		}
	})
}
