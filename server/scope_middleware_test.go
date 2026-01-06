package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// TestScopeMiddlewareOnly tests only the scope middleware without permissions
func TestScopeMiddlewareOnly(t *testing.T) {
	// Clear database configuration
	t.Setenv("CONFIG_DIR", "/tmp/nonexistent")
	t.Setenv("IAM_DATABASE__IAM__READ__DSN", "")
	t.Setenv("IAM_DATABASE__IAM__WRITE__DSN", "")

	// Create server
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("test-key"), jwt.SigningMethodHS256))

	cfg := &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes:    []oauth2.GrantType{oauth2.ClientCredentials},
	}

	s := &Server{
		Config:  cfg,
		Manager: m,
	}

	// Helper function to generate access token with specific scopes
	generateToken := func(clientID string, scopes string) string {
		ti := &models.Token{
			ClientID:        clientID,
			Scope:           scopes,
			AccessCreateAt:  time.Now(),
			AccessExpiresIn: time.Hour,
		}

		data := &oauth2.GenerateBasic{
			Client:    &models.Client{ID: clientID},
			UserID:    "",
			TokenInfo: ti,
		}

		gen := generates.NewJWTAccessGenerate("", []byte("test-key"), jwt.SigningMethodHS256)
		accessToken, _, _ := gen.Token(context.Background(), data, false)
		return accessToken
	}

	// Create a simple router with only scope middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Test endpoint that requires client:read scope
	router.GET("/test/client-read", s.RequireAnyScope("client:read", "admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success", "scopes": c.GetStringSlice("user_scopes")})
	})

	// Test endpoint that requires admin scope
	router.PUT("/test/admin-only", s.RequireAnyScope("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
	})

	// Test endpoint that requires multiple specific scopes (AND logic)
	router.POST("/test/multi-scope", s.RequireAllScopes("read", "write"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "multi-scope access granted"})
	})

	t.Run("ValidScope_ClientRead", func(t *testing.T) {
		// Generate token with client:read scope
		token := generateToken("test-client", "client:read")

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		resp := e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		resp.ValueEqual("message", "success")
		scopes := resp.Value("scopes").Array()
		scopes.Element(0).Equal("client:read")
	})

	t.Run("ValidScope_AdminAccess", func(t *testing.T) {
		// Generate token with admin scope
		token := generateToken("test-client", "admin")

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK).
			JSON().Object().
			ValueEqual("message", "success")
	})

	t.Run("InsufficientScope", func(t *testing.T) {
		// Generate token with wrong scope
		token := generateToken("test-client", "write")

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.GET("/test/client-read").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusForbidden).
			JSON().Object().
			ValueEqual("error", "insufficient_scope")
	})

	t.Run("NoAuthHeader", func(t *testing.T) {
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

	t.Run("MultipleScopes_AND_Success", func(t *testing.T) {
		// Generate token with both read and write scopes
		token := generateToken("test-client", "read write")

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.POST("/test/multi-scope").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusOK).
			JSON().Object().
			ValueEqual("message", "multi-scope access granted")
	})

	t.Run("MultipleScopes_AND_Failure", func(t *testing.T) {
		// Generate token with only read scope (missing write)
		token := generateToken("test-client", "read")

		e := httpexpect.Default(t, httptest.NewServer(router).URL)

		e.POST("/test/multi-scope").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusForbidden).
			JSON().Object().
			ValueEqual("error", "insufficient_scope")
	})
}
