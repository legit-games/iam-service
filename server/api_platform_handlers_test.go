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

func newPlatformTestServer(t *testing.T) (*Server, func(clientID, userID, scopes string) string) {
	t.Helper()

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

	generateToken := func(clientID, userID, scopes string) string {
		ti := &models.Token{
			ClientID:        clientID,
			UserID:          userID,
			Scope:           scopes,
			AccessCreateAt:  time.Now(),
			AccessExpiresIn: time.Hour,
		}

		data := &oauth2.GenerateBasic{
			Client:    &models.Client{ID: clientID},
			UserID:    userID,
			TokenInfo: ti,
		}

		gen := generates.NewJWTAccessGenerate("", []byte("test-key"), jwt.SigningMethodHS256)
		accessToken, _, _ := gen.Token(context.Background(), data, false)
		return accessToken
	}

	return s, generateToken
}

func TestHandleGetPlatformToken_MissingParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, generateToken := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleGetPlatformTokenGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	token := generateToken("test-client", "user123", "platform:read admin")
	e := httpexpect.Default(t, ts.URL)

	t.Run("EmptyNamespace", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/ /users/user123/platforms/steam/platformToken").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ValueEqual("error", "invalid_request")
	})

	t.Run("EmptyUserID", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/ /platforms/steam/platformToken").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ValueEqual("error", "invalid_request")
	})

	t.Run("EmptyPlatformID", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms/ /platformToken").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ValueEqual("error", "invalid_request")
	})
}

func TestHandleGetPlatformToken_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleGetPlatformTokenGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	t.Run("NoAuthHeader", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms/steam/platformToken").
			Expect().
			Status(http.StatusUnauthorized)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms/steam/platformToken").
			WithHeader("Authorization", "Bearer invalid-token").
			Expect().
			Status(http.StatusUnauthorized)
	})
}

func TestHandleGetPlatformToken_InsufficientScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, generateToken := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleGetPlatformTokenGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Token with insufficient scope
	token := generateToken("test-client", "user123", "user:read")
	e := httpexpect.Default(t, ts.URL)

	e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms/steam/platformToken").
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusForbidden)
}

func TestHandleGetPlatformToken_NoDatabaseOrUserNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, generateToken := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleGetPlatformTokenGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	token := generateToken("test-client", "user123", "platform:read admin")
	e := httpexpect.Default(t, ts.URL)

	resp := e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms/steam/platformToken").
		WithHeader("Authorization", "Bearer "+token).
		Expect()

	// When DB is not configured: 501 Not Implemented
	// When DB is configured but user not found: 404 Not Found
	status := resp.Raw().StatusCode
	if status != http.StatusNotImplemented && status != http.StatusNotFound {
		t.Fatalf("expected status 501 or 404, got %d", status)
	}

	respObj := resp.JSON().Object()
	errVal := respObj.Value("error").String().Raw()
	if errVal != "not_implemented" && errVal != "user_not_found" {
		t.Fatalf("expected error 'not_implemented' or 'user_not_found', got %s", errVal)
	}
}

func TestHandleListPlatformAccounts_MissingParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, generateToken := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleListPlatformAccountsGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	token := generateToken("test-client", "user123", "platform:read admin")
	e := httpexpect.Default(t, ts.URL)

	t.Run("EmptyNamespace", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/ /users/user123/platforms").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ValueEqual("error", "invalid_request")
	})

	t.Run("EmptyUserID", func(t *testing.T) {
		e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/ /platforms").
			WithHeader("Authorization", "Bearer "+token).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ValueEqual("error", "invalid_request")
	})
}

func TestHandleListPlatformAccounts_NoDatabaseOrEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, generateToken := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms",
		s.RequireAnyScope(ScopePlatformRead, ScopeAdmin),
		s.HandleListPlatformAccountsGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	token := generateToken("test-client", "user123", "platform:read admin")
	e := httpexpect.Default(t, ts.URL)

	resp := e.GET("/iam/v1/oauth/admin/namespaces/TESTNS/users/user123/platforms").
		WithHeader("Authorization", "Bearer "+token).
		Expect()

	// When DB is not configured: 501 Not Implemented
	// When DB is configured but empty: 200 OK with empty platforms array
	status := resp.Raw().StatusCode
	if status != http.StatusNotImplemented && status != http.StatusOK {
		t.Fatalf("expected status 501 or 200, got %d", status)
	}

	if status == http.StatusNotImplemented {
		resp.JSON().Object().ValueEqual("error", "not_implemented")
	} else {
		// Status 200 - should have platforms key
		resp.JSON().Object().ContainsKey("platforms")
	}
}

func TestHandlePlatformAuthorize_MissingRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/platforms/:platformId/authorize", s.HandlePlatformAuthorizeGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Missing request_id
	e.GET("/iam/v1/oauth/platforms/google/authorize").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ValueEqual("error", "invalid_request").
		ValueEqual("error_description", "request_id parameter is required")
}

func TestHandlePlatformAuthorize_InvalidRequestIDFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/platforms/:platformId/authorize", s.HandlePlatformAuthorizeGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Invalid request_id format (not UUID4 without hyphens)
	e.GET("/iam/v1/oauth/platforms/google/authorize").
		WithQuery("request_id", "invalid-request-id").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ValueEqual("error", "invalid_request").
		ValueEqual("error_description", "invalid request_id format")
}

func TestHandlePlatformAuthorize_InvalidPlatformID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/oauth/platforms/:platformId/authorize", s.HandlePlatformAuthorizeGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Invalid platform_id (contains special characters)
	e.GET("/iam/v1/oauth/platforms/invalid-platform!/authorize").
		WithQuery("request_id", "550e8400e29b41d4a716446655440000").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ValueEqual("error", "invalid_request")
}

func TestHandlePlatformAuthenticate_MissingParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/platforms/:platformId/authenticate", s.HandlePlatformAuthenticateGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Missing code and state
	e.GET("/iam/v1/platforms/google/authenticate").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ValueEqual("error", "invalid_request").
		ValueEqual("error_description", "missing required parameters")
}

func TestHandlePlatformAuthenticate_PlatformError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _ := newPlatformTestServer(t)

	router := gin.New()
	router.GET("/iam/v1/platforms/:platformId/authenticate", s.HandlePlatformAuthenticateGin)

	ts := httptest.NewServer(router)
	defer ts.Close()

	e := httpexpect.Default(t, ts.URL)

	// Platform returns error (e.g., user denied access)
	e.GET("/iam/v1/platforms/google/authenticate").
		WithQuery("error", "access_denied").
		WithQuery("error_description", "user denied access").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ValueEqual("error", "access_denied").
		ValueEqual("error_description", "user denied access")
}
