package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	perm "github.com/go-oauth2/oauth2/v4/permission"
	"github.com/go-session/session/v3"
)

// NewGinEngine builds a Gin router and registers all default OAuth2 routes.
// This is additive and does not affect the existing net/http mux-based wiring.
func NewGinEngine(s *Server) *gin.Engine {
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.Use(gin.Recovery())
	r.Use(parseFormMiddleware())

	// /oauth/authorize with session form restore middleware (disable implicit response_type=token)
	r.GET("/oauth/authorize", blockImplicitMiddleware(), restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))
	r.POST("/oauth/authorize", blockImplicitMiddleware(), restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))

	// Token endpoint(s) (keep standard handler)
	r.POST("/oauth/token", ginFrom(s.HandleTokenRequest))
	if s.Config != nil && s.Config.AllowGetAccessRequest {
		r.GET("/oauth/token", ginFrom(s.HandleTokenRequest))
	}

	// Introspect & Revoke (keep standard handler)
	r.POST("/oauth/introspect", ginFrom(s.HandleIntrospectionRequest))
	r.POST("/oauth/revoke", ginFrom(s.HandleRevocationRequest))

	// OIDC endpoints
	if s.Config != nil && s.Config.OIDCEnabled {
		r.GET("/.well-known/openid-configuration", ginFrom(s.HandleOIDCDiscovery))
		r.GET("/.well-known/jwks.json", ginFrom(s.HandleOIDCJWKS))
		r.GET("/oauth/userinfo", ginFrom(s.HandleOIDCUserInfo))
		// POST userinfo is also valid per spec
		r.POST("/oauth/userinfo", ginFrom(s.HandleOIDCUserInfo))
	}

	// Swagger endpoints (Gin-native)
	r.GET("/swagger.json", s.HandleSwaggerJSONGin)
	r.GET("/swagger", s.HandleSwaggerUIGin)

	// JSON API routes (Gin-native)
	r.POST("/iam/v1/public/login", s.HandleAPILoginGin)
	r.POST("/iam/v1/public/users", s.HandleAPIRegisterUserGin)

	// Namespace & Account management APIs (Gin-native)
	r.POST("/iam/v1/admin/namespaces", RequireAuthorization("ADMIN:NAMESPACE:*", perm.CREATE, nil), s.handleCreateNamespace)
	r.POST("/iam/v1/accounts/head", RequireAuthorization("ADMIN:NAMESPACE:*:USER", perm.CREATE, nil), s.handleCreateHeadAccount)
	r.POST("/iam/v1/accounts/headless", RequireAuthorization("ADMIN:NAMESPACE:*:USER", perm.CREATE, nil), s.handleCreateHeadlessAccount)
	r.POST("/iam/v1/accounts/:id/link", RequireAuthorization("ADMIN:NAMESPACE:*:USER", perm.UPDATE, nil), s.handleLinkAccount)
	r.POST("/iam/v1/accounts/:id/unlink", RequireAuthorization("ADMIN:NAMESPACE:*:USER", perm.UPDATE, nil), s.handleUnlinkAccount)

	// Admin: client upsert and permissions (namespace required)
	r.POST("/iam/v1/admin/namespaces/:ns/clients", RequireAuthorization("ADMIN:NAMESPACE:{ns}:CLIENT", perm.CREATE, nil), s.HandleUpsertClientByNamespaceGin)
	r.PUT("/iam/v1/admin/namespaces/:ns/clients/:id/permissions", RequireAuthorization("ADMIN:NAMESPACE:{ns}:CLIENT", perm.UPDATE, nil), s.HandleUpdateClientPermissionsByNamespaceGin)
	// Admin: client read/list/delete
	r.GET("/iam/v1/admin/clients/:id", RequireAuthorization("ADMIN:NAMESPACE:*:CLIENT", perm.READ, nil), s.HandleGetClientGin)
	r.GET("/iam/v1/admin/clients", RequireAuthorization("ADMIN:NAMESPACE:*:CLIENT", perm.READ, nil), s.HandleListClientsGin)
	// list clients by namespace
	r.GET("/iam/v1/admin/namespaces/:ns/clients", RequireAuthorization("ADMIN:NAMESPACE:{ns}:CLIENT", perm.READ, nil), s.HandleListClientsByNamespaceGin)
	r.DELETE("/iam/v1/admin/clients/:id", RequireAuthorization("ADMIN:NAMESPACE:*:CLIENT", perm.DELETE, nil), s.HandleDeleteClientGin)

	// Admin: add permissions to an account (Gin-native)
	// r.POST("/iam/v1/admin/accounts/:accountId/permissions", s.HandleAPIAddAccountPermissionsGin)
	// Admin: ban/unban user in namespace
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/ban", RequireAuthorization("ADMIN:NAMESPACE:{ns}:USER", perm.UPDATE, nil), s.HandleBanUserGin)
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/unban", RequireAuthorization("ADMIN:NAMESPACE:{ns}:USER", perm.UPDATE, nil), s.HandleUnbanUserGin)
	// Admin: list bans
	r.GET("/iam/v1/admin/namespaces/:ns/users/:id/bans", RequireAuthorization("ADMIN:NAMESPACE:{ns}:USER", perm.READ, nil), s.HandleListUserBansGin)
	r.GET("/iam/v1/admin/namespaces/:ns/bans", RequireAuthorization("ADMIN:NAMESPACE:{ns}:USER", perm.READ, nil), s.HandleListNamespaceBansGin)
	// Admin: account-level ban/unban
	r.POST("/iam/v1/admin/accounts/:id/ban", RequireAuthorization("ADMIN:NAMESPACE:*:ACCOUNT", perm.UPDATE, nil), s.HandleBanAccountGin)
	r.POST("/iam/v1/admin/accounts/:id/unban", RequireAuthorization("ADMIN:NAMESPACE:*:ACCOUNT", perm.UPDATE, nil), s.HandleUnbanAccountGin)
	r.GET("/iam/v1/admin/accounts/:id/bans", RequireAuthorization("ADMIN:NAMESPACE:*:ACCOUNT", perm.READ, nil), s.HandleListAccountBansGin)

	return r
}

// ginFrom adapts existing handlers (http.ResponseWriter, *http.Request) to a Gin handler.
func ginFrom(h func(http.ResponseWriter, *http.Request) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		_ = h(c.Writer, c.Request)
		c.Abort()
	}
}

// parseFormMiddleware ensures r.ParseForm() is called for urlencoded/multipart requests so r.FormValue works.
func parseFormMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		ct := r.Header.Get("Content-Type")
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if ct != "" {
				// Check common form content types
				if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
					_ = r.ParseForm()
				}
			}
		}
		c.Next()
	}
}

// restoreAuthorizeFormMiddleware restores saved authorize request form from session after login redirects.
func restoreAuthorizeFormMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if store, err := session.Start(c.Request.Context(), c.Writer, c.Request); err == nil {
			if v, ok := store.Get("ReturnUri"); ok {
				// support both url.Values and map[string][]string
				if form, ok2 := v.(map[string][]string); ok2 {
					c.Request.Form = form
				} else if vals, ok2 := v.(url.Values); ok2 {
					c.Request.Form = vals
				}
				store.Delete("ReturnUri")
				_ = store.Save()
			}
		}
		c.Next()
	}
}

// blockImplicitMiddleware rejects OAuth 2.0 Implicit Flow (response_type=token) to comply with OAuth 2.1.
func blockImplicitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rt := c.Query("response_type")
		if strings.EqualFold(rt, "token") {
			c.Header("Content-Type", "application/json;charset=UTF-8")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "unsupported_response_type",
				"error_description": "Implicit flow is disabled. Use Authorization Code with PKCE.",
			})
			return
		}
		c.Next()
	}
}
