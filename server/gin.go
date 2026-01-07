package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
	"github.com/go-oauth2/oauth2/v4/store"
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

	// Introspect & Revoke (no scope required - standard OAuth 2.0 client auth only)
	r.POST("/oauth/introspect", ginFrom(s.HandleIntrospectionRequest))
	r.POST("/oauth/revoke", ginFrom(s.HandleRevocationRequest))

	// OIDC endpoints
	if s.Config != nil && s.Config.OIDCEnabled {
		r.GET("/.well-known/openid-configuration", ginFrom(s.HandleOIDCDiscovery))
		r.GET("/.well-known/jwks.json", ginFrom(s.HandleOIDCJWKS))
		r.GET("/oauth/userinfo", s.RequireAnyScope(ScopeProfile), ginFrom(s.HandleOIDCUserInfo))
		// POST userinfo is also valid per spec
		r.POST("/oauth/userinfo", s.RequireAnyScope(ScopeProfile), ginFrom(s.HandleOIDCUserInfo))
	}

	// Swagger endpoints (Gin-native)
	r.GET("/swagger.json", s.HandleSwaggerJSONGin)
	r.GET("/swagger", s.HandleSwaggerUIGin)

	// JSON API routes (Gin-native)
	r.POST("/iam/v1/public/login", s.HandleAPILoginGin)
	r.POST("/iam/v1/public/users", s.HandleAPIRegisterUserGin)

	// Namespace & Account management APIs (Scope + Permission)
	r.GET("/iam/v1/admin/namespaces", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.READ), s.handleListNamespaces)
	r.POST("/iam/v1/admin/namespaces", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.CREATE), s.handleCreateNamespace)
	r.POST("/iam/v1/accounts/head", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.CREATE), s.handleCreateHeadAccount)
	r.POST("/iam/v1/accounts/headless", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.CREATE), s.handleCreateHeadlessAccount)
	r.POST("/iam/v1/accounts/:id/link", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.handleLinkAccount)
	r.POST("/iam/v1/accounts/:id/unlink", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.handleUnlinkAccount)

	// Admin: client upsert and permissions (Scope + Permission)
	r.POST("/iam/v1/admin/namespaces/:ns/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.CREATE), s.HandleUpsertClientByNamespaceGin)
	r.PUT("/iam/v1/admin/namespaces/:ns/clients/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.UPDATE), s.HandleUpdateClientPermissionsByNamespaceGin)
	r.PUT("/iam/v1/admin/namespaces/:ns/clients/:id/scopes", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.UPDATE), s.HandleUpdateClientScopesByNamespaceGin)
	// Global client scopes endpoint (admin only)
	r.PUT("/iam/v1/admin/clients/:id/scopes", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.UPDATE), s.HandleUpdateClientScopesGin)
	// Admin: client read/list/delete
	r.GET("/iam/v1/admin/clients/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.READ), s.HandleGetClientGin)
	r.GET("/iam/v1/admin/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.READ), s.HandleListClientsGin)
	// list clients by namespace
	r.GET("/iam/v1/admin/namespaces/:ns/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.READ), s.HandleListClientsByNamespaceGin)
	r.DELETE("/iam/v1/admin/clients/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.DELETE), s.HandleDeleteClientGin)

	// Admin: add permissions to an account (Gin-native)
	// r.POST("/iam/v1/admin/accounts/:accountId/permissions", s.HandleAPIAddAccountPermissionsGin)
	// Admin: ban/unban user in namespace (Scope + Permission)
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/ban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.UPDATE), s.HandleBanUserGin)
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/unban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.UPDATE), s.HandleUnbanUserGin)
	// Admin: list bans
	r.GET("/iam/v1/admin/namespaces/:ns/users/:id/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleListUserBansGin)
	r.GET("/iam/v1/admin/namespaces/:ns/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleListNamespaceBansGin)
	// Admin: account-level ban/unban
	r.POST("/iam/v1/admin/accounts/:id/ban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.UPDATE), s.HandleBanAccountGin)
	r.POST("/iam/v1/admin/accounts/:id/unban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.UPDATE), s.HandleUnbanAccountGin)
	r.GET("/iam/v1/admin/accounts/:id/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.READ), s.HandleListAccountBansGin)

	// Roles management (Scope + Permission)
	r.POST("/iam/v1/admin/namespaces/:ns/roles", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.CREATE), s.HandleUpsertRoleGin)
	r.GET("/iam/v1/admin/namespaces/:ns/roles", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.READ), s.HandleListRolesGin)
	r.DELETE("/iam/v1/admin/namespaces/:ns/roles/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.DELETE), s.HandleDeleteRoleGin)
	// Assignments
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/users/:userId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToUserGin)
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/clients/:clientId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToClientGin)
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/assign-all-users", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToAllUsersGin)

	// Platform token management (admin)
	r.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER:{userId}", permission.READ), s.HandleGetPlatformTokenGin)
	r.GET("/iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER:{userId}", permission.READ), s.HandleListPlatformAccountsGin)

	// Platform OAuth authorization flow (public - no auth required)
	r.GET("/iam/v1/oauth/platforms/:platformId/authorize", s.HandlePlatformAuthorizeGin)
	r.GET("/iam/v1/platforms/:platformId/authenticate", s.HandlePlatformAuthenticateGin)

	// Platform token endpoint (public - client auth via Basic Auth)
	r.POST("/iam/v1/oauth/platforms/:platformId/token", s.HandlePlatformTokenGin)

	// Register admin console routes (embedded React SPA or dev proxy)
	RegisterAdminRoutes(r)

	return r
}

// getDBClientStore returns a database-backed client store
func (s *Server) getDBClientStore() *store.DBClientStore {
	db, _ := s.GetPrimaryDB()
	return store.NewDBClientStore(db)
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

// HandleUpdateClientScopesByNamespaceGin updates an OAuth client's allowed scopes within a namespace.
// Request:
//   - Path params: :ns, :id
//   - JSON body: { "scopes": ["read","write"] } or { "scope": "read write" }
//
// Response: 200 OK with normalized scopes, or 4xx on validation errors.
func (s *Server) HandleUpdateClientScopesByNamespaceGin(c *gin.Context) {
	namespace := c.Param("ns")
	clientID := c.Param("id")
	if namespace == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing namespace or client_id"})
		return
	}

	var body struct {
		Scopes []string `json:"scopes"`
		Scope  string   `json:"scope"` // space-delimited fallback per RFC 6749
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON body"})
		return
	}

	// Merge scopes from array or space-delimited string.
	var scopes []string
	if len(body.Scopes) > 0 {
		scopes = append(scopes, body.Scopes...)
	}
	if body.Scope != "" {
		scopes = append(scopes, strings.Fields(body.Scope)...)
	}
	if len(scopes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "no scopes provided"})
		return
	}

	// Validate each scope token (space-delimited, no spaces within a token).
	// RFC 6749 leaves the syntax to the AS; commonly a safe charset is [A-Za-z0-9:._-].
	scopeRe := regexp.MustCompile(`^[A-Za-z0-9:._-]+$`)
	uniq := make(map[string]struct{}, len(scopes))
	norm := make([]string, 0, len(scopes))
	for _, sTok := range scopes {
		sTok = strings.TrimSpace(sTok)
		if sTok == "" || strings.ContainsAny(sTok, " \t\r\n") || !scopeRe.MatchString(sTok) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "invalid scope token: " + sTok})
			return
		}
		if _, ok := uniq[sTok]; ok {
			continue
		}
		uniq[sTok] = struct{}{}
		norm = append(norm, sTok)
	}

	// Check if client exists in namespace
	cliStore := s.getDBClientStore()
	client, err := cliStore.GetByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_client", "error_description": "client not found"})
		return
	}

	// Validate client belongs to the specified namespace
	if clientInfo, ok := client.(interface{ GetNamespace() string }); ok {
		if clientNamespace := clientInfo.GetNamespace(); clientNamespace != namespace {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_client", "error_description": "client does not belong to specified namespace"})
			return
		}
	}

	// Update client scopes using the DB client store
	if err := cliStore.UpdateScopes(c.Request.Context(), clientID, norm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to update scopes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"namespace": namespace,
		"client_id": clientID,
		"scopes":    norm,
		"message":   "scopes updated successfully",
	})
}
