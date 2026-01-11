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
	r.GET("/iam/v1/public/namespaces/:ns/platforms", s.HandleGetActivePlatformsGin)
	r.GET("/iam/v1/public/platforms", s.HandleGetActivePlatformsByClientGin)
	r.GET("/iam/v1/public/platforms/:platformId/login", s.HandleStartPlatformLoginGin)

	// Admin route group with TokenMiddleware
	// TokenMiddleware validates bearer token and sets user_id, client_id, scopes in context
	adminGroup := r.Group("/iam/v1")
	adminGroup.Use(s.TokenMiddleware())

	// Namespace & Account management APIs (Scope + Permission)
	adminGroup.GET("/admin/namespaces", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.READ), s.handleListNamespaces)
	adminGroup.POST("/admin/namespaces", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.CREATE), s.handleCreateNamespace)
	adminGroup.GET("/admin/namespaces/:ns", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.READ), s.handleGetNamespace)
	adminGroup.PUT("/admin/namespaces/:ns", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeNamespaceWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*", permission.UPDATE), s.handleUpdateNamespace)
	adminGroup.POST("/users/head", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.CREATE), s.handleCreateHeadAccount)
	adminGroup.POST("/users/headless", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.CREATE), s.handleCreateHeadlessAccount)
	adminGroup.POST("/users/:id/link", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.handleLinkAccount)
	adminGroup.POST("/users/:id/unlink", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.handleUnlinkAccount)
	// Link eligibility check and platforms
	adminGroup.GET("/users/:id/link/check", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.READ), s.handleCheckLinkEligibility)
	adminGroup.GET("/users/:id/platforms", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.READ), s.handleGetLinkedPlatforms)
	// One-time link code management
	adminGroup.POST("/users/:id/link-code", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.CREATE), s.handleGenerateLinkCode)
	adminGroup.GET("/link-codes/:code/validate", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.READ), s.handleValidateLinkCode)
	adminGroup.POST("/users/:id/link-with-code", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.handleLinkWithCode)
	// Account merge
	adminGroup.GET("/accounts/:id/merge/check", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.READ), s.HandleCheckMergeEligibilityGin)
	adminGroup.POST("/accounts/:id/merge", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.UPDATE), s.HandleMergeAccountGin)

	// Admin: client upsert and permissions (Scope + Permission)
	adminGroup.POST("/admin/namespaces/:ns/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.CREATE), s.HandleUpsertClientByNamespaceGin)
	adminGroup.PUT("/admin/namespaces/:ns/clients/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.UPDATE), s.HandleUpdateClientPermissionsByNamespaceGin)
	adminGroup.PUT("/admin/namespaces/:ns/clients/:id/scopes", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.UPDATE), s.HandleUpdateClientScopesByNamespaceGin)
	// Global client scopes endpoint (admin only)
	adminGroup.PUT("/admin/clients/:id/scopes", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.UPDATE), s.HandleUpdateClientScopesGin)
	// Admin: client read/list/delete
	adminGroup.GET("/admin/clients/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.READ), s.HandleGetClientGin)
	adminGroup.GET("/admin/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.READ), s.HandleListClientsGin)
	// list clients by namespace
	adminGroup.GET("/admin/namespaces/:ns/clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:CLIENT", permission.READ), s.HandleListClientsByNamespaceGin)
	adminGroup.DELETE("/admin/clients/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeClientAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:CLIENT", permission.DELETE), s.HandleDeleteClientGin)

	// Admin: list users (with optional filters)
	adminGroup.GET("/admin/namespaces/:ns/users", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleListUsersGin)
	// Admin: get user by ID
	adminGroup.GET("/admin/namespaces/:ns/users/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleGetUserGin)
	// Admin: ban/unban user in namespace (Scope + Permission)
	adminGroup.POST("/admin/namespaces/:ns/users/:id/ban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.UPDATE), s.HandleBanUserGin)
	adminGroup.POST("/admin/namespaces/:ns/users/:id/unban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.UPDATE), s.HandleUnbanUserGin)
	// Admin: list bans
	adminGroup.GET("/admin/namespaces/:ns/users/:id/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleListUserBansGin)
	adminGroup.GET("/admin/namespaces/:ns/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleListNamespaceBansGin)
	// Admin: account-level ban/unban
	adminGroup.POST("/admin/users/:id/ban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.UPDATE), s.HandleBanAccountGin)
	adminGroup.POST("/admin/users/:id/unban", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.UPDATE), s.HandleUnbanAccountGin)
	adminGroup.GET("/admin/users/:id/bans", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.READ), s.HandleListAccountBansGin)
	adminGroup.GET("/admin/users/:id/login-history", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.READ), s.HandleListLoginHistoryGin)
	adminGroup.GET("/admin/users/:id/link-history", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAccountRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:ACCOUNT", permission.READ), s.HandleListLinkHistoryGin)
	// Admin: dashboard stats (namespace-scoped)
	adminGroup.GET("/admin/namespaces/:ns/stats/signups", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER", permission.READ), s.HandleGetSignupStatsGin)
	// Admin: user permissions
	adminGroup.GET("/admin/users/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserRead, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.READ), s.HandleGetUserPermissionsGin)
	adminGroup.PUT("/admin/users/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.HandleUpdateUserPermissionsGin)
	adminGroup.POST("/admin/users/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.UPDATE), s.HandleAddUserPermissionsGin)
	adminGroup.DELETE("/admin/users/:id/permissions", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeUserAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:*:USER", permission.DELETE), s.HandleRemoveUserPermissionsGin)

	// Roles management (Scope + Permission)
	adminGroup.POST("/admin/namespaces/:ns/roles", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.CREATE), s.HandleUpsertRoleGin)
	adminGroup.GET("/admin/namespaces/:ns/roles", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.READ), s.HandleListRolesGin)
	adminGroup.DELETE("/admin/namespaces/:ns/roles/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.DELETE), s.HandleDeleteRoleGin)
	// Assignments
	adminGroup.POST("/admin/namespaces/:ns/roles/:id/users/:userId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToUserGin)
	adminGroup.POST("/admin/namespaces/:ns/roles/:id/clients/:clientId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToClientGin)
	adminGroup.POST("/admin/namespaces/:ns/roles/:id/assign-all-users", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeRoleAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:ROLE", permission.UPDATE), s.HandleAssignRoleToAllUsersGin)

	// Platform token management (admin)
	adminGroup.GET("/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER:{userId}", permission.READ), s.HandleGetPlatformTokenGin)
	adminGroup.GET("/oauth/admin/namespaces/:ns/users/:userId/platforms", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:USER:{userId}", permission.READ), s.HandleListPlatformAccountsGin)

	// Platform user search (admin)
	adminGroup.GET("/admin/namespaces/:ns/platform-users/search", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.READ), s.HandleSearchPlatformAccountsGin)

	// Platform client configuration (admin)
	adminGroup.GET("/admin/namespaces/:ns/platform-clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.READ), s.HandleListPlatformClientsGin)
	adminGroup.GET("/admin/namespaces/:ns/platform-clients/:platformId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformRead, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.READ), s.HandleGetPlatformClientGin)
	adminGroup.POST("/admin/namespaces/:ns/platform-clients", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.CREATE), s.HandleCreatePlatformClientGin)
	adminGroup.PUT("/admin/namespaces/:ns/platform-clients/:platformId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.UPDATE), s.HandleUpdatePlatformClientGin)
	adminGroup.PUT("/admin/namespaces/:ns/platform-clients/:platformId/active", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformWrite, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.UPDATE), s.HandleUpdatePlatformClientActiveGin)
	adminGroup.DELETE("/admin/namespaces/:ns/platform-clients/:platformId", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopePlatformAdmin, ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:PLATFORM", permission.DELETE), s.HandleDeletePlatformClientGin)

	// Platform OAuth authorization flow (public - no auth required)
	r.GET("/iam/v1/oauth/platforms/:platformId/authorize", s.HandlePlatformAuthorizeGin)
	r.GET("/iam/v1/platforms/:platformId/authenticate", s.HandlePlatformAuthenticateGin)

	// Platform token endpoint (public - client auth via Basic Auth)
	r.POST("/iam/v1/oauth/platforms/:platformId/token", s.HandlePlatformTokenGin)

	// Password reset endpoints (public - no auth required)
	r.POST("/iam/v1/public/users/forgot-password", s.HandleForgotPasswordGin)
	r.POST("/iam/v1/public/users/reset-password", s.HandleResetPasswordGin)
	r.GET("/iam/v1/public/users/reset-password/validate", s.HandleValidateResetCodeGin)

	// System settings (admin only)
	adminGroup.GET("/admin/settings", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:*:SETTINGS", permission.READ), s.HandleGetAllSettingsGin)

	// Email providers - Supported types (admin only)
	adminGroup.GET("/admin/email-providers/types", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:*:EMAIL", permission.READ), s.HandleGetSupportedProvidersGin)

	// Email providers - Namespace scoped (all operations are namespace-scoped)
	adminGroup.GET("/admin/namespaces/:ns/email-providers", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.READ), s.HandleListEmailProvidersByNamespaceGin)
	adminGroup.GET("/admin/namespaces/:ns/email-providers/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.READ), s.HandleGetEmailProviderByNamespaceGin)
	adminGroup.POST("/admin/namespaces/:ns/email-providers", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.CREATE), s.HandleCreateEmailProviderByNamespaceGin)
	adminGroup.PUT("/admin/namespaces/:ns/email-providers/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.UPDATE), s.HandleUpdateEmailProviderByNamespaceGin)
	adminGroup.DELETE("/admin/namespaces/:ns/email-providers/:id", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.DELETE), s.HandleDeleteEmailProviderByNamespaceGin)
	adminGroup.POST("/admin/namespaces/:ns/email-providers/:id/set-default", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.UPDATE), s.HandleSetDefaultEmailProviderByNamespaceGin)
	adminGroup.POST("/admin/namespaces/:ns/email-providers/:id/test", s.RequireScopeAndPermission(ScopeRequirement{Required: []string{ScopeAdmin}}, "ADMIN:NAMESPACE:{ns}:EMAIL", permission.UPDATE), s.HandleTestEmailProviderByNamespaceGin)

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
