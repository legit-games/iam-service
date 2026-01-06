package server

import (
	"github.com/gin-gonic/gin"
)

// NewGinEngineWithScopeAuth builds a Gin router with ONLY OAuth 2.0 scope-based authorization
// This version removes all permission-based middleware for pure OAuth 2.0 compliance
func NewGinEngineWithScopeAuth(s *Server) *gin.Engine {
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.Use(gin.Recovery())
	r.Use(parseFormMiddleware())

	// OAuth 2.0 Core Endpoints (no scope check required per RFC 6749)
	r.GET("/oauth/authorize", blockImplicitMiddleware(), restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))
	r.POST("/oauth/authorize", blockImplicitMiddleware(), restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))
	r.POST("/oauth/token", ginFrom(s.HandleTokenRequest))
	if s.Config != nil && s.Config.AllowGetAccessRequest {
		r.GET("/oauth/token", ginFrom(s.HandleTokenRequest))
	}

	// Protected OAuth endpoints (scope required per RFC)
	r.POST("/oauth/introspect", s.RequireAnyScope(ScopeTokenIntrospect, ScopeAdmin), ginFrom(s.HandleIntrospectionRequest))
	r.POST("/oauth/revoke", s.RequireAnyScope(ScopeTokenRevoke, ScopeAdmin), ginFrom(s.HandleRevocationRequest))

	// OIDC endpoints
	if s.Config != nil && s.Config.OIDCEnabled {
		r.GET("/.well-known/openid-configuration", ginFrom(s.HandleOIDCDiscovery))
		r.GET("/.well-known/jwks.json", ginFrom(s.HandleOIDCJWKS))
		r.GET("/oauth/userinfo", s.RequireAnyScope(ScopeProfile), ginFrom(s.HandleOIDCUserInfo))
		r.POST("/oauth/userinfo", s.RequireAnyScope(ScopeProfile), ginFrom(s.HandleOIDCUserInfo))
	}

	// Swagger endpoints (public)
	r.GET("/swagger.json", s.HandleSwaggerJSONGin)
	r.GET("/swagger", s.HandleSwaggerUIGin)

	// Public endpoints (no auth required)
	r.POST("/iam/v1/public/login", s.HandleAPILoginGin)
	r.POST("/iam/v1/public/users", s.HandleAPIRegisterUserGin)

	// === SCOPE-PROTECTED IAM API ENDPOINTS ===

	// Namespace Management
	r.POST("/iam/v1/admin/namespaces", s.RequireAnyScope(ScopeNamespaceWrite, ScopeAdmin), s.handleCreateNamespace)

	// Account Management
	r.POST("/iam/v1/accounts/head", s.RequireAnyScope(ScopeAccountWrite, ScopeAdmin), s.handleCreateHeadAccount)
	r.POST("/iam/v1/accounts/headless", s.RequireAnyScope(ScopeAccountWrite, ScopeAdmin), s.handleCreateHeadlessAccount)
	r.POST("/iam/v1/accounts/:id/link", s.RequireAnyScope(ScopeAccountWrite, ScopeAdmin), s.handleLinkAccount)
	r.POST("/iam/v1/accounts/:id/unlink", s.RequireAnyScope(ScopeAccountWrite, ScopeAdmin), s.handleUnlinkAccount)
	r.POST("/iam/v1/admin/accounts/:id/ban", s.RequireAnyScope(ScopeAccountAdmin, ScopeAdmin), s.HandleBanAccountGin)
	r.POST("/iam/v1/admin/accounts/:id/unban", s.RequireAnyScope(ScopeAccountAdmin, ScopeAdmin), s.HandleUnbanAccountGin)
	r.GET("/iam/v1/admin/accounts/:id/bans", s.RequireAnyScope(ScopeAccountRead, ScopeAdmin), s.HandleListAccountBansGin)

	// Client Management
	r.GET("/iam/v1/admin/clients/:id", s.RequireAnyScope(ScopeClientRead, ScopeAdmin), s.HandleGetClientGin)
	r.GET("/iam/v1/admin/clients", s.RequireAnyScope(ScopeClientRead, ScopeAdmin), s.HandleListClientsGin)
	r.GET("/iam/v1/admin/namespaces/:ns/clients", s.RequireAnyScope(ScopeClientRead, ScopeAdmin), s.HandleListClientsByNamespaceGin)
	r.POST("/iam/v1/admin/namespaces/:ns/clients", s.RequireAnyScope(ScopeClientWrite, ScopeAdmin), s.HandleUpsertClientByNamespaceGin)
	r.PUT("/iam/v1/admin/namespaces/:ns/clients/:id/permissions", s.RequireAnyScope(ScopeClientAdmin, ScopeAdmin), s.HandleUpdateClientPermissionsByNamespaceGin)
	r.PUT("/iam/v1/admin/namespaces/:ns/clients/:id/scopes", s.RequireAnyScope(ScopeClientAdmin, ScopeAdmin), s.HandleUpdateClientScopesByNamespaceGin)
	r.PUT("/iam/v1/admin/clients/:id/scopes", s.RequireAnyScope(ScopeClientAdmin, ScopeAdmin), s.HandleUpdateClientScopesGin)
	r.DELETE("/iam/v1/admin/clients/:id", s.RequireAnyScope(ScopeClientAdmin, ScopeAdmin), s.HandleDeleteClientGin)

	// User Management
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/ban", s.RequireAnyScope(ScopeUserAdmin, ScopeAdmin), s.HandleBanUserGin)
	r.POST("/iam/v1/admin/namespaces/:ns/users/:id/unban", s.RequireAnyScope(ScopeUserAdmin, ScopeAdmin), s.HandleUnbanUserGin)
	r.GET("/iam/v1/admin/namespaces/:ns/users/:id/bans", s.RequireAnyScope(ScopeUserRead, ScopeAdmin), s.HandleListUserBansGin)
	r.GET("/iam/v1/admin/namespaces/:ns/bans", s.RequireAnyScope(ScopeUserRead, ScopeAdmin), s.HandleListNamespaceBansGin)

	// Role Management
	r.POST("/iam/v1/admin/namespaces/:ns/roles", s.RequireAnyScope(ScopeRoleWrite, ScopeAdmin), s.HandleUpsertRoleGin)
	r.GET("/iam/v1/admin/namespaces/:ns/roles", s.RequireAnyScope(ScopeRoleRead, ScopeAdmin), s.HandleListRolesGin)
	r.DELETE("/iam/v1/admin/namespaces/:ns/roles/:id", s.RequireAnyScope(ScopeRoleAdmin, ScopeAdmin), s.HandleDeleteRoleGin)
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/users/:userId", s.RequireAnyScope(ScopeRoleAdmin, ScopeAdmin), s.HandleAssignRoleToUserGin)
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/clients/:clientId", s.RequireAnyScope(ScopeRoleAdmin, ScopeAdmin), s.HandleAssignRoleToClientGin)
	r.POST("/iam/v1/admin/namespaces/:ns/roles/:id/assign-all-users", s.RequireAnyScope(ScopeRoleAdmin, ScopeAdmin), s.HandleAssignRoleToAllUsersGin)

	return r
}

// === This file provides an alternative scope-only engine ===
// Use NewGinEngineWithScopeAuth instead of NewGinEngine for pure OAuth 2.0 scope authorization
