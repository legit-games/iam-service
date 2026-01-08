package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
)

// RequireScopeAndPermission creates a middleware that checks scope FIRST, then permission
// This provides a layered authorization approach: OAuth 2.0 scopes as the first gate,
// role-based permissions as the second gate
// NOTE: This middleware expects TokenMiddleware to have run first
func (s *Server) RequireScopeAndPermission(scopeRequirement ScopeRequirement, permissionSpec string, permAction permission.Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get scopes from context (set by TokenMiddleware)
		userScopes := GetScopesFromContext(c)
		if len(userScopes) == 0 {
			// No scopes found - token middleware should have set them
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "no scopes found in token",
			})
			c.Abort()
			return
		}

		// Check scope requirements
		if !hasRequiredScopes(userScopes, scopeRequirement) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "token lacks required scope",
				"scope":             strings.Join(getAllRequiredScopes(scopeRequirement), " "),
			})
			c.Abort()
			return
		}

		// If user has "admin" scope, bypass permission check (admin has full access)
		hasAdminScope := false
		for _, scope := range userScopes {
			if scope == ScopeAdmin {
				hasAdminScope = true
				break
			}
		}
		if hasAdminScope {
			// Admin scope bypasses permission check
			c.Next()
			return
		}

		// If scope check passed but no admin scope, proceed to permission check
		permissionMiddleware := RequireAuthorization(permissionSpec, permAction, nil)
		permissionMiddleware(c)

		// If permission middleware aborted, don't continue
		if c.IsAborted() {
			return
		}

		// Both checks passed, continue to handler
		c.Next()
	}
}

// RequireScopeFirst creates a middleware that checks scope first, then delegates to next handler
// This is useful when you want scope as a primary gate but don't necessarily need permission check
func (s *Server) RequireScopeFirst(scopeRequirement ScopeRequirement, nextMiddleware gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check scope
		scopeMiddleware := s.RequireScope(scopeRequirement)
		scopeMiddleware(c)

		// If scope check failed, don't continue
		if c.IsAborted() {
			return
		}

		// If scope check passed, execute next middleware
		if nextMiddleware != nil {
			nextMiddleware(c)
		} else {
			c.Next()
		}
	}
}
