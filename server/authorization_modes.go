package server

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
	"github.com/golang-jwt/jwt/v5"
)

// AuthorizationMode defines how authorization should be handled
type AuthorizationMode int

const (
	// ScopeOnly - Use only OAuth 2.0 scope-based authorization
	ScopeOnly AuthorizationMode = iota
	// PermissionOnly - Use only role-based permission authorization
	PermissionOnly
	// ScopeOrPermission - Allow access if EITHER scope OR permission is satisfied
	ScopeOrPermission
	// ScopeAndPermission - Require BOTH scope AND permission to be satisfied
	ScopeAndPermission
)

// RequireScopeOrPermission creates a middleware that checks either scope OR permission
// This provides flexibility for migration from permission-based to scope-based auth
func (s *Server) RequireScopeOrPermission(scopeRequirement ScopeRequirement, permissionSpec string, permAction permission.Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try scope-based authorization first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
					return []byte("test-key"), nil
				})

				if err == nil && token.Valid {
					if claims, ok := token.Claims.(jwt.MapClaims); ok {
						// Extract scopes from token
						var userScopes []string
						if scopeClaim, exists := claims["scope"]; exists {
							if scopeStr, ok := scopeClaim.(string); ok {
								userScopes = strings.Fields(scopeStr)
							}
						}

						// Check scope requirements
						if hasRequiredScopes(userScopes, scopeRequirement) {
							// Store token info in context for later use
							c.Set("token_claims", claims)
							c.Set("user_scopes", userScopes)
							c.Set("client_id", claims["client_id"])
							c.Set("user_id", claims["sub"])
							c.Next()
							return
						}
					}
				}
			}
		}

		// If scope check failed, fall back to permission check
		// Create a permission middleware and execute it
		permissionMiddleware := RequireAuthorization(permissionSpec, permAction, nil)
		permissionMiddleware(c)
	}
}

// RequireScopeOnly creates a middleware that ONLY checks OAuth 2.0 scopes
// This bypasses the permission system entirely
func (s *Server) RequireScopeOnly(requirement ScopeRequirement) gin.HandlerFunc {
	return s.RequireScope(requirement)
}

// CreateAuthorizationMiddleware creates the appropriate middleware based on the authorization mode
func (s *Server) CreateAuthorizationMiddleware(mode AuthorizationMode, scopeRequirement ScopeRequirement, permissionSpec string, permAction permission.Action) gin.HandlerFunc {
	switch mode {
	case ScopeOnly:
		return s.RequireScope(scopeRequirement)
	case PermissionOnly:
		return RequireAuthorization(permissionSpec, permAction, nil)
	case ScopeOrPermission:
		return s.RequireScopeOrPermission(scopeRequirement, permissionSpec, permAction)
	case ScopeAndPermission:
		// Chain both middlewares - scope first, then permission
		return func(c *gin.Context) {
			// First check scope
			scopeMiddleware := s.RequireScope(scopeRequirement)
			scopeMiddleware(c)

			if c.IsAborted() {
				return
			}

			// Then check permission
			permissionMiddleware := RequireAuthorization(permissionSpec, permAction, nil)
			permissionMiddleware(c)
		}
	default:
		return s.RequireScope(scopeRequirement)
	}
}
