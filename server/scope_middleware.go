package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/golang-jwt/jwt/v5"
)

// ScopeRequirement represents a scope requirement for an endpoint
type ScopeRequirement struct {
	Required []string // Required scopes (OR logic - user needs at least one)
	All      []string // All required scopes (AND logic - user needs all)
}

// RequireScope creates a middleware that validates OAuth 2.0 scopes from access tokens
// Supports both JWT access tokens and opaque tokens (via token store lookup)
func (s *Server) RequireScope(requirement ScopeRequirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Bearer token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "missing authorization header",
			})
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		var userScopes []string
		var claims jwt.MapClaims
		var tokenValid bool

		// Try to parse as JWT first
		jwtKey := []byte("test-key") // Default for testing
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err == nil && token.Valid {
			// JWT token - extract claims
			var ok bool
			claims, ok = token.Claims.(jwt.MapClaims)
			if ok {
				tokenValid = true
				if scopeClaim, exists := claims["scope"]; exists {
					if scopeStr, ok := scopeClaim.(string); ok {
						userScopes = strings.Fields(scopeStr)
					}
				}
			}
		}

		// If JWT parsing failed, try to look up as opaque token in token store
		if !tokenValid && s.Manager != nil {
			if m, ok := s.Manager.(*manage.Manager); ok {
				ti, err := m.LoadAccessToken(c.Request.Context(), tokenString)
				if err == nil && ti != nil {
					tokenValid = true
					userScopes = strings.Fields(ti.GetScope())
					// Create synthetic claims from token info
					claims = jwt.MapClaims{
						"sub":       ti.GetUserID(),
						"client_id": ti.GetClientID(),
						"scope":     ti.GetScope(),
					}
				}
			}
		}

		if !tokenValid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid access token",
			})
			c.Abort()
			return
		}

		// Check scope requirements
		if !hasRequiredScopes(userScopes, requirement) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "token lacks required scope",
				"scope":             strings.Join(getAllRequiredScopes(requirement), " "),
			})
			c.Abort()
			return
		}

		// Store token info in context for later use
		c.Set("token_claims", claims)
		c.Set("user_scopes", userScopes)
		c.Set("client_id", claims["client_id"])
		c.Set("user_id", claims["sub"])

		c.Next()
	}
}

// hasRequiredScopes checks if user has required scopes
func hasRequiredScopes(userScopes []string, requirement ScopeRequirement) bool {
	userScopeMap := make(map[string]bool)
	for _, scope := range userScopes {
		userScopeMap[scope] = true
	}

	// Check "All" requirement (AND logic) - user must have ALL listed scopes
	if len(requirement.All) > 0 {
		for _, requiredScope := range requirement.All {
			if !userScopeMap[requiredScope] {
				return false
			}
		}
	}

	// Check "Required" requirement (OR logic) - user must have at least ONE scope
	if len(requirement.Required) > 0 {
		hasAny := false
		for _, requiredScope := range requirement.Required {
			if userScopeMap[requiredScope] {
				hasAny = true
				break
			}
		}
		if !hasAny {
			return false
		}
	}

	// If no requirements specified, allow access
	if len(requirement.All) == 0 && len(requirement.Required) == 0 {
		return true
	}

	return true
}

// getAllRequiredScopes returns all scopes mentioned in the requirement
func getAllRequiredScopes(requirement ScopeRequirement) []string {
	scopes := make(map[string]bool)

	for _, scope := range requirement.All {
		scopes[scope] = true
	}
	for _, scope := range requirement.Required {
		scopes[scope] = true
	}

	result := make([]string, 0, len(scopes))
	for scope := range scopes {
		result = append(result, scope)
	}

	return result
}

// RequireAnyScope requires at least one of the specified scopes
func (s *Server) RequireAnyScope(scopes ...string) gin.HandlerFunc {
	return s.RequireScope(ScopeRequirement{Required: scopes})
}

// RequireAllScopes requires all of the specified scopes
func (s *Server) RequireAllScopes(scopes ...string) gin.HandlerFunc {
	return s.RequireScope(ScopeRequirement{All: scopes})
}

// OptionalScope allows access but extracts scope info if present
func (s *Server) OptionalScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Similar to RequireScope but doesn't block on missing scopes
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]
		jwtKey := []byte("test-key") // Default for testing

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.Next()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			var userScopes []string
			if scopeClaim, exists := claims["scope"]; exists {
				if scopeStr, ok := scopeClaim.(string); ok {
					userScopes = strings.Fields(scopeStr)
				}
			}

			c.Set("token_claims", claims)
			c.Set("user_scopes", userScopes)
			c.Set("client_id", claims["client_id"])
			c.Set("user_id", claims["sub"])
		}

		c.Next()
	}
}
