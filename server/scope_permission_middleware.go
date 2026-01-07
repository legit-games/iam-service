package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
	"github.com/golang-jwt/jwt/v5"
)

// RequireScopeAndPermission creates a middleware that checks scope FIRST, then permission
// This provides a layered authorization approach: OAuth 2.0 scopes as the first gate,
// role-based permissions as the second gate
func (s *Server) RequireScopeAndPermission(scopeRequirement ScopeRequirement, permissionSpec string, permAction permission.Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Step 1: Check OAuth 2.0 scopes first
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "missing authorization header",
			})
			c.Abort()
			return
		}

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
		jwtKey := []byte("00000000") // Must match the key used in generates.NewJWTAccessGenerate

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid access token",
			})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid token claims",
			})
			c.Abort()
			return
		}

		// Extract scopes from token
		var userScopes []string
		if scopeClaim, exists := claims["scope"]; exists {
			if scopeStr, ok := scopeClaim.(string); ok {
				userScopes = strings.Fields(scopeStr)
			}
		}

		// Check scope requirements FIRST
		if !hasRequiredScopes(userScopes, scopeRequirement) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "token lacks required scope",
				"scope":             strings.Join(getAllRequiredScopes(scopeRequirement), " "),
			})
			c.Abort()
			return
		}

		// Store token info in context for the permission middleware
		c.Set("token_claims", claims)
		c.Set("user_scopes", userScopes)
		c.Set("client_id", claims["client_id"])
		c.Set("user_id", claims["sub"])

		// Step 2: If scope check passed, proceed to permission check
		// Execute the permission middleware
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
