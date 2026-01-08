package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TokenMiddleware validates the bearer token and sets user info in context.
// This middleware should run first, before scope/permission checks.
// It supports both JWT tokens and opaque tokens stored in token store.
func (s *Server) TokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
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

		// Try to parse as JWT first
		jwtKey := []byte("00000000") // Must match the key used in generates.NewJWTAccessGenerate
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err == nil && token.Valid {
			// JWT token parsed successfully
			claims, ok := token.Claims.(jwt.MapClaims)
			if ok {
				// Set values in context from JWT claims
				// Prefer user_id claim (actual user ID from users table), fallback to sub (account_id)
				if userID, exists := claims["user_id"]; exists {
					c.Set("user_id", userID)
				} else if sub, exists := claims["sub"]; exists {
					c.Set("user_id", sub)
				}
				if clientID, exists := claims["client_id"]; exists {
					c.Set("client_id", clientID)
				}
				if namespace, exists := claims["namespace"]; exists {
					c.Set("namespace", namespace)
				}
				if scope, exists := claims["scope"]; exists {
					if scopeStr, ok := scope.(string); ok {
						c.Set("user_scopes", strings.Fields(scopeStr))
					}
				}
				if permissions, exists := claims["permissions"]; exists {
					c.Set("permissions", permissions)
				}
				c.Set("token_claims", claims)
				c.Set("token_type", "jwt")
				c.Next()
				return
			}
		}

		// Fallback: Try to validate using token store (for opaque tokens)
		// Check if AccessTokenResolveHandler is set before calling ValidationBearerToken
		if s.AccessTokenResolveHandler == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid access token",
			})
			c.Abort()
			return
		}

		ti, verr := s.ValidationBearerToken(c.Request)
		if verr != nil || ti == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid access token",
			})
			c.Abort()
			return
		}

		// Set values in context from token info
		c.Set("user_id", ti.GetUserID())
		c.Set("client_id", ti.GetClientID())
		if scope := ti.GetScope(); scope != "" {
			c.Set("user_scopes", strings.Fields(scope))
		}
		c.Set("token_info", ti)
		c.Set("token_type", "opaque")

		c.Next()
	}
}

// GetUserIDFromContext retrieves the user ID from the gin context.
// Returns empty string if not found.
func GetUserIDFromContext(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetClientIDFromContext retrieves the client ID from the gin context.
// Returns empty string if not found.
func GetClientIDFromContext(c *gin.Context) string {
	if clientID, exists := c.Get("client_id"); exists {
		if id, ok := clientID.(string); ok {
			return id
		}
	}
	return ""
}

// GetScopesFromContext retrieves the scopes from the gin context.
// Returns empty slice if not found.
func GetScopesFromContext(c *gin.Context) []string {
	if scopes, exists := c.Get("user_scopes"); exists {
		if s, ok := scopes.([]string); ok {
			return s
		}
	}
	return []string{}
}

// GetNamespaceFromContext retrieves the namespace from the gin context.
// Returns empty string if not found.
func GetNamespaceFromContext(c *gin.Context) string {
	if namespace, exists := c.Get("namespace"); exists {
		if ns, ok := namespace.(string); ok {
			return ns
		}
	}
	return ""
}
