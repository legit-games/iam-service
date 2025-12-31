package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
)

// ClaimsExtractor defines how to build permission.Claims from a JWT or request context.
// Implementers can plug in their own extraction if needed.
type ClaimsExtractor func(*gin.Context) permission.Claims

// DefaultClaimsExtractor builds Claims from context or Authorization Bearer JWT.
// Context keys (preferred if already set by upstream middleware):
// - permissions: []string of "RESOURCE_ACTION"
// - accountId: string (UUID4 hyphenless)
// - namespace: string
// If not present, attempts to decode JWT payload and read the same claim keys.
func DefaultClaimsExtractor(c *gin.Context) permission.Claims {
	claims := permission.Claims{}
	// From context
	if v, ok := c.Get("permissions"); ok {
		if arr, ok2 := v.([]string); ok2 {
			claims.Permissions = arr
		}
	}
	if v, ok := c.Get("accountId"); ok {
		if s, ok2 := v.(string); ok2 {
			claims.AccountID = s
		}
	}
	if v, ok := c.Get("namespace"); ok {
		if s, ok2 := v.(string); ok2 {
			claims.Namespace = s
		}
	}
	// If missing, try to read from Authorization Bearer JWT
	if len(claims.Permissions) == 0 || claims.AccountID == "" || claims.Namespace == "" {
		jwtPerms, jwtAcc, jwtNs := extractClaimsFromJWT(c)
		if len(claims.Permissions) == 0 {
			claims.Permissions = jwtPerms
		}
		if claims.AccountID == "" {
			claims.AccountID = jwtAcc
		}
		if claims.Namespace == "" {
			claims.Namespace = jwtNs
		}
	}
	return claims
}

// RequireAuthorization returns a middleware that checks permission before handler execution.
// resource may contain placeholders like {accountId}, {namespace}, or path params {id} etc.
// action is a permission.Action bitmask.
func RequireAuthorization(resource string, action permission.Action, extract ClaimsExtractor) gin.HandlerFunc {
	if extract == nil {
		extract = DefaultClaimsExtractor
	}
	return func(c *gin.Context) {
		// Replace placeholders from path params first
		res := resource
		for _, p := range c.Params {
			ph := "{" + p.Key + "}"
			if strings.Contains(res, ph) {
				res = strings.ReplaceAll(res, ph, p.Value)
			}
		}
		// Build claims
		claims := extract(c)
		// Evaluate
		svc := permission.Service{}
		if !svc.HasPermission(claims, res+"_"+actionString(action)) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// actionString converts Action to its string name (CREATE, READ, ...)
func actionString(a permission.Action) string {
	switch a {
	case permission.CREATE:
		return "CREATE"
	case permission.READ:
		return "READ"
	case permission.UPDATE:
		return "UPDATE"
	case permission.DELETE:
		return "DELETE"
	case permission.CREATE_READ:
		return "CREATE_READ"
	case permission.CREATE_UPDATE:
		return "CREATE_UPDATE"
	case permission.READ_UPDATE:
		return "READ_UPDATE"
	case permission.CREATE_READ_UPDATE:
		return "CREATE_READ_UPDATE"
	case permission.CREATE_DELETE:
		return "CREATE_DELETE"
	case permission.READ_DELETE:
		return "READ_DELETE"
	case permission.CREATE_READ_DELETE:
		return "CREATE_READ_DELETE"
	case permission.UPDATE_DELETE:
		return "UPDATE_DELETE"
	case permission.CREATE_UPDATE_DELETE:
		return "CREATE_UPDATE_DELETE"
	case permission.READ_UPDATE_DELETE:
		return "READ_UPDATE_DELETE"
	case permission.ALL:
		return "ALL"
	default:
		return "UNKNOWN"
	}
}

// extractClaimsFromJWT decodes the JWT payload without verifying signature to extract claims.
// Expected claim keys: "permissions" (array of strings), "accountId" (string), "namespace" (string).
func extractClaimsFromJWT(c *gin.Context) (perms []string, accountId string, namespace string) {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return nil, "", ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, "", ""
	}
	token := parts[1]
	segs := strings.Split(token, ".")
	if len(segs) < 2 {
		return nil, "", ""
	}
	payloadB64 := segs[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, "", ""
	}
	var m map[string]any
	if err := json.Unmarshal(payloadBytes, &m); err != nil {
		return nil, "", ""
	}
	// permissions
	if v, ok := m["permissions"]; ok {
		if arr, ok2 := v.([]any); ok2 {
			for _, e := range arr {
				if s, ok3 := e.(string); ok3 {
					perms = append(perms, s)
				}
			}
		}
	}
	// accountId
	if v, ok := m["accountId"]; ok {
		if s, ok2 := v.(string); ok2 {
			accountId = s
		}
	}
	// namespace
	if v, ok := m["namespace"]; ok {
		if s, ok2 := v.(string); ok2 {
			namespace = s
		}
	}
	return perms, accountId, namespace
}
