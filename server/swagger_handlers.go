package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleSwaggerJSON serves an OpenAPI 3.0 spec that documents the available endpoints.
func (s *Server) HandleSwaggerJSON(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "OAuth2 Authorization Server",
			"version":     "1.0.0",
			"description": "OpenAPI for OAuth2 endpoints (RFC 6749, 6750, 7009, 7662).",
		},
		"servers": []map[string]interface{}{{"url": "/"}},
		"paths": map[string]interface{}{
			"/oauth/authorize":           s.swaggerAuthorizePath(),
			"/oauth/token":               s.swaggerTokenPath(),
			"/oauth/introspect":          s.swaggerIntrospectPath(),
			"/oauth/revoke":              s.swaggerRevokePath(),
			"/api/login":                 s.swaggerAPILoginPath(),
			"/api/register":              s.swaggerRegisterUserPath(),
			"/iam/v1/public/users":       s.swaggerRegisterUserPath(),
			"/iam/v1/public/users/login": s.swaggerAPILoginPath(),
			"/iam/v1/admin/users":        s.swaggerRegisterUserPath(),
			"/iam/v1/admin/users/{accountId}/permissions": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Append permissions to an account",
					"description": "Adds or merges permissions array into the account's JSONB permissions field. Requires ADMIN:NAMESPACE:*:ACCOUNT_UPDATE.",
					"parameters":  []map[string]interface{}{{"name": "accountId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "400": map[string]interface{}{"description": "Bad Request"}},
				},
			},
			// New: namespace-scoped client routes
			"/iam/v1/admin/namespaces/{ns}/clients": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create or update a client in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_CREATE. Upserts client with permissions.",
					"parameters":  []map[string]interface{}{{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"id":          map[string]interface{}{"type": "string"},
							"secret":      map[string]interface{}{"type": "string"},
							"domain":      map[string]interface{}{"type": "string"},
							"user_id":     map[string]interface{}{"type": "string"},
							"public":      map[string]interface{}{"type": "boolean"},
							"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						}, "required": []string{"id", "secret", "domain"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
				"get": map[string]interface{}{
					"summary":     "List clients in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_READ. Note: Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "offset", "in": "query", "schema": map[string]interface{}{"type": "integer", "minimum": 0}},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 1000}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/clients/{id}/permissions": map[string]interface{}{
				"put": map[string]interface{}{
					"summary":     "Replace client permissions in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_UPDATE. Note: Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/ban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Ban a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Bans a user with PERMANENT or TIMED ban. Actor is derived from the caller's access token. Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"type":   map[string]interface{}{"type": "string", "enum": []string{"PERMANENT", "TIMED"}},
							"reason": map[string]interface{}{"type": "string"},
							"until":  map[string]interface{}{"type": "string", "format": "date-time", "description": "Required when type=TIMED"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "User banned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/unban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unban a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Removes a user's ban in the namespace. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"reason": map[string]interface{}{"type": "string"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "User unbanned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans for a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER READ. Returns current and historical bans for the user.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER READ. Use ?active=true to filter active bans.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "active", "in": "query", "required": false, "schema": map[string]interface{}{"type": "boolean"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			// Account-level ban endpoints
			"/iam/v1/admin/users/{id}/ban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Ban an account (affects all users under the account)",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Bans an entire account with PERMANENT or TIMED ban. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"type":   map[string]interface{}{"type": "string", "enum": []string{"PERMANENT", "TIMED"}},
							"reason": map[string]interface{}{"type": "string"},
							"until":  map[string]interface{}{"type": "string", "format": "date-time", "description": "Required when type=TIMED"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account banned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/users/{id}/unban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unban an account",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Removes an account's ban. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"reason": map[string]interface{}{"type": "string"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account unbanned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/users/{id}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans for an account",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT READ. Returns current and historical bans for the account.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create or update a role in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_CREATE. Note: Namespace name must be uppercase A–Z only.",
					"parameters":  []map[string]interface{}{{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"name":        map[string]interface{}{"type": "string"},
							"roleType":    map[string]interface{}{"type": "string", "enum": []string{"USER", "CLIENT"}},
							"permissions": map[string]interface{}{"type": "object", "additionalProperties": true},
							"description": map[string]interface{}{"type": "string"},
						}, "required": []string{"name", "roleType"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
				"get": map[string]interface{}{
					"summary":     "List roles in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_READ.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "roleType", "in": "query", "schema": map[string]interface{}{"type": "string", "enum": []string{"USER", "CLIENT"}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}": map[string]interface{}{
				"delete": map[string]interface{}{
					"summary":     "Delete a role",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_DELETE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/users/{userId}": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to a user",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/clients/{clientId}": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to a client",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "clientId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/assign-all-users": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to all users in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			// Platform endpoints
			"/iam/v1/oauth/admin/namespaces/{ns}/users/{userId}/platforms/{platformId}/platformToken": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Retrieve third-party platform token for a user",
					"description": "Retrieves the stored platform token for a user's linked platform account. Requires platform:read or admin scope.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace"},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "User ID"},
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., steam, google, facebook)"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Platform token retrieved successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Platform account not found"},
					},
				},
			},
			"/iam/v1/oauth/admin/namespaces/{ns}/users/{userId}/platforms": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List linked platform accounts for a user",
					"description": "Returns all platform accounts linked to the specified user. Requires platform:read or admin scope.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace"},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "User ID"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of platform accounts"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/iam/v1/oauth/platforms/{platformId}/authorize": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Initiate platform OAuth authorization",
					"description": "Initiates the OAuth authorization flow with a third-party platform. Returns a redirect URL to the platform's login page.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., google, facebook, discord)"},
						{"name": "request_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "UUID4 without hyphens identifying the authorization request"},
					},
					"responses": map[string]interface{}{
						"302": map[string]interface{}{"description": "Redirect to platform authorization URL"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/platforms/{platformId}/authenticate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Platform OAuth callback",
					"description": "Handles the OAuth callback from third-party platforms after user authorization.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID"},
						{"name": "code", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Authorization code from platform"},
						{"name": "state", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "State parameter (request_id)"},
						{"name": "error", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Error code if authorization failed"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Authentication successful"},
						"400": map[string]interface{}{"description": "Invalid request or authorization denied"},
					},
				},
			},
			"/iam/v1/oauth/platforms/{platformId}/token": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Exchange platform credentials for IAM token",
					"description": "Authenticates a user using third-party platform credentials (platform_token or device_id) and returns IAM access tokens. Requires Basic Auth with client credentials.",
					"tags":        []string{"Platform"},
					"security":    []map[string]interface{}{{"basicAuth": []interface{}{}}},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., steam, google, facebook, device)"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/x-www-form-urlencoded": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"platform_token":  map[string]interface{}{"type": "string", "description": "Token from platform authentication (required if device_id not provided)"},
										"device_id":       map[string]interface{}{"type": "string", "description": "Device identifier (required if platform_token not provided)"},
										"createHeadless":  map[string]interface{}{"type": "boolean", "description": "Create headless account if not linked (default: true)"},
										"skipSetCookie":   map[string]interface{}{"type": "boolean", "description": "Skip setting cookies in response (default: false)"},
										"mac_address":     map[string]interface{}{"type": "string", "description": "MAC address of the device"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Access token issued successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized or not_linked error"},
						"403": map[string]interface{}{"description": "User banned"},
						"503": map[string]interface{}{"description": "Platform service unavailable"},
					},
				},
			},
			// Account Linking endpoints
			"/iam/v1/admin/users/{id}/link": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Link a HEADLESS account to a HEAD account",
					"description": "Links a HEADLESS account to a HEAD account, making the HEAD account a FULL account. The HEADLESS account becomes ORPHAN.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID (target)"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace":           map[string]interface{}{"type": "string", "description": "Namespace to link"},
							"headless_account_id": map[string]interface{}{"type": "string", "description": "HEADLESS account ID (source)"},
						}, "required": []string{"namespace", "headless_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Account linked successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"409": map[string]interface{}{"description": "Link not eligible - conflict detected"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/unlink": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unlink a platform from an account",
					"description": "Removes a specific platform credential from an account. Deletes from platform_users table to prevent platform login.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace":           map[string]interface{}{"type": "string", "description": "Namespace of the platform"},
							"provider_type":       map[string]interface{}{"type": "string", "description": "Platform provider type (e.g., google, steam)"},
							"provider_account_id": map[string]interface{}{"type": "string", "description": "Platform account ID"},
						}, "required": []string{"namespace", "provider_type", "provider_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Platform unlinked successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"500": map[string]interface{}{"description": "Internal server error"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link/check": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Check link eligibility",
					"description": "Checks if a HEAD account can link a HEADLESS account. Returns eligibility status and conflict information if any.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID"},
						{"name": "namespace", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace to check"},
						{"name": "headless_account_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEADLESS account ID"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Eligibility check result"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/platforms": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List linked platforms for an account",
					"description": "Returns all platform accounts linked to the specified account. Can filter by namespace.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Account ID"},
						{"name": "namespace", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Filter by namespace"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of linked platforms"},
						"500": map[string]interface{}{"description": "Internal server error"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link-code": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Generate a link code for a HEADLESS account",
					"description": "Generates a one-time link code that can be used to link a HEADLESS account to a HEAD account. Code expires in 10 minutes.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEADLESS account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace": map[string]interface{}{"type": "string", "description": "Namespace for the link code"},
						}, "required": []string{"namespace"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Link code generated"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"404": map[string]interface{}{"description": "Account not found"},
					},
				},
			},
			"/iam/v1/admin/link-codes/{code}/validate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Validate a link code",
					"description": "Validates a link code without using it. Returns code information if valid.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "code", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Link code to validate"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Validation result"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link-with-code": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Link account using a link code",
					"description": "Links a HEAD account to a HEADLESS account using a one-time link code.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"code": map[string]interface{}{"type": "string", "description": "Link code from HEADLESS account"},
						}, "required": []string{"code"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Account linked successfully"},
						"400": map[string]interface{}{"description": "Invalid or expired code"},
						"409": map[string]interface{}{"description": "Link not eligible - conflict detected"},
					},
				},
			},
			// Account Merge endpoints
			"/iam/v1/admin/accounts/{id}/merge/check": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Check merge eligibility",
					"description": "Checks if source account can be merged into target account. Returns eligibility status, conflicts, and namespaces to be merged.",
					"tags":        []string{"Account Merge"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Target account ID"},
						{"name": "source_account_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Source account ID to merge from"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Merge eligibility result"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/admin/accounts/{id}/merge": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Merge accounts",
					"description": "Merges source account into target account. All BODY users from source are moved to target. Requires conflict resolutions if conflicts exist.",
					"tags":        []string{"Account Merge"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Target account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"source_account_id":    map[string]interface{}{"type": "string", "description": "Source account ID to merge from"},
							"conflict_resolutions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"namespace": map[string]interface{}{"type": "string"}, "keep": map[string]interface{}{"type": "string", "enum": []string{"SOURCE", "TARGET"}}}}, "description": "Resolution for each conflicting namespace"},
						}, "required": []string{"source_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Merge successful"},
						"400": map[string]interface{}{"description": "Invalid request or merge not eligible"},
						"409": map[string]interface{}{"description": "Conflicts require resolution"},
					},
				},
			},
			// Password Reset endpoints
			"/iam/v1/public/users/forgot-password": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Request password reset",
					"description": "Initiates password reset flow by sending a 6-digit code to the user's email. Rate limited to 3 requests per 5 minutes per email.",
					"tags":        []string{"Password Reset"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"email": map[string]interface{}{"type": "string", "format": "email", "description": "Email address associated with the account"},
						}, "required": []string{"email"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Reset code sent (or account not found - same response for security)"},
						"400": map[string]interface{}{"description": "Invalid email format"},
						"429": map[string]interface{}{"description": "Rate limited - too many requests"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
			"/iam/v1/public/users/reset-password/validate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Validate reset code",
					"description": "Validates a password reset code without consuming it. Does not increment failed attempt counter.",
					"tags":        []string{"Password Reset"},
					"parameters": []map[string]interface{}{
						{"name": "email", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "format": "email"}, "description": "Email address"},
						{"name": "code", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "pattern": "^[0-9]{6}$"}, "description": "6-digit reset code"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Validation result with valid status, reason, and remaining attempts"},
						"400": map[string]interface{}{"description": "Missing email or code"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
			"/iam/v1/public/users/reset-password": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Reset password",
					"description": "Resets user password using a valid reset code. Increments failed attempt counter on wrong code (max 5 attempts, then 30-minute lockout).",
					"tags":        []string{"Password Reset"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"email":        map[string]interface{}{"type": "string", "format": "email", "description": "Email address"},
							"code":         map[string]interface{}{"type": "string", "pattern": "^[0-9]{6}$", "description": "6-digit reset code"},
							"new_password": map[string]interface{}{"type": "string", "minLength": 8, "description": "New password (minimum 8 characters)"},
						}, "required": []string{"email", "code", "new_password"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Password reset successful"},
						"400": map[string]interface{}{"description": "Invalid request, code, or password requirements not met"},
						"429": map[string]interface{}{"description": "Account locked due to too many failed attempts"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
		},
		"components": map[string]interface{}{"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}}},
	}
	// OIDC endpoints in spec when enabled
	if s.Config != nil && s.Config.OIDCEnabled {
		paths := spec["paths"].(map[string]interface{})
		paths["/.well-known/openid-configuration"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC Discovery", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "OpenID Provider Metadata"}}},
		}
		paths["/.well-known/jwks.json"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC JWKS", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "JSON Web Key Set"}}},
		}
		paths["/oauth/userinfo"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC UserInfo", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "User claims"}, "401": map[string]interface{}{"description": "Unauthorized"}}},
		}
	}
	// After building spec, augment parameter descriptions for namespace routes
	paths := spec["paths"].(map[string]interface{})
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/clients"].(map[string]interface{}); ok {
		// annotate GET
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_READ. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := get["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
		// annotate POST
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_CREATE. Upserts client with permissions. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/clients/{id}/permissions"].(map[string]interface{}); ok {
		if put, ok2 := p["put"].(map[string]interface{}); ok2 {
			put["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_UPDATE. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := put["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/users/{id}/ban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Bans a user with PERMANENT or TIMED ban. Actor is derived from the caller's access token. Namespace name must be uppercase A–Z only."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/users/{id}/unban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Removes a user's ban in the namespace. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/users/{id}/ban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Bans an entire account with PERMANENT or TIMED ban. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/users/{id}/unban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Removes an account's ban. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles"].(map[string]interface{}); ok {
		// annotate GET
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_READ."
			if params, ok3 := get["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
		// annotate POST
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_CREATE. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}"].(map[string]interface{}); ok {
		if delete, ok2 := p["delete"].(map[string]interface{}); ok2 {
			delete["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_DELETE."
			if params, ok3 := delete["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/users/{userId}"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/clients/{clientId}"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/assign-all-users"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	// Annotate authorize path: Implicit disabled
	if p, ok := paths["/oauth/authorize"].(map[string]interface{}); ok {
		// ensure GET description mentions implicit disabled
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["summary"] = "Authorize (Authorization Code + PKCE)"
			get["description"] = "Implicit flow (response_type=token) is disabled. Use Authorization Code with PKCE and state."
		}
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["summary"] = "Authorize (Authorization Code + PKCE)"
			post["description"] = "Implicit flow (response_type=token) is disabled. Use Authorization Code with PKCE and state."
		}
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(spec)
}

// HandleSwaggerUI serves a minimal Swagger UI that points to /swagger.json
func (s *Server) HandleSwaggerUI(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	html := `<!doctype html><html><head><meta charset="utf-8"/><title>Swagger UI</title>
	<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
	</head><body><div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
	<script>window.ui = SwaggerUIBundle({ url: '/swagger.json', dom_id: '#swagger-ui' });</script>
	</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
	return nil
}

// HandleSwaggerJSONGin serves the OpenAPI spec via Gin.
func (s *Server) HandleSwaggerJSONGin(c *gin.Context) {
	if c.Request.Method != http.MethodGet {
		c.Status(http.StatusMethodNotAllowed)
		return
	}
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "OAuth2 Authorization Server",
			"version":     "1.0.0",
			"description": "OpenAPI for OAuth2 endpoints (RFC 6749, 6750, 7009, 7662).",
		},
		"servers": []map[string]interface{}{{"url": "/"}},
		"paths": map[string]interface{}{
			"/oauth/authorize":           s.swaggerAuthorizePath(),
			"/oauth/token":               s.swaggerTokenPath(),
			"/oauth/introspect":          s.swaggerIntrospectPath(),
			"/oauth/revoke":              s.swaggerRevokePath(),
			"/api/login":                 s.swaggerAPILoginPath(),
			"/api/register":              s.swaggerRegisterUserPath(),
			"/iam/v1/public/users":       s.swaggerRegisterUserPath(),
			"/iam/v1/public/users/login": s.swaggerAPILoginPath(),
			"/iam/v1/admin/users":        s.swaggerRegisterUserPath(),
			"/iam/v1/admin/users/{accountId}/permissions": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Append permissions to an account",
					"description": "Adds or merges permissions array into the account's JSONB permissions field. Requires ADMIN:NAMESPACE:*:ACCOUNT_UPDATE.",
					"parameters":  []map[string]interface{}{{"name": "accountId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "400": map[string]interface{}{"description": "Bad Request"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/clients": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create or update a client in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_CREATE. Upserts client with permissions.",
					"parameters":  []map[string]interface{}{{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"id":          map[string]interface{}{"type": "string"},
							"secret":      map[string]interface{}{"type": "string"},
							"domain":      map[string]interface{}{"type": "string"},
							"user_id":     map[string]interface{}{"type": "string"},
							"public":      map[string]interface{}{"type": "boolean"},
							"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						}, "required": []string{"id", "secret", "domain"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
				"get": map[string]interface{}{
					"summary":     "List clients in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_READ. Note: Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "offset", "in": "query", "schema": map[string]interface{}{"type": "integer", "minimum": 0}},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 1000}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/clients/{id}/permissions": map[string]interface{}{
				"put": map[string]interface{}{
					"summary":     "Replace client permissions in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:CLIENT_UPDATE. Note: Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/ban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Ban a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Bans a user with PERMANENT or TIMED ban. Actor is derived from the caller's access token. Namespace name must be uppercase A–Z only.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"type":   map[string]interface{}{"type": "string", "enum": []string{"PERMANENT", "TIMED"}},
							"reason": map[string]interface{}{"type": "string"},
							"until":  map[string]interface{}{"type": "string", "format": "date-time", "description": "Required when type=TIMED"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "User banned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/unban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unban a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Removes a user's ban in the namespace. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"reason": map[string]interface{}{"type": "string"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "User unbanned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/users/{id}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans for a user in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER READ. Returns current and historical bans for the user.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:USER READ. Use ?active=true to filter active bans.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace (uppercase A–Z only)."},
						{"name": "active", "in": "query", "required": false, "schema": map[string]interface{}{"type": "boolean"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			// Account-level ban endpoints
			"/iam/v1/admin/users/{id}/ban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Ban an account (affects all users under the account)",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Bans an entire account with PERMANENT or TIMED ban. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"type":   map[string]interface{}{"type": "string", "enum": []string{"PERMANENT", "TIMED"}},
							"reason": map[string]interface{}{"type": "string"},
							"until":  map[string]interface{}{"type": "string", "format": "date-time", "description": "Required when type=TIMED"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account banned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/users/{id}/unban": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unban an account",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Removes an account's ban. Actor is derived from the caller's access token.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"reason": map[string]interface{}{"type": "string"},
						}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account unbanned"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/users/{id}/bans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List bans for an account",
					"description": "Requires ADMIN:NAMESPACE:*:ACCOUNT READ. Returns current and historical bans for the account.",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Account bans list"}, "401": map[string]interface{}{"description": "Unauthorized"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create or update a role in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_CREATE. Note: Namespace name must be uppercase A–Z only.",
					"parameters":  []map[string]interface{}{{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"name":        map[string]interface{}{"type": "string"},
							"roleType":    map[string]interface{}{"type": "string", "enum": []string{"USER", "CLIENT"}},
							"permissions": map[string]interface{}{"type": "object", "additionalProperties": true},
							"description": map[string]interface{}{"type": "string"},
						}, "required": []string{"name", "roleType"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
				"get": map[string]interface{}{
					"summary":     "List roles in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_READ.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "roleType", "in": "query", "schema": map[string]interface{}{"type": "string", "enum": []string{"USER", "CLIENT"}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}": map[string]interface{}{
				"delete": map[string]interface{}{
					"summary":     "Delete a role",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_DELETE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/users/{userId}": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to a user",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/clients/{clientId}": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to a client",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "clientId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			"/iam/v1/admin/namespaces/{ns}/roles/{id}/assign-all-users": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Assign role to all users in a namespace",
					"description": "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE.",
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}},
				},
			},
			// Platform endpoints
			"/iam/v1/oauth/admin/namespaces/{ns}/users/{userId}/platforms/{platformId}/platformToken": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Retrieve third-party platform token for a user",
					"description": "Retrieves the stored platform token for a user's linked platform account. Requires platform:read or admin scope.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace"},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "User ID"},
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., steam, google, facebook)"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Platform token retrieved successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Platform account not found"},
					},
				},
			},
			"/iam/v1/oauth/admin/namespaces/{ns}/users/{userId}/platforms": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List linked platform accounts for a user",
					"description": "Returns all platform accounts linked to the specified user. Requires platform:read or admin scope.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "ns", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace"},
						{"name": "userId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "User ID"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of platform accounts"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/iam/v1/oauth/platforms/{platformId}/authorize": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Initiate platform OAuth authorization",
					"description": "Initiates the OAuth authorization flow with a third-party platform. Returns a redirect URL to the platform's login page.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., google, facebook, discord)"},
						{"name": "request_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "UUID4 without hyphens identifying the authorization request"},
					},
					"responses": map[string]interface{}{
						"302": map[string]interface{}{"description": "Redirect to platform authorization URL"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/platforms/{platformId}/authenticate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Platform OAuth callback",
					"description": "Handles the OAuth callback from third-party platforms after user authorization.",
					"tags":        []string{"Platform"},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID"},
						{"name": "code", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Authorization code from platform"},
						{"name": "state", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "State parameter (request_id)"},
						{"name": "error", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Error code if authorization failed"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Authentication successful"},
						"400": map[string]interface{}{"description": "Invalid request or authorization denied"},
					},
				},
			},
			"/iam/v1/oauth/platforms/{platformId}/token": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Exchange platform credentials for IAM token",
					"description": "Authenticates a user using third-party platform credentials (platform_token or device_id) and returns IAM access tokens. Requires Basic Auth with client credentials.",
					"tags":        []string{"Platform"},
					"security":    []map[string]interface{}{{"basicAuth": []interface{}{}}},
					"parameters": []map[string]interface{}{
						{"name": "platformId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Platform ID (e.g., steam, google, facebook, device)"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/x-www-form-urlencoded": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"platform_token":  map[string]interface{}{"type": "string", "description": "Token from platform authentication (required if device_id not provided)"},
										"device_id":       map[string]interface{}{"type": "string", "description": "Device identifier (required if platform_token not provided)"},
										"createHeadless":  map[string]interface{}{"type": "boolean", "description": "Create headless account if not linked (default: true)"},
										"skipSetCookie":   map[string]interface{}{"type": "boolean", "description": "Skip setting cookies in response (default: false)"},
										"mac_address":     map[string]interface{}{"type": "string", "description": "MAC address of the device"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Access token issued successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"401": map[string]interface{}{"description": "Unauthorized or not_linked error"},
						"403": map[string]interface{}{"description": "User banned"},
						"503": map[string]interface{}{"description": "Platform service unavailable"},
					},
				},
			},
			// Account Linking endpoints
			"/iam/v1/admin/users/{id}/link": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Link a HEADLESS account to a HEAD account",
					"description": "Links a HEADLESS account to a HEAD account, making the HEAD account a FULL account. The HEADLESS account becomes ORPHAN.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID (target)"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace":           map[string]interface{}{"type": "string", "description": "Namespace to link"},
							"headless_account_id": map[string]interface{}{"type": "string", "description": "HEADLESS account ID (source)"},
						}, "required": []string{"namespace", "headless_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Account linked successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"409": map[string]interface{}{"description": "Link not eligible - conflict detected"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/unlink": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Unlink a platform from an account",
					"description": "Removes a specific platform credential from an account. Deletes from platform_users table to prevent platform login.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace":           map[string]interface{}{"type": "string", "description": "Namespace of the platform"},
							"provider_type":       map[string]interface{}{"type": "string", "description": "Platform provider type (e.g., google, steam)"},
							"provider_account_id": map[string]interface{}{"type": "string", "description": "Platform account ID"},
						}, "required": []string{"namespace", "provider_type", "provider_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Platform unlinked successfully"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"500": map[string]interface{}{"description": "Internal server error"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link/check": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Check link eligibility",
					"description": "Checks if a HEAD account can link a HEADLESS account. Returns eligibility status and conflict information if any.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID"},
						{"name": "namespace", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Namespace to check"},
						{"name": "headless_account_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEADLESS account ID"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Eligibility check result"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/platforms": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List linked platforms for an account",
					"description": "Returns all platform accounts linked to the specified account. Can filter by namespace.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Account ID"},
						{"name": "namespace", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "Filter by namespace"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of linked platforms"},
						"500": map[string]interface{}{"description": "Internal server error"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link-code": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Generate a link code for a HEADLESS account",
					"description": "Generates a one-time link code that can be used to link a HEADLESS account to a HEAD account. Code expires in 10 minutes.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEADLESS account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"namespace": map[string]interface{}{"type": "string", "description": "Namespace for the link code"},
						}, "required": []string{"namespace"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Link code generated"},
						"400": map[string]interface{}{"description": "Invalid request"},
						"404": map[string]interface{}{"description": "Account not found"},
					},
				},
			},
			"/iam/v1/admin/link-codes/{code}/validate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Validate a link code",
					"description": "Validates a link code without using it. Returns code information if valid.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "code", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Link code to validate"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Validation result"},
					},
				},
			},
			"/iam/v1/admin/users/{id}/link-with-code": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Link account using a link code",
					"description": "Links a HEAD account to a HEADLESS account using a one-time link code.",
					"tags":        []string{"Account Linking"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "HEAD account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"code": map[string]interface{}{"type": "string", "description": "Link code from HEADLESS account"},
						}, "required": []string{"code"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Account linked successfully"},
						"400": map[string]interface{}{"description": "Invalid or expired code"},
						"409": map[string]interface{}{"description": "Link not eligible - conflict detected"},
					},
				},
			},
			// Account Merge endpoints
			"/iam/v1/admin/accounts/{id}/merge/check": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Check merge eligibility",
					"description": "Checks if source account can be merged into target account. Returns eligibility status, conflicts, and namespaces to be merged.",
					"tags":        []string{"Account Merge"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Target account ID"},
						{"name": "source_account_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Source account ID to merge from"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Merge eligibility result"},
						"400": map[string]interface{}{"description": "Invalid request"},
					},
				},
			},
			"/iam/v1/admin/accounts/{id}/merge": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Merge accounts",
					"description": "Merges source account into target account. All BODY users from source are moved to target. Requires conflict resolutions if conflicts exist.",
					"tags":        []string{"Account Merge"},
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}, "description": "Target account ID"},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"source_account_id":    map[string]interface{}{"type": "string", "description": "Source account ID to merge from"},
							"conflict_resolutions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"namespace": map[string]interface{}{"type": "string"}, "keep": map[string]interface{}{"type": "string", "enum": []string{"SOURCE", "TARGET"}}}}, "description": "Resolution for each conflicting namespace"},
						}, "required": []string{"source_account_id"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Merge successful"},
						"400": map[string]interface{}{"description": "Invalid request or merge not eligible"},
						"409": map[string]interface{}{"description": "Conflicts require resolution"},
					},
				},
			},
			// Password Reset endpoints
			"/iam/v1/public/users/forgot-password": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Request password reset",
					"description": "Initiates password reset flow by sending a 6-digit code to the user's email. Rate limited to 3 requests per 5 minutes per email.",
					"tags":        []string{"Password Reset"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"email": map[string]interface{}{"type": "string", "format": "email", "description": "Email address associated with the account"},
						}, "required": []string{"email"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Reset code sent (or account not found - same response for security)"},
						"400": map[string]interface{}{"description": "Invalid email format"},
						"429": map[string]interface{}{"description": "Rate limited - too many requests"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
			"/iam/v1/public/users/reset-password/validate": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Validate reset code",
					"description": "Validates a password reset code without consuming it. Does not increment failed attempt counter.",
					"tags":        []string{"Password Reset"},
					"parameters": []map[string]interface{}{
						{"name": "email", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "format": "email"}, "description": "Email address"},
						{"name": "code", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "pattern": "^[0-9]{6}$"}, "description": "6-digit reset code"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Validation result with valid status, reason, and remaining attempts"},
						"400": map[string]interface{}{"description": "Missing email or code"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
			"/iam/v1/public/users/reset-password": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Reset password",
					"description": "Resets user password using a valid reset code. Increments failed attempt counter on wrong code (max 5 attempts, then 30-minute lockout).",
					"tags":        []string{"Password Reset"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
							"email":        map[string]interface{}{"type": "string", "format": "email", "description": "Email address"},
							"code":         map[string]interface{}{"type": "string", "pattern": "^[0-9]{6}$", "description": "6-digit reset code"},
							"new_password": map[string]interface{}{"type": "string", "minLength": 8, "description": "New password (minimum 8 characters)"},
						}, "required": []string{"email", "code", "new_password"}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Password reset successful"},
						"400": map[string]interface{}{"description": "Invalid request, code, or password requirements not met"},
						"429": map[string]interface{}{"description": "Account locked due to too many failed attempts"},
						"501": map[string]interface{}{"description": "Password reset not configured"},
					},
				},
			},
		},
		"components": map[string]interface{}{"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}}},
	}
	if s.Config != nil && s.Config.OIDCEnabled {
		paths := spec["paths"].(map[string]interface{})
		paths["/.well-known/openid-configuration"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC Discovery", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "OpenID Provider Metadata"}}},
		}
		paths["/.well-known/jwks.json"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC JWKS", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "JSON Web Key Set"}}},
		}
		paths["/oauth/userinfo"] = map[string]interface{}{
			"get": map[string]interface{}{"summary": "OIDC UserInfo", "responses": map[string]interface{}{"200": map[string]interface{}{"description": "User claims"}, "401": map[string]interface{}{"description": "Unauthorized"}}},
		}
	}
	paths := spec["paths"].(map[string]interface{})
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/clients"].(map[string]interface{}); ok {
		// annotate GET
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_READ. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := get["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
		// annotate POST
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_CREATE. Upserts client with permissions. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/clients/{id}/permissions"].(map[string]interface{}); ok {
		if put, ok2 := p["put"].(map[string]interface{}); ok2 {
			put["description"] = "Requires ADMIN:NAMESPACE:{ns}:CLIENT_UPDATE. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := put["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/users/{id}/ban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Bans a user with PERMANENT or TIMED ban. Actor is derived from the caller's access token. Namespace name must be uppercase A–Z only."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/users/{id}/unban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:USER UPDATE. Removes a user's ban in the namespace. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/users/{id}/ban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Bans an entire account with PERMANENT or TIMED ban. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/users/{id}/unban"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:*:ACCOUNT UPDATE. Removes an account's ban. Actor is derived from the caller's access token."
			if rb, ok3 := post["requestBody"].(map[string]interface{}); ok3 {
				if content, ok4 := rb["content"].(map[string]interface{}); ok4 {
					if appjson, ok5 := content["application/json"].(map[string]interface{}); ok5 {
						if schema, ok6 := appjson["schema"].(map[string]interface{}); ok6 {
							if props, ok7 := schema["properties"].(map[string]interface{}); ok7 {
								delete(props, "actor_id")
							}
						}
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles"].(map[string]interface{}); ok {
		// annotate GET
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_READ."
			if params, ok3 := get["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
		// annotate POST
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_CREATE. Note: Namespace name must be uppercase A–Z only."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}"].(map[string]interface{}); ok {
		if delete, ok2 := p["delete"].(map[string]interface{}); ok2 {
			delete["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_DELETE."
			if params, ok3 := delete["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/users/{userId}"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/clients/{clientId}"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	if p, ok := paths["/iam/v1/admin/namespaces/{ns}/roles/{id}/assign-all-users"].(map[string]interface{}); ok {
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["description"] = "Requires ADMIN:NAMESPACE:{ns}:ROLE_UPDATE."
			if params, ok3 := post["parameters"].([]map[string]interface{}); ok3 {
				for i := range params {
					if params[i]["name"] == "ns" {
						params[i]["description"] = "Namespace (uppercase A–Z only)."
					}
				}
			}
		}
	}
	// Annotate authorize path: Implicit disabled
	if p, ok := paths["/oauth/authorize"].(map[string]interface{}); ok {
		// ensure GET description mentions implicit disabled
		if get, ok2 := p["get"].(map[string]interface{}); ok2 {
			get["summary"] = "Authorize (Authorization Code + PKCE)"
			get["description"] = "Implicit flow (response_type=token) is disabled. Use Authorization Code with PKCE and state."
		}
		if post, ok2 := p["post"].(map[string]interface{}); ok2 {
			post["summary"] = "Authorize (Authorization Code + PKCE)"
			post["description"] = "Implicit flow (response_type=token) is disabled. Use Authorization Code with PKCE and state."
		}
	}
	c.Header("Content-Type", "application/json;charset=UTF-8")
	c.Status(http.StatusOK)
	_ = json.NewEncoder(c.Writer).Encode(spec)
}

// HandleSwaggerUIGin serves a minimal Swagger UI via Gin.
func (s *Server) HandleSwaggerUIGin(c *gin.Context) {
	if c.Request.Method != http.MethodGet {
		c.Status(http.StatusMethodNotAllowed)
		return
	}
	html := `<!doctype html><html><head><meta charset="utf-8"/><title>Swagger UI</title>
	<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
	</head><body><div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
	<script>window.ui = SwaggerUIBundle({ url: '/swagger.json', dom_id: '#swagger-ui' });</script>
	</body></html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write([]byte(html))
}
