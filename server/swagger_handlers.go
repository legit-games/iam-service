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
			"/iam/v1/admin/accounts/{accountId}/permissions": map[string]interface{}{
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
			"/iam/v1/admin/accounts/{accountId}/permissions": map[string]interface{}{
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
