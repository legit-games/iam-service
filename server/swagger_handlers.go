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
					"description": "Adds or merges permissions array into the account's JSONB permissions field.",
					"parameters":  []map[string]interface{}{{"name": "accountId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "400": map[string]interface{}{"description": "Bad Request"}},
				},
			},
		},
		"components": map[string]interface{}{"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}}},
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
					"description": "Adds or merges permissions array into the account's JSONB permissions field.",
					"parameters":  []map[string]interface{}{{"name": "accountId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "required": []string{"permissions"}}}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "OK"}, "400": map[string]interface{}{"description": "Bad Request"}},
				},
			},
		},
		"components": map[string]interface{}{"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}}},
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
