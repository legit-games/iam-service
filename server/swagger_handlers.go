package server

import (
	"encoding/json"
	"net/http"
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
			"description": "OpenAPI for OAuth2 endpoints (RFC 6749, 6750, 7009, 7662, 7591).",
		},
		"servers": []map[string]interface{}{{"url": "/"}},
		"paths": map[string]interface{}{
			"/oauth/authorize":           s.swaggerAuthorizePath(),
			"/oauth/token":               s.swaggerTokenPath(),
			"/oauth/introspect":          s.swaggerIntrospectPath(),
			"/oauth/revoke":              s.swaggerRevokePath(),
			"/register":                  s.swaggerRegisterPath(),
			"/api/login":                 s.swaggerAPILoginPath(),
			"/api/register":              s.swaggerRegisterUserPath(),
			"/iam/v1/public/users":       s.swaggerRegisterUserPath(),
			"/iam/v1/public/users/login": s.swaggerAPILoginPath(),
			"/iam/v1/admin/users":        s.swaggerRegisterUserPath(),
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}},
		},
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
