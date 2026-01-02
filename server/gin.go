package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// NewGinEngine builds a Gin router and registers all default OAuth2 routes.
// This is additive and does not affect the existing net/http mux-based wiring.
func NewGinEngine(s *Server) *gin.Engine {
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.Use(gin.Recovery())
	r.Use(parseFormMiddleware())

	// /oauth/authorize with session form restore middleware (keep standard handler)
	r.GET("/oauth/authorize", restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))
	r.POST("/oauth/authorize", restoreAuthorizeFormMiddleware(), ginFrom(s.HandleAuthorizeRequest))

	// Token endpoint(s) (keep standard handler)
	r.POST("/oauth/token", ginFrom(s.HandleTokenRequest))
	if s.Config != nil && s.Config.AllowGetAccessRequest {
		r.GET("/oauth/token", ginFrom(s.HandleTokenRequest))
	}

	// Introspect & Revoke (keep standard handler)
	r.POST("/oauth/introspect", ginFrom(s.HandleIntrospectionRequest))
	r.POST("/oauth/revoke", ginFrom(s.HandleRevocationRequest))

	// Swagger endpoints (Gin-native)
	r.GET("/swagger.json", s.HandleSwaggerJSONGin)
	r.GET("/swagger", s.HandleSwaggerUIGin)

	// Dynamic client registration (Gin-native)
	r.POST("/iam/v1/oauth/clients", s.HandleClientRegistrationGin)

	// JSON API routes (Gin-native)
	r.POST("/iam/v1/public/login", s.HandleAPILoginGin)
	r.POST("/iam/v1/public/users", s.HandleAPIRegisterUserGin)

	r.POST("/iam/v1/admin/accounts/:accountId/permissions", s.HandleAPIAddAccountPermissionsGin)

	return r
}

// ginFrom adapts existing handlers (http.ResponseWriter, *http.Request) to a Gin handler.
func ginFrom(h func(http.ResponseWriter, *http.Request) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		_ = h(c.Writer, c.Request)
		c.Abort()
	}
}

// parseFormMiddleware ensures r.ParseForm() is called for urlencoded/multipart requests so r.FormValue works.
func parseFormMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		ct := r.Header.Get("Content-Type")
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if ct != "" {
				// Check common form content types
				if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
					_ = r.ParseForm()
				}
			}
		}
		c.Next()
	}
}

// restoreAuthorizeFormMiddleware restores saved authorize request form from session after login redirects.
func restoreAuthorizeFormMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if store, err := session.Start(c.Request.Context(), c.Writer, c.Request); err == nil {
			if v, ok := store.Get("ReturnUri"); ok {
				// support both url.Values and map[string][]string
				if form, ok2 := v.(map[string][]string); ok2 {
					c.Request.Form = form
				} else if vals, ok2 := v.(url.Values); ok2 {
					c.Request.Form = vals
				}
				store.Delete("ReturnUri")
				_ = store.Save()
			}
		}
		c.Next()
	}
}
