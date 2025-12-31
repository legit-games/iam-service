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

	// /oauth/authorize with session form restore middleware
	r.GET("/oauth/authorize", restoreAuthorizeFormMiddleware(), func(c *gin.Context) {
		wrapGinHandler(c, s.HandleAuthorizeRequest)
	})
	r.POST("/oauth/authorize", restoreAuthorizeFormMiddleware(), func(c *gin.Context) {
		wrapGinHandler(c, s.HandleAuthorizeRequest)
	})

	// Token endpoint(s)
	r.POST("/oauth/token", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleTokenRequest)
	})
	if s.Config != nil && s.Config.AllowGetAccessRequest {
		r.GET("/oauth/token", func(c *gin.Context) {
			wrapGinHandler(c, s.HandleTokenRequest)
		})
	}

	// Introspect & Revoke
	r.POST("/oauth/introspect", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleIntrospectionRequest)
	})
	r.POST("/oauth/revoke", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleRevocationRequest)
	})

	// Dynamic client registration
	r.POST("/register", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleClientRegistrationRequest)
	})

	// Swagger endpoints
	r.GET("/swagger.json", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleSwaggerJSON)
	})
	r.GET("/swagger", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleSwaggerUI)
	})

	// JSON API routes required by tests
	r.POST("/api/login", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleAPILogin)
	})
	// Public user registration
	r.POST("/iam/v1/public/users", func(c *gin.Context) {
		wrapGinHandler(c, s.HandleAPIRegisterUser)
	})

	return r
}

// wrapGinHandler adapts existing handlers (http.ResponseWriter, *http.Request) to Gin.
func wrapGinHandler(c *gin.Context, h func(http.ResponseWriter, *http.Request) error) {
	// Let Gin continue processing the standard library request
	_ = h(c.Writer, c.Request)
	// Stop further handlers (including default 404) from running
	c.Abort()
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
