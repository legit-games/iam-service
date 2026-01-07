//go:build dev

package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterAdminRoutes proxies admin requests to the Vite dev server in development mode.
// This allows hot module replacement and fast refresh during development.
func RegisterAdminRoutes(r *gin.Engine) {
	// Proxy to Vite dev server
	viteURL, err := url.Parse("http://localhost:5173")
	if err != nil {
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(viteURL)

	// Custom director to preserve the original path
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = viteURL.Host
	}

	// Handle all admin routes
	r.Any("/admin/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// Also proxy Vite's websocket for HMR
	r.Any("/@vite/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	r.Any("/node_modules/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	r.Any("/src/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})
}
