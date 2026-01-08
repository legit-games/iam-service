//go:build !dev

package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed admin/dist/*
var adminFS embed.FS

// RegisterAdminRoutes adds the embedded admin console routes to the Gin engine.
// In production mode, this serves the pre-built React SPA from embedded files.
func RegisterAdminRoutes(r *gin.Engine) {
	// Get the dist subdirectory
	distFS, err := fs.Sub(adminFS, "admin/dist")
	if err != nil {
		// If admin/dist doesn't exist, admin console is not built - skip registration
		return
	}

	// Serve static files
	r.GET("/admin/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")

		// Normalize the filepath - serve index.html for root path
		if filepath == "/" || filepath == "" {
			indexData, err := fs.ReadFile(distFS, "index.html")
			if err != nil {
				c.String(http.StatusNotFound, "index.html not found")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexData)
			return
		}

		// Remove leading slash for fs.Open
		cleanPath := strings.TrimPrefix(filepath, "/")

		// Check if file exists
		f, err := distFS.Open(cleanPath)
		if err != nil {
			// SPA fallback: serve index.html for client-side routing
			indexData, err := fs.ReadFile(distFS, "index.html")
			if err != nil {
				c.String(http.StatusNotFound, "index.html not found")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexData)
			return
		}
		f.Close()

		// Serve the file with proper content type
		c.FileFromFS(filepath, http.FS(distFS))
	})
}
