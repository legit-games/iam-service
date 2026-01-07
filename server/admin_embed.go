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

		// Normalize the filepath
		if filepath == "/" || filepath == "" {
			filepath = "/index.html"
		}

		// Remove leading slash for fs.Open
		cleanPath := strings.TrimPrefix(filepath, "/")

		// Check if file exists
		f, err := distFS.Open(cleanPath)
		if err != nil {
			// SPA fallback: serve index.html for client-side routing
			c.FileFromFS("/index.html", http.FS(distFS))
			return
		}
		f.Close()

		// Serve the file
		c.FileFromFS(filepath, http.FS(distFS))
	})
}
