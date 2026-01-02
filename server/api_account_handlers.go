package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// HandleAPIAddAccountPermissionsGin is a Gin-native handler to append permissions to an account's JSONB permissions column.
// POST /iam/v1/admin/accounts/:accountId/permissions
// Body: { "permissions": ["ADMIN:..._READ", ...] }
func (s *Server) HandleAPIAddAccountPermissionsGin(c *gin.Context) {
	accountID := strings.TrimSpace(c.Param("accountId"))
	if accountID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "accountId is required in path"})
		return
	}
	var payload struct {
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid JSON payload"})
		return
	}
	if len(payload.Permissions) == 0 {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "permissions array is required"})
		return
	}

	dsn := strings.TrimSpace(os.Getenv("USER_DB_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}
	if dsn == "" {
		c.JSON(501, gin.H{"error": "not_implemented", "error_description": "set USER_DB_DSN or MIGRATE_DSN"})
		return
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}

	// Load existing permissions
	var raw sql.NullString
	row := db.WithContext(c.Request.Context()).Raw(`SELECT permissions::text FROM accounts WHERE id=$1`, accountID).Row()
	if err := row.Scan(&raw); err != nil && err != sql.ErrNoRows {
		c.JSON(500, gin.H{"error": "server_error", "error_description": fmt.Sprintf("select permissions: %v", err)})
		return
	}
	// Merge unique
	existing := map[string]struct{}{}
	if raw.Valid && strings.TrimSpace(raw.String) != "" {
		var arr []string
		_ = json.Unmarshal([]byte(raw.String), &arr)
		for _, p := range arr {
			p = strings.TrimSpace(p)
			if p != "" {
				existing[p] = struct{}{}
			}
		}
	}
	for _, p := range payload.Permissions {
		p = strings.TrimSpace(p)
		if p != "" {
			existing[p] = struct{}{}
		}
	}
	// Build array
	merged := make([]string, 0, len(existing))
	for p := range existing {
		merged = append(merged, p)
	}
	buf, _ := json.Marshal(merged)

	// Update JSONB column
	if err := db.WithContext(c.Request.Context()).Exec(`UPDATE accounts SET permissions=$1::jsonb WHERE id=$2`, string(buf), accountID).Error; err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": fmt.Sprintf("update permissions: %v", err)})
		return
	}

	c.JSON(200, gin.H{"status": "ok"})
}
