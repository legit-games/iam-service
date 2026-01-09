package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type CreateHeadAccountRequest struct {
	AccountID    string  `json:"account_id" binding:"required"`
	Username     string  `json:"username" binding:"required"`
	PasswordHash string  `json:"password_hash" binding:"required"`
	Email        *string `json:"email"`
}

func (s *Server) handleCreateHeadAccount(c *gin.Context) {
	var req CreateHeadAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	// Validate and normalize email if provided
	var email *string
	if req.Email != nil {
		trimmedEmail := strings.TrimSpace(*req.Email)
		if trimmedEmail != "" {
			if !isValidEmail(trimmedEmail) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid email format"})
				return
			}
			email = &trimmedEmail
		}
	}

	userID, err := s.userStore.CreateHeadAccount(c.Request.Context(), req.AccountID, req.Username, req.PasswordHash, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": userID})
}

type CreateHeadlessAccountRequest struct {
	AccountID         string `json:"account_id" binding:"required"`
	Namespace         string `json:"namespace" binding:"required"`
	ProviderType      string `json:"provider_type" binding:"required"`
	ProviderAccountID string `json:"provider_account_id" binding:"required"`
}

func (s *Server) handleCreateHeadlessAccount(c *gin.Context) {
	var req CreateHeadlessAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	if err := s.userStore.CreateHeadlessAccount(c.Request.Context(), req.AccountID, req.Namespace, req.ProviderType, req.ProviderAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"account_id": req.AccountID})
}

type LinkAccountRequest struct {
	Namespace         string `json:"namespace" binding:"required"`
	HeadlessAccountID string `json:"headless_account_id" binding:"required"`
}

func (s *Server) handleLinkAccount(c *gin.Context) {
	headAccountID := c.Param("id")
	var req LinkAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	if err := s.userStore.Link(c.Request.Context(), req.Namespace, headAccountID, req.HeadlessAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": true})
}

type UnlinkAccountRequest struct {
	Namespace         string `json:"namespace" binding:"required"`
	ProviderType      string `json:"provider_type" binding:"required"`
	ProviderAccountID string `json:"provider_account_id" binding:"required"`
}

func (s *Server) handleUnlinkAccount(c *gin.Context) {
	accountID := c.Param("id")
	var req UnlinkAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	if err := s.userStore.Unlink(c.Request.Context(), accountID, req.Namespace, req.ProviderType, req.ProviderAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"unlinked": true})
}

// HandleGetUserPermissionsGin returns the permissions for a user
func (s *Server) HandleGetUserPermissionsGin(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "user ID is required"})
		return
	}

	db, err := s.GetIAMReadDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var permissionsJSON []byte
	row := db.WithContext(c.Request.Context()).Raw(`SELECT COALESCE(permissions, '[]'::jsonb) FROM users WHERE id = $1`, userID).Row()
	if err := row.Scan(&permissionsJSON); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	var permissions []string
	if err := json.Unmarshal(permissionsJSON, &permissions); err != nil {
		permissions = []string{}
	}

	c.JSON(http.StatusOK, gin.H{"user_id": userID, "permissions": permissions})
}

// HandleUpdateUserPermissionsGin updates the permissions for a user
func (s *Server) HandleUpdateUserPermissionsGin(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "user ID is required"})
		return
	}

	var req struct {
		Permissions []string `json:"permissions" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if req.Permissions == nil {
		req.Permissions = []string{}
	}

	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var exists int
	row := db.WithContext(c.Request.Context()).Raw(`SELECT 1 FROM users WHERE id = $1`, userID).Row()
	if err := row.Scan(&exists); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	permissionsJSON, err := json.Marshal(req.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to encode permissions"})
		return
	}

	result := db.WithContext(c.Request.Context()).Exec(`UPDATE users SET permissions = $1 WHERE id = $2`, permissionsJSON, userID)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": result.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user_id": userID, "permissions": req.Permissions})
}

// HandleAddUserPermissionsGin adds permissions to a user (without removing existing ones)
func (s *Server) HandleAddUserPermissionsGin(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "user ID is required"})
		return
	}

	var req struct {
		Permissions []string `json:"permissions" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if len(req.Permissions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "permissions array cannot be empty"})
		return
	}

	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var permissionsJSON []byte
	row := db.WithContext(c.Request.Context()).Raw(`SELECT COALESCE(permissions, '[]'::jsonb) FROM users WHERE id = $1`, userID).Row()
	if err := row.Scan(&permissionsJSON); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	var currentPerms []string
	if err := json.Unmarshal(permissionsJSON, &currentPerms); err != nil {
		currentPerms = []string{}
	}

	permSet := make(map[string]bool)
	for _, p := range currentPerms {
		permSet[p] = true
	}
	for _, p := range req.Permissions {
		permSet[p] = true
	}

	newPerms := make([]string, 0, len(permSet))
	for p := range permSet {
		newPerms = append(newPerms, p)
	}

	newPermsJSON, _ := json.Marshal(newPerms)
	result := db.WithContext(c.Request.Context()).Exec(`UPDATE users SET permissions = $1 WHERE id = $2`, newPermsJSON, userID)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": result.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user_id": userID, "permissions": newPerms})
}

// HandleRemoveUserPermissionsGin removes specific permissions from a user
func (s *Server) HandleRemoveUserPermissionsGin(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "user ID is required"})
		return
	}

	var req struct {
		Permissions []string `json:"permissions" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if len(req.Permissions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "permissions array cannot be empty"})
		return
	}

	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var permissionsJSON []byte
	row := db.WithContext(c.Request.Context()).Raw(`SELECT COALESCE(permissions, '[]'::jsonb) FROM users WHERE id = $1`, userID).Row()
	if err := row.Scan(&permissionsJSON); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	var currentPerms []string
	if err := json.Unmarshal(permissionsJSON, &currentPerms); err != nil {
		currentPerms = []string{}
	}

	removeSet := make(map[string]bool)
	for _, p := range req.Permissions {
		removeSet[p] = true
	}

	newPerms := make([]string, 0)
	for _, p := range currentPerms {
		if !removeSet[p] {
			newPerms = append(newPerms, p)
		}
	}

	newPermsJSON, _ := json.Marshal(newPerms)
	result := db.WithContext(c.Request.Context()).Exec(`UPDATE users SET permissions = $1 WHERE id = $2`, newPermsJSON, userID)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": result.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user_id": userID, "permissions": newPerms})
}

func errorResponse(err error) map[string]string { return map[string]string{"error": err.Error()} }
