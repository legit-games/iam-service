package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/store"
)

// RevocationListResponse is the API response for the revocation list.
type RevocationListResponse struct {
	RevokedTokens store.RevocationList `json:"revoked_tokens"`
	RevokedUsers  []store.UserRevocationRecord `json:"revoked_users"`
}

// RevokeTokenRequest is the request body for revoking a token.
type RevokeTokenRequest struct {
	Token string `json:"token" form:"token" binding:"required"`
}

// RevokeUserRequest is the request body for revoking all user tokens.
type RevokeUserRequest struct {
	UserID    string `json:"user_id" binding:"required"`
	Reason    string `json:"reason"`
	ExpiresIn int    `json:"expires_in"` // seconds, 0 means default TTL
}

// RevokeUserResponse is the response for revoking user tokens.
type RevokeUserResponse struct {
	Success   bool      `json:"success"`
	UserID    string    `json:"user_id"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Message   string    `json:"message"`
}

// HandleGetRevocationListGin returns the token revocation list.
// GET /oauth/revocationlist
// @Summary Get token revocation list
// @Description Returns a list of revoked users and revoked tokens in bloom filter format.
// @Description The bloom filter uses MurmurHash3 algorithm for hashing the values.
// @Tags OAuth2.0
// @Produce json
// @Success 200 {object} store.RevocationList
// @Failure 500 {object} map[string]interface{}
// @Router /oauth/revocationlist [get]
func (s *Server) HandleGetRevocationListGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	revocationList, err := s.revocationStore.GetRevocationList(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to get revocation list: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, revocationList)
}

// HandleRevokeTokenGin revokes a specific token.
// POST /oauth/revoke
// @Summary Revoke a token
// @Description Revokes a specific access or refresh token.
// @Tags OAuth2.0
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "The token to revoke"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /oauth/revoke [post]
func (s *Server) HandleRevokeTokenGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	var req RevokeTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token is required",
		})
		return
	}

	// Parse the token to get its expiration time
	// For now, use default TTL
	expiresAt := time.Now().UTC().Add(s.revocationStore.GetConfig().TokenTTL)

	// Try to get user ID and client ID from the token if it's a JWT
	var userID, clientID *string
	ti, err := s.Manager.LoadAccessToken(c.Request.Context(), req.Token)
	if err == nil && ti != nil {
		uid := ti.GetUserID()
		cid := ti.GetClientID()
		if uid != "" {
			userID = &uid
		}
		if cid != "" {
			clientID = &cid
		}
		// Use the token's actual expiration if available
		if ti.GetAccessExpiresIn() > 0 {
			expiresAt = ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn())
		}
	}

	// Revoke the token
	if err := s.revocationStore.RevokeToken(c.Request.Context(), req.Token, userID, clientID, "manual_revocation", expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to revoke token: " + err.Error(),
		})
		return
	}

	// Also remove from token store if possible
	if s.Manager != nil {
		_ = s.Manager.RemoveAccessToken(c.Request.Context(), req.Token)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "token has been revoked",
	})
}

// HandleRevokeUserTokensGin revokes all tokens for a user.
// POST /iam/v1/admin/namespaces/:ns/revoke/users/:userId
// @Summary Revoke all user tokens
// @Description Revokes all tokens for a specific user.
// @Tags IAM Admin
// @Accept json
// @Produce json
// @Param ns path string true "Namespace"
// @Param userId path string true "User ID"
// @Param body body RevokeUserRequest true "Revocation details"
// @Success 200 {object} RevokeUserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Security BearerAuth
// @Router /iam/v1/admin/namespaces/{ns}/revoke/users/{userId} [post]
func (s *Server) HandleRevokeUserTokensGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	userID := c.Param("userId")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	var req RevokeUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Use path param if body is empty
		req.UserID = userID
	}
	if req.UserID == "" {
		req.UserID = userID
	}

	reason := req.Reason
	if reason == "" {
		reason = "admin_action"
	}

	now := time.Now().UTC()
	var expiresAt time.Time
	if req.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(req.ExpiresIn) * time.Second)
		if err := s.revocationStore.RevokeUserWithExpiry(c.Request.Context(), req.UserID, reason, expiresAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "failed to revoke user tokens: " + err.Error(),
			})
			return
		}
	} else {
		expiresAt = now.Add(s.revocationStore.GetConfig().UserRevocationTTL)
		if err := s.revocationStore.RevokeUser(c.Request.Context(), req.UserID, reason); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "failed to revoke user tokens: " + err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, RevokeUserResponse{
		Success:   true,
		UserID:    req.UserID,
		RevokedAt: now,
		ExpiresAt: expiresAt,
		Message:   "all tokens for user have been revoked",
	})
}

// HandleRemoveUserRevocationGin removes the user revocation (e.g., when ban is lifted).
// DELETE /iam/v1/admin/namespaces/:ns/revoke/users/:userId
// @Summary Remove user revocation
// @Description Removes the revocation for a user, allowing their tokens to be valid again.
// @Tags IAM Admin
// @Produce json
// @Param ns path string true "Namespace"
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Security BearerAuth
// @Router /iam/v1/admin/namespaces/{ns}/revoke/users/{userId} [delete]
func (s *Server) HandleRemoveUserRevocationGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	userID := c.Param("userId")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	if err := s.revocationStore.RemoveUserRevocation(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to remove user revocation: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user_id": userID,
		"message": "user revocation has been removed",
	})
}

// HandleCheckTokenRevocationGin checks if a token is revoked.
// GET /oauth/revoke/check
// @Summary Check if token is revoked
// @Description Checks if a specific token has been revoked.
// @Tags OAuth2.0
// @Produce json
// @Param token query string true "The token to check"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /oauth/revoke/check [get]
func (s *Server) HandleCheckTokenRevocationGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token query parameter is required",
		})
		return
	}

	isRevoked, err := s.revocationStore.IsTokenRevoked(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to check token: " + err.Error(),
		})
		return
	}

	// Also check if the user is revoked
	var userRevoked bool
	var userRevokedAt *time.Time
	ti, err := s.Manager.LoadAccessToken(c.Request.Context(), token)
	if err == nil && ti != nil && ti.GetUserID() != "" {
		userRevokedAt, err = s.revocationStore.IsUserRevoked(c.Request.Context(), ti.GetUserID())
		if err == nil && userRevokedAt != nil {
			// Check if the token was issued before the user was revoked
			if ti.GetAccessCreateAt().Before(*userRevokedAt) {
				userRevoked = true
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"revoked":           isRevoked || userRevoked,
		"token_revoked":     isRevoked,
		"user_revoked":      userRevoked,
		"user_revoked_at":   userRevokedAt,
	})
}

// HandleCheckUserRevocationGin checks if a user's tokens are revoked.
// GET /iam/v1/admin/namespaces/:ns/revoke/users/:userId/status
// @Summary Check user revocation status
// @Description Checks if a user's tokens are currently revoked.
// @Tags IAM Admin
// @Produce json
// @Param ns path string true "Namespace"
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Security BearerAuth
// @Router /iam/v1/admin/namespaces/{ns}/revoke/users/{userId}/status [get]
func (s *Server) HandleCheckUserRevocationGin(c *gin.Context) {
	if s.revocationStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "revocation service is not configured",
		})
		return
	}

	userID := c.Param("userId")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	revokedAt, err := s.revocationStore.IsUserRevoked(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to check user revocation: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"revoked":    revokedAt != nil,
		"revoked_at": revokedAt,
	})
}
