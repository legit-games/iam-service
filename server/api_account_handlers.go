package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CreateHeadAccountRequest struct {
	AccountID    string `json:"account_id" binding:"required"`
	Username     string `json:"username" binding:"required"`
	PasswordHash string `json:"password_hash" binding:"required"`
}

func (s *Server) handleCreateHeadAccount(c *gin.Context) {
	var req CreateHeadAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	if err := s.userStore.CreateHeadAccount(c.Request.Context(), req.AccountID, req.Username, req.PasswordHash); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"account_id": req.AccountID})
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

func errorResponse(err error) map[string]string { return map[string]string{"error": err.Error()} }
