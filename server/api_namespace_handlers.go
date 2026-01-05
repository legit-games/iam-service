package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CreateNamespaceRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

func (s *Server) handleCreateNamespace(c *gin.Context) {
	var req CreateNamespaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	id, err := s.nsStore.Create(c.Request.Context(), req.Name, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "name": req.Name})
}
