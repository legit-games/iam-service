package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
)

type CreateNamespaceRequest struct {
	Name        string               `json:"name" binding:"required"`
	Type        models.NamespaceType `json:"type" binding:"required"` // 'publisher' or 'game'
	Description string               `json:"description"`
}

func (s *Server) handleCreateNamespace(c *gin.Context) {
	var req CreateNamespaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	// validate enum-like type
	if !req.Type.IsValid() {
		c.JSON(http.StatusBadRequest, errorResponse(errInvalidNamespaceType()))
		return
	}
	// normalize name to uppercase for storage
	upperName := strings.ToUpper(strings.TrimSpace(req.Name))
	if upperName == "" {
		c.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("name must not be empty")))
		return
	}
	// allow only English letters A-Z
	if !regexp.MustCompile(`^[A-Z]+$`).MatchString(upperName) {
		c.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("invalid namespace name: only English letters A-Z are allowed")))
		return
	}
	// Duplicate name check (against uppercase stored names)
	if existing, err := s.nsStore.GetByName(c.Request.Context(), upperName); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	} else if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "namespace already exists", "id": existing.ID})
		return
	}
	id, err := s.nsStore.Create(c.Request.Context(), upperName, string(req.Type.Normalize()), req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "name": upperName, "type": req.Type.Normalize()})
}

func errInvalidNamespaceType() error {
	return fmt.Errorf("invalid namespace type: must be 'publisher' or 'game'")
}
