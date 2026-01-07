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

func (s *Server) handleListNamespaces(c *gin.Context) {
	namespaces, err := s.nsStore.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, namespaces)
}

func (s *Server) handleGetNamespace(c *gin.Context) {
	name := c.Param("ns")
	if name == "" {
		c.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("namespace parameter required")))
		return
	}

	// Normalize name to uppercase for lookup
	upperName := strings.ToUpper(strings.TrimSpace(name))

	ns, err := s.nsStore.GetByName(c.Request.Context(), upperName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	if ns == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "namespace not found"})
		return
	}
	c.JSON(http.StatusOK, ns)
}

type UpdateNamespaceRequest struct {
	Description string `json:"description"`
	Active      *bool  `json:"active"`
}

func (s *Server) handleUpdateNamespace(c *gin.Context) {
	name := c.Param("ns")
	if name == "" {
		c.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("namespace parameter required")))
		return
	}

	// Normalize name to uppercase for lookup
	upperName := strings.ToUpper(strings.TrimSpace(name))

	// Check if namespace exists
	ns, err := s.nsStore.GetByName(c.Request.Context(), upperName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	if ns == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "namespace not found"})
		return
	}

	var req UpdateNamespaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	// Use existing active value if not provided
	active := ns.Active
	if req.Active != nil {
		active = *req.Active
	}

	if err := s.nsStore.Update(c.Request.Context(), upperName, req.Description, active); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Return updated namespace
	updatedNs, err := s.nsStore.GetByName(c.Request.Context(), upperName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, updatedNs)
}
