package server

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
)

// Client registration/upsert and permission management (admin endpoints)

type UpsertClientRequest struct {
	ID          string   `json:"id" binding:"required"`
	Secret      string   `json:"secret" binding:"required"`
	Domain      string   `json:"domain" binding:"required"`
	UserID      string   `json:"user_id"`
	Public      bool     `json:"public"`
	Permissions []string `json:"permissions"`
}

type UpdateClientPermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

// HandleUpsertClientGin creates or updates a client record.
func (s *Server) HandleUpsertClientGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	var req UpsertClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	cliStore := s.getDBClientStore()
	if err := cliStore.Upsert(c.Request.Context(), &models.Client{ID: req.ID, Secret: req.Secret, Domain: req.Domain, UserID: req.UserID, Public: req.Public, Permissions: req.Permissions}); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": req.ID})
}

// HandleUpdateClientPermissionsGin replaces permissions for a client.
func (s *Server) HandleUpdateClientPermissionsGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	clientID := c.Param("id")
	var req UpdateClientPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	cliStore := s.getDBClientStore()
	if err := cliStore.UpdatePermissions(c.Request.Context(), clientID, req.Permissions); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": clientID, "permissions": req.Permissions})
}

// HandleGetClientGin returns a single client by id.
func (s *Server) HandleGetClientGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	id := c.Param("id")
	cliStore := s.getDBClientStore()
	ci, err := cliStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, errorResponse(err))
		return
	}
	r := ci.(*models.Client)
	c.JSON(http.StatusOK, gin.H{
		"id":          r.ID,
		"domain":      r.Domain,
		"user_id":     r.UserID,
		"public":      r.Public,
		"permissions": r.Permissions,
	})
}

// HandleListClientsGin returns paged clients with offset/limit.
func (s *Server) HandleListClientsGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	cliStore := s.getDBClientStore()
	list, err := cliStore.List(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, list)
}

// HandleDeleteClientGin deletes a client by id.
func (s *Server) HandleDeleteClientGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	id := c.Param("id")
	cliStore := s.getDBClientStore()
	if err := cliStore.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// helper: get DB client store
func (s *Server) getDBClientStore() *store.DBClientStore {
	db, _ := s.GetPrimaryDB()
	return store.NewDBClientStore(db)
}

// Keep existing 501 for dynamic registration if route not used
func (s *Server) HandleClientRegistrationRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	return NotImplemented(w, "dynamic client registration is disabled")
}

// HandleClientRegistrationGin responds with 501 Not Implemented.
func (s *Server) HandleClientRegistrationGin(c *gin.Context) {
	NotImplementedGin(c, "dynamic client registration is disabled")
}
