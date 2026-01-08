package server

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/dto"
)

// HandleUpsertClientGin creates or updates a client record.
func (s *Server) HandleUpsertClientGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	var req dto.UpsertClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	cliStore := s.getDBClientStore()
	if err := cliStore.Upsert(c.Request.Context(), &models.Client{ID: req.ID, Secret: req.Secret, Domain: req.Domain, UserID: req.UserID, Public: req.Public, Namespace: req.Namespace, Permissions: req.Permissions, Scopes: req.Scopes}); err != nil {
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
	var req dto.UpdateClientPermissionsRequest
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

// HandleUpdateClientScopesGin replaces scopes for a client.
func (s *Server) HandleUpdateClientScopesGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	clientID := c.Param("id")
	var req dto.UpdateClientScopesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	cliStore := s.getDBClientStore()
	if err := cliStore.UpdateScopes(c.Request.Context(), clientID, req.Scopes); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": clientID, "scopes": req.Scopes})
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
	c.JSON(http.StatusOK, dto.FromClient(r))
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
	c.JSON(http.StatusOK, dto.FromClients(list))
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

// HandleListClientsByNamespaceGin returns clients in a given namespace.
func (s *Server) HandleListClientsByNamespaceGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	ns := c.Param("ns")
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	cliStore := s.getDBClientStore()
	list, err := cliStore.ListByNamespace(c.Request.Context(), ns, offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, dto.FromClients(list))
}

// HandleUpsertClientByNamespaceGin creates or updates a client within a specific namespace.
func (s *Server) HandleUpsertClientByNamespaceGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	ns := c.Param("ns")
	var req dto.UpsertClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	// Override request namespace with path namespace for safety
	req.Namespace = ns
	cliStore := s.getDBClientStore()
	if err := cliStore.Upsert(c.Request.Context(), &models.Client{ID: req.ID, Secret: req.Secret, Domain: req.Domain, UserID: req.UserID, Public: req.Public, Namespace: req.Namespace, Permissions: req.Permissions, Scopes: req.Scopes}); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": req.ID, "namespace": ns})
}

// HandleUpdateClientPermissionsByNamespaceGin updates permissions for a client constrained to a namespace path param.
func (s *Server) HandleUpdateClientPermissionsByNamespaceGin(c *gin.Context) {
	if _, err := s.GetPrimaryDB(); err != nil {
		c.JSON(http.StatusServiceUnavailable, errorResponse(err))
		return
	}
	ns := c.Param("ns")
	clientID := c.Param("id")
	var req dto.UpdateClientPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	cliStore := s.getDBClientStore()
	// Optional: verify client belongs to ns
	if ci, err := cliStore.GetByID(c.Request.Context(), clientID); err == nil {
		if mc, ok := ci.(*models.Client); ok {
			if mc.Namespace != ns {
				c.JSON(http.StatusForbidden, errorResponse(errors.ErrInvalidClient))
				return
			}
		}
	}
	if err := cliStore.UpdatePermissions(c.Request.Context(), clientID, req.Permissions); err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": clientID, "namespace": ns, "permissions": req.Permissions})
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
