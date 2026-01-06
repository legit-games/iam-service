package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
)

func (s *Server) HandleUpsertRoleGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	var body struct {
		Name        string          `json:"name"`
		RoleType    string          `json:"roleType"`
		Permissions json.RawMessage `json:"permissions"`
		Description string          `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	role := models.Role{Namespace: ns, Name: body.Name, RoleType: strings.ToUpper(strings.TrimSpace(body.RoleType)), Permissions: body.Permissions, Description: body.Description}
	if err := roleStore.UpsertRole(c.Request.Context(), role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func (s *Server) HandleListRolesGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	db, err := s.GetIAMReadDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	var rt *string
	if v := strings.TrimSpace(c.Query("roleType")); v != "" {
		vv := strings.ToUpper(v)
		rt = &vv
	}
	roles, err := roleStore.ListRoles(c.Request.Context(), ns, rt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

func (s *Server) HandleDeleteRoleGin(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	if err := roleStore.DeleteRole(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func (s *Server) HandleAssignRoleToUserGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	roleID := strings.TrimSpace(c.Param("id"))
	userID := strings.TrimSpace(c.Param("userId"))
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	if err := roleStore.AssignRoleToUser(c.Request.Context(), userID, ns, roleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func (s *Server) HandleAssignRoleToClientGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	roleID := strings.TrimSpace(c.Param("id"))
	clientID := strings.TrimSpace(c.Param("clientId"))
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	if err := roleStore.AssignRoleToClient(c.Request.Context(), clientID, ns, roleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func (s *Server) HandleAssignRoleToAllUsersGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	roleID := strings.TrimSpace(c.Param("id"))
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	roleStore := store.NewRoleStore(db)
	if err := roleStore.AssignRoleToAllUsersInNamespace(c.Request.Context(), ns, roleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}
