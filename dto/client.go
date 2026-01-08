package dto

import "github.com/go-oauth2/oauth2/v4/models"

// UpsertClientRequest represents a request to create or update a client.
type UpsertClientRequest struct {
	ID          string   `json:"id" binding:"required"`
	Secret      string   `json:"secret" binding:"required"`
	Domain      string   `json:"domain" binding:"required"`
	UserID      string   `json:"user_id"`
	Public      bool     `json:"public"`
	Namespace   string   `json:"namespace"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`
}

// UpdateClientPermissionsRequest represents a request to update client permissions.
type UpdateClientPermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

// UpdateClientScopesRequest represents a request to update client scopes.
type UpdateClientScopesRequest struct {
	Scopes []string `json:"scopes" binding:"required"`
}

// ClientResponse represents a client in API responses.
// Secret is intentionally excluded for security.
type ClientResponse struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Public      bool     `json:"public"`
	UserID      string   `json:"user_id,omitempty"`
	Namespace   string   `json:"namespace"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`
}

// FromClient converts a models.Client to ClientResponse.
func FromClient(c *models.Client) ClientResponse {
	return ClientResponse{
		ID:          c.ID,
		Domain:      c.Domain,
		Public:      c.Public,
		UserID:      c.UserID,
		Namespace:   c.Namespace,
		Permissions: c.Permissions,
		Scopes:      c.Scopes,
	}
}

// FromClients converts a slice of models.Client to a slice of ClientResponse.
func FromClients(clients []*models.Client) []ClientResponse {
	responses := make([]ClientResponse, len(clients))
	for i, c := range clients {
		responses[i] = FromClient(c)
	}
	return responses
}
