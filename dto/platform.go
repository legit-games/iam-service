package dto

import (
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
)

// PlatformClientRequest represents a request to create or update a platform client.
type PlatformClientRequest struct {
	PlatformID            string `json:"platform_id"`
	ClientID              string `json:"client_id"`
	Secret                string `json:"secret,omitempty"`
	RedirectURI           string `json:"redirect_uri"`
	AppID                 string `json:"app_id,omitempty"`
	Environment           string `json:"environment"`
	PlatformName          string `json:"platform_name,omitempty"`
	Type                  string `json:"type,omitempty"`
	SSOURL                string `json:"sso_url,omitempty"`
	OrganizationID        string `json:"organization_id,omitempty"`
	FederationMetadataURL string `json:"federation_metadata_url,omitempty"`
	ACSURL                string `json:"acs_url,omitempty"`
	KeyID                 string `json:"key_id,omitempty"`
	TeamID                string `json:"team_id,omitempty"`
	GenericOauthFlow      bool   `json:"generic_oauth_flow"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	Scopes                string `json:"scopes,omitempty"`
	JwksEndpoint          string `json:"jwks_endpoint,omitempty"`
	Active                bool   `json:"active"`
}

// ToModel converts PlatformClientRequest to models.PlatformClient.
func (r *PlatformClientRequest) ToModel() *models.PlatformClient {
	return &models.PlatformClient{
		PlatformID:            r.PlatformID,
		ClientID:              r.ClientID,
		Secret:                r.Secret,
		RedirectURI:           r.RedirectURI,
		AppID:                 r.AppID,
		Environment:           r.Environment,
		PlatformName:          r.PlatformName,
		Type:                  r.Type,
		SSOURL:                r.SSOURL,
		OrganizationID:        r.OrganizationID,
		FederationMetadataURL: r.FederationMetadataURL,
		ACSURL:                r.ACSURL,
		KeyID:                 r.KeyID,
		TeamID:                r.TeamID,
		GenericOauthFlow:      r.GenericOauthFlow,
		AuthorizationEndpoint: r.AuthorizationEndpoint,
		TokenEndpoint:         r.TokenEndpoint,
		UserInfoEndpoint:      r.UserInfoEndpoint,
		Scopes:                r.Scopes,
		JwksEndpoint:          r.JwksEndpoint,
		Active:                r.Active,
	}
}

// PlatformClientResponse represents a platform client in API responses.
// Secret is intentionally excluded for security.
type PlatformClientResponse struct {
	ID                    string    `json:"id"`
	Namespace             string    `json:"namespace"`
	PlatformID            string    `json:"platform_id"`
	ClientID              string    `json:"client_id"`
	RedirectURI           string    `json:"redirect_uri"`
	AppID                 string    `json:"app_id,omitempty"`
	Environment           string    `json:"environment"`
	PlatformName          string    `json:"platform_name,omitempty"`
	Type                  string    `json:"type,omitempty"`
	SSOURL                string    `json:"sso_url,omitempty"`
	OrganizationID        string    `json:"organization_id,omitempty"`
	FederationMetadataURL string    `json:"federation_metadata_url,omitempty"`
	ACSURL                string    `json:"acs_url,omitempty"`
	KeyID                 string    `json:"key_id,omitempty"`
	TeamID                string    `json:"team_id,omitempty"`
	GenericOauthFlow      bool      `json:"generic_oauth_flow"`
	AuthorizationEndpoint string    `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string    `json:"token_endpoint,omitempty"`
	UserInfoEndpoint      string    `json:"userinfo_endpoint,omitempty"`
	Scopes                string    `json:"scopes,omitempty"`
	JwksEndpoint          string    `json:"jwks_endpoint,omitempty"`
	Active                bool      `json:"active"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// FromPlatformClient converts a models.PlatformClient to PlatformClientResponse.
func FromPlatformClient(pc *models.PlatformClient) PlatformClientResponse {
	return PlatformClientResponse{
		ID:                    pc.ID,
		Namespace:             pc.Namespace,
		PlatformID:            pc.PlatformID,
		ClientID:              pc.ClientID,
		RedirectURI:           pc.RedirectURI,
		AppID:                 pc.AppID,
		Environment:           pc.Environment,
		PlatformName:          pc.PlatformName,
		Type:                  pc.Type,
		SSOURL:                pc.SSOURL,
		OrganizationID:        pc.OrganizationID,
		FederationMetadataURL: pc.FederationMetadataURL,
		ACSURL:                pc.ACSURL,
		KeyID:                 pc.KeyID,
		TeamID:                pc.TeamID,
		GenericOauthFlow:      pc.GenericOauthFlow,
		AuthorizationEndpoint: pc.AuthorizationEndpoint,
		TokenEndpoint:         pc.TokenEndpoint,
		UserInfoEndpoint:      pc.UserInfoEndpoint,
		Scopes:                pc.Scopes,
		JwksEndpoint:          pc.JwksEndpoint,
		Active:                pc.Active,
		CreatedAt:             pc.CreatedAt,
		UpdatedAt:             pc.UpdatedAt,
	}
}

// FromPlatformClients converts a slice of models.PlatformClient to a slice of PlatformClientResponse.
func FromPlatformClients(clients []*models.PlatformClient) []PlatformClientResponse {
	responses := make([]PlatformClientResponse, len(clients))
	for i, pc := range clients {
		responses[i] = FromPlatformClient(pc)
	}
	return responses
}

// PlatformUserResponse represents a platform user link in API responses.
// RefreshToken is intentionally excluded for security.
type PlatformUserResponse struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Namespace       string    `json:"namespace"`
	PlatformID      string    `json:"platform_id"`
	PlatformUserID  string    `json:"platform_user_id"`
	OriginNamespace string    `json:"origin_namespace,omitempty"`
	DisplayName     string    `json:"display_name,omitempty"`
	EmailAddress    string    `json:"email_address,omitempty"`
	AvatarURL       string    `json:"avatar_url,omitempty"`
	OnlineID        string    `json:"online_id,omitempty"`
	LinkedAt        time.Time `json:"linked_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// FromPlatformUser converts a models.PlatformUser to PlatformUserResponse.
func FromPlatformUser(pu *models.PlatformUser) PlatformUserResponse {
	return PlatformUserResponse{
		ID:              pu.ID,
		UserID:          pu.UserID,
		Namespace:       pu.Namespace,
		PlatformID:      pu.PlatformID,
		PlatformUserID:  pu.PlatformUserID,
		OriginNamespace: pu.OriginNamespace,
		DisplayName:     pu.DisplayName,
		EmailAddress:    pu.EmailAddress,
		AvatarURL:       pu.AvatarURL,
		OnlineID:        pu.OnlineID,
		LinkedAt:        pu.LinkedAt,
		CreatedAt:       pu.CreatedAt,
		UpdatedAt:       pu.UpdatedAt,
	}
}

// FromPlatformUsers converts a slice of models.PlatformUser to a slice of PlatformUserResponse.
func FromPlatformUsers(users []*models.PlatformUser) []PlatformUserResponse {
	responses := make([]PlatformUserResponse, len(users))
	for i, pu := range users {
		responses[i] = FromPlatformUser(pu)
	}
	return responses
}
