package models

import "time"

// PlatformClient stores OAuth client configuration for third-party platforms.
// Each namespace can have its own set of platform credentials.
type PlatformClient struct {
	ID                    string    `json:"id" db:"id" gorm:"primaryKey"`
	Namespace             string    `json:"namespace" db:"namespace" gorm:"index:idx_platform_client_lookup,unique"`
	PlatformID            string    `json:"platform_id" db:"platform_id" gorm:"index:idx_platform_client_lookup,unique"`
	ClientID              string    `json:"client_id" db:"client_id"`
	Secret                string    `json:"-" db:"secret"` // Never expose in JSON
	RedirectURI           string    `json:"redirect_uri" db:"redirect_uri"`
	AppID                 string    `json:"app_id,omitempty" db:"app_id"`
	Environment           string    `json:"environment" db:"environment"` // dev, prod-qa, prod
	PlatformName          string    `json:"platform_name,omitempty" db:"platform_name"`
	Type                  string    `json:"type,omitempty" db:"type"`
	SSOURL                string    `json:"sso_url,omitempty" db:"sso_url"`
	OrganizationID        string    `json:"organization_id,omitempty" db:"organization_id"`
	FederationMetadataURL string    `json:"federation_metadata_url,omitempty" db:"federation_metadata_url"`
	ACSURL                string    `json:"acs_url,omitempty" db:"acs_url"`
	KeyID                 string    `json:"key_id,omitempty" db:"key_id"`     // Apple Key ID
	TeamID                string    `json:"team_id,omitempty" db:"team_id"`   // Apple Team ID
	GenericOauthFlow      bool      `json:"generic_oauth_flow" db:"generic_oauth_flow"`
	AuthorizationEndpoint string    `json:"authorization_endpoint,omitempty" db:"authorization_endpoint"`
	TokenEndpoint         string    `json:"token_endpoint,omitempty" db:"token_endpoint"`
	UserInfoEndpoint      string    `json:"userinfo_endpoint,omitempty" db:"userinfo_endpoint"`
	Scopes                string    `json:"scopes,omitempty" db:"scopes"`
	JwksEndpoint          string    `json:"jwks_endpoint,omitempty" db:"jwks_endpoint"`
	Active                bool      `json:"active" db:"active" gorm:"default:true"`
	CreatedAt             time.Time `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
}

// TableName returns the table name for GORM.
func (PlatformClient) TableName() string {
	return "platform_clients"
}

// Supported platform IDs
const (
	PlatformGoogle     = "google"
	PlatformFacebook   = "facebook"
	PlatformApple      = "apple"
	PlatformDiscord    = "discord"
	PlatformTwitch     = "twitch"
	PlatformSteam      = "steamopenid"
	PlatformEpicGames  = "epicgames"
	PlatformPSN        = "ps4web"
	PlatformXbox       = "xblweb"
	PlatformAmazon     = "amazon"
	PlatformAzure      = "azure"
	PlatformSnapchat   = "snapchat"
)

// PlatformEnvironment constants
const (
	EnvDev    = "dev"
	EnvProdQA = "prod-qa"
	EnvProd   = "prod"
)
