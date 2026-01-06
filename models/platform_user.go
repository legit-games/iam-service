package models

import "time"

// PlatformUser stores the link between an IAM user and their third-party platform account.
type PlatformUser struct {
	ID              string    `json:"id" db:"id" gorm:"primaryKey"`
	UserID          string    `json:"user_id" db:"user_id" gorm:"index:idx_platform_user_lookup"`
	Namespace       string    `json:"namespace" db:"namespace" gorm:"index:idx_platform_user_lookup"`
	PlatformID      string    `json:"platform_id" db:"platform_id" gorm:"index:idx_platform_user_lookup"`
	PlatformUserID  string    `json:"platform_user_id" db:"platform_user_id"`
	OriginNamespace string    `json:"origin_namespace,omitempty" db:"origin_namespace"`
	DisplayName     string    `json:"display_name,omitempty" db:"display_name"`
	EmailAddress    string    `json:"email_address,omitempty" db:"email_address"`
	AvatarURL       string    `json:"avatar_url,omitempty" db:"avatar_url"`
	OnlineID        string    `json:"online_id,omitempty" db:"online_id"`
	RefreshToken    string    `json:"-" db:"refresh_token"`
	LinkedAt        time.Time `json:"linked_at" db:"linked_at"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// TableName returns the table name for GORM
func (PlatformUser) TableName() string {
	return "platform_users"
}

// PlatformToken represents a cached platform access token.
type PlatformToken struct {
	ThirdPartyToken string `json:"platform_token"`
	SandboxID       string `json:"sand_box_id,omitempty"`
}

// TokenThirdPartyResponse is the API response for platform token retrieval.
type TokenThirdPartyResponse struct {
	PlatformToken string `json:"platform_token"`
	SandBoxID     string `json:"sand_box_id,omitempty"`
}

// PlatformTokenRequest represents the form data for POST /iam/v3/oauth/platforms/{platformId}/token.
type PlatformTokenRequest struct {
	PlatformToken  string `json:"platform_token" form:"platform_token"`
	DeviceID       string `json:"device_id" form:"device_id"`
	ClientID       string `json:"client_id" form:"client_id"`
	CreateHeadless *bool  `json:"createHeadless" form:"createHeadless"`
	MacAddress     string `json:"mac_address" form:"mac_address"`
	SkipSetCookie  bool   `json:"skipSetCookie" form:"skipSetCookie"`
}

// GetCreateHeadless returns the createHeadless value, defaulting to true.
func (r *PlatformTokenRequest) GetCreateHeadless() bool {
	if r.CreateHeadless == nil {
		return true
	}
	return *r.CreateHeadless
}

// NamespaceRole represents a role assigned in a specific namespace.
type NamespaceRole struct {
	RoleID    string `json:"roleId"`
	Namespace string `json:"namespace"`
}

// Permission represents a permission entry.
type Permission struct {
	Resource string `json:"resource"`
	Action   int    `json:"action"`
}

// Ban represents an active ban on a user.
type Ban struct {
	Reason  string `json:"reason,omitempty"`
	EndDate int64  `json:"endDate,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// PlatformTokenResponse is the response for platform token authentication.
type PlatformTokenResponse struct {
	AccessToken    string          `json:"access_token"`
	RefreshToken   string          `json:"refresh_token,omitempty"`
	ExpiresIn      int             `json:"expires_in"`
	TokenType      string          `json:"token_type"`
	UserID         string          `json:"user_id"`
	PlatformID     string          `json:"platform_id"`
	PlatformUserID string          `json:"platform_user_id"`
	DisplayName    string          `json:"display_name,omitempty"`
	Namespace      string          `json:"namespace"`
	NamespaceRoles []NamespaceRole `json:"namespace_roles,omitempty"`
	Roles          []string        `json:"roles,omitempty"`
	Permissions    []Permission    `json:"permissions,omitempty"`
	Bans           []Ban           `json:"bans,omitempty"`
	JusticeFlags   int             `json:"jflgs"`
	IsComply       bool            `json:"is_comply"`
	Scope          string          `json:"scope,omitempty"`
	XUID           string          `json:"xuid,omitempty"`
}

// PlatformTokenErrorResponse represents error responses from the platform token endpoint.
type PlatformTokenErrorResponse struct {
	Error            string   `json:"error"`
	ErrorDescription string   `json:"error_description,omitempty"`
	PlatformID       string   `json:"platformId,omitempty"`
	LinkingToken     string   `json:"linkingToken,omitempty"`
	ClientID         string   `json:"clientId,omitempty"`
	MFAToken         string   `json:"mfa_token,omitempty"`
	Factors          []string `json:"factors,omitempty"`
	DefaultFactor    string   `json:"default_factor,omitempty"`
	Email            string   `json:"email,omitempty"`
	UserBan          *Ban     `json:"userBan,omitempty"`
}
