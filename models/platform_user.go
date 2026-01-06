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