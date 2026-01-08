package dto

import (
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
)

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID                string          `json:"id"`
	AccountID         string          `json:"account_id"`
	Namespace         *string         `json:"namespace,omitempty"`
	UserType          models.UserType `json:"user_type"`
	ProviderType      *string         `json:"provider_type,omitempty"`
	ProviderAccountID *string         `json:"provider_account_id,omitempty"`
	Orphaned          bool            `json:"orphaned"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// FromUser converts a models.User to UserResponse.
func FromUser(u *models.User) UserResponse {
	return UserResponse{
		ID:                u.ID,
		AccountID:         u.AccountID,
		Namespace:         u.Namespace,
		UserType:          u.UserType,
		ProviderType:      u.ProviderType,
		ProviderAccountID: u.ProviderAccountID,
		Orphaned:          u.Orphaned,
		CreatedAt:         u.CreatedAt,
		UpdatedAt:         u.UpdatedAt,
	}
}

// FromUsers converts a slice of models.User to a slice of UserResponse.
func FromUsers(users []*models.User) []UserResponse {
	responses := make([]UserResponse, len(users))
	for i, u := range users {
		responses[i] = FromUser(u)
	}
	return responses
}
