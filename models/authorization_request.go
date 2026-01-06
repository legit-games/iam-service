package models

import "time"

// AuthorizationRequest represents an OAuth authorization request stored in Redis.
// This is created when a user initiates the OAuth flow via /oauth/authorize
// and is used to maintain state across the platform authentication redirect.
type AuthorizationRequest struct {
	RequestID           string    `json:"request_id"`
	Namespace           string    `json:"namespace"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	ResponseType        string    `json:"response_type"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	TargetAuthPage      string    `json:"target_auth_page,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// IsExpired checks if the authorization request has expired.
func (ar *AuthorizationRequest) IsExpired() bool {
	return time.Now().After(ar.ExpiresAt)
}
