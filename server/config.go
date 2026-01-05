package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
)

// Config configuration parameters
type Config struct {
	TokenType                   string                // token type
	AllowGetAccessRequest       bool                  // to allow GET requests for the token
	AllowedResponseTypes        []oauth2.ResponseType // allow the authorization type
	AllowedGrantTypes           []oauth2.GrantType    // allow the grant type
	AllowedCodeChallengeMethods []oauth2.CodeChallengeMethod
	ForcePKCE                   bool
	// OIDC settings
	OIDCEnabled bool
	Issuer      string // issuer URL for ID tokens and discovery
	// Refresh rotation settings (operator-configurable)
	RefreshRotation RefreshRotationConfig
}

// RefreshRotationConfig maps to manage.RefreshingConfig.
type RefreshRotationConfig struct {
	// Whether to issue a new refresh token during refresh
	GenerateNew bool
	// Whether to reset refresh token create time on rotation
	ResetTime bool
	// Whether to remove old access token on refresh
	RemoveOldAccess bool
	// Whether to remove old refresh token on refresh (enforces reuse detection)
	RemoveOldRefresh bool
	// Optional overrides for exp durations
	AccessExpOverride  time.Duration
	RefreshExpOverride time.Duration
}

// NewConfig create to configuration instance
func NewConfig() *Config {
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
		ForcePKCE:   true,
		OIDCEnabled: true,
		Issuer:      "http://localhost", // can be overridden by deployment config
		RefreshRotation: RefreshRotationConfig{
			GenerateNew:      true,
			ResetTime:        true,
			RemoveOldAccess:  true,
			RemoveOldRefresh: true,
		},
	}
}

// AuthorizeRequest authorization request
type AuthorizeRequest struct {
	ResponseType        oauth2.ResponseType
	ClientID            string
	Scope               string
	RedirectURI         string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod oauth2.CodeChallengeMethod
	AccessTokenExp      time.Duration
	Request             *http.Request
	// OIDC
	Nonce string
}

// Application-level sentinel errors for missing configuration.
var (
	ErrRegDBDSNNotSet  = errors.New("REG_DB_DSN not set")
	ErrUserDBDSNNotSet = errors.New("USER_DB_DSN not set")
)

// NotImplemented writes a standardized not_implemented JSON error for net/http handlers.
func NotImplemented(w http.ResponseWriter, description string) error {
	w.WriteHeader(http.StatusNotImplemented)
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"error":             "not_implemented",
		"error_description": description,
	})
}

// NotImplementedGin writes a standardized not_implemented JSON error for Gin handlers.
func NotImplementedGin(c *gin.Context, description string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":             "not_implemented",
		"error_description": description,
	})
}
