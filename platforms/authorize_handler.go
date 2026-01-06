package platforms

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-oauth2/oauth2/v4/models"
)

// AuthorizeHandler defines the interface for platform-specific authorization URL builders.
type AuthorizeHandler interface {
	// BuildAuthorizeURL constructs the OAuth authorization URL for the platform.
	BuildAuthorizeURL(baseURI string, platformClient *models.PlatformClient, requestID string) (string, error)
	// PlatformID returns the platform identifier.
	PlatformID() string
}

// AuthorizeHandlerRegistry manages platform-specific authorize handlers.
type AuthorizeHandlerRegistry struct {
	handlers map[string]AuthorizeHandler
}

// NewAuthorizeHandlerRegistry creates a new registry with default handlers.
func NewAuthorizeHandlerRegistry() *AuthorizeHandlerRegistry {
	r := &AuthorizeHandlerRegistry{
		handlers: make(map[string]AuthorizeHandler),
	}
	// Register default handlers
	r.Register(&GoogleHandler{})
	r.Register(&FacebookHandler{})
	r.Register(&AppleHandler{})
	r.Register(&DiscordHandler{})
	r.Register(&TwitchHandler{})
	r.Register(&SteamHandler{})
	r.Register(&EpicGamesHandler{})
	r.Register(&GenericOIDCHandler{})
	return r
}

// Register adds a handler to the registry.
func (r *AuthorizeHandlerRegistry) Register(handler AuthorizeHandler) {
	r.handlers[handler.PlatformID()] = handler
}

// Get returns the handler for a platform ID.
func (r *AuthorizeHandlerRegistry) Get(platformID string) AuthorizeHandler {
	if h, ok := r.handlers[platformID]; ok {
		return h
	}
	// Fall back to generic OIDC handler for unknown platforms
	return r.handlers["generic"]
}

// GoogleHandler handles Google OAuth authorization.
type GoogleHandler struct{}

func (h *GoogleHandler) PlatformID() string { return models.PlatformGoogle }

func (h *GoogleHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("access_type", "offline")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)
	params.Set("prompt", "consent")

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode(), nil
}

// FacebookHandler handles Facebook OAuth authorization.
type FacebookHandler struct{}

func (h *FacebookHandler) PlatformID() string { return models.PlatformFacebook }

func (h *FacebookHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "email public_profile")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)

	return "https://www.facebook.com/v18.0/dialog/oauth?" + params.Encode(), nil
}

// AppleHandler handles Apple Sign-In authorization.
type AppleHandler struct{}

func (h *AppleHandler) PlatformID() string { return models.PlatformApple }

func (h *AppleHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "name email")
	params.Set("response_mode", "form_post")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)

	return "https://appleid.apple.com/auth/authorize?" + params.Encode(), nil
}

// DiscordHandler handles Discord OAuth authorization.
type DiscordHandler struct{}

func (h *DiscordHandler) PlatformID() string { return models.PlatformDiscord }

func (h *DiscordHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "identify email")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)

	return "https://discord.com/api/oauth2/authorize?" + params.Encode(), nil
}

// TwitchHandler handles Twitch OAuth authorization.
type TwitchHandler struct{}

func (h *TwitchHandler) PlatformID() string { return models.PlatformTwitch }

func (h *TwitchHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "user:read:email")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)

	return "https://id.twitch.tv/oauth2/authorize?" + params.Encode(), nil
}

// SteamHandler handles Steam OpenID 2.0 authorization.
type SteamHandler struct{}

func (h *SteamHandler) PlatformID() string { return models.PlatformSteam }

func (h *SteamHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	// Steam uses OpenID 2.0, not OAuth 2.0
	params := url.Values{}
	params.Set("openid.mode", "checkid_setup")
	params.Set("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Set("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Set("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Set("openid.return_to", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate?state=%s", baseURI, h.PlatformID(), requestID))
	params.Set("openid.realm", baseURI)

	return "https://steamcommunity.com/openid/login?" + params.Encode(), nil
}

// EpicGamesHandler handles Epic Games OAuth authorization.
type EpicGamesHandler struct{}

func (h *EpicGamesHandler) PlatformID() string { return models.PlatformEpicGames }

func (h *EpicGamesHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "basic_profile")
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, h.PlatformID()))
	params.Set("state", requestID)

	return "https://www.epicgames.com/id/authorize?" + params.Encode(), nil
}

// GenericOIDCHandler handles generic OIDC platforms.
type GenericOIDCHandler struct{}

func (h *GenericOIDCHandler) PlatformID() string { return "generic" }

func (h *GenericOIDCHandler) BuildAuthorizeURL(baseURI string, pc *models.PlatformClient, requestID string) (string, error) {
	if pc.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("authorization_endpoint not configured for platform %s", pc.PlatformID)
	}

	params := url.Values{}
	params.Set("client_id", pc.ClientID)
	params.Set("response_type", "code")
	if pc.Scopes != "" {
		params.Set("scope", pc.Scopes)
	} else {
		params.Set("scope", "openid profile email")
	}
	params.Set("redirect_uri", fmt.Sprintf("%s/iam/v1/platforms/%s/authenticate", baseURI, pc.PlatformID))
	params.Set("state", requestID)

	authURL := pc.AuthorizationEndpoint
	if strings.Contains(authURL, "?") {
		return authURL + "&" + params.Encode(), nil
	}
	return authURL + "?" + params.Encode(), nil
}
