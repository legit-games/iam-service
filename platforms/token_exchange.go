package platforms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-oauth2/oauth2/v4/models"
)

// TokenExchangeResult contains the result of a token exchange operation.
type TokenExchangeResult struct {
	UserInfo     *PlatformUserInfo
	AccessToken  string
	RefreshToken string
}

// TokenExchangeHandler defines the interface for platform-specific token exchange.
type TokenExchangeHandler interface {
	// ExchangeCode exchanges an authorization code for tokens and user info.
	ExchangeCode(ctx context.Context, pc *models.PlatformClient, code, redirectURI string) (*TokenExchangeResult, error)
	// PlatformID returns the platform identifier.
	PlatformID() string
}

// TokenExchangeRegistry manages platform-specific token exchange handlers.
type TokenExchangeRegistry struct {
	handlers map[string]TokenExchangeHandler
}

// NewTokenExchangeRegistry creates a new registry with default handlers.
func NewTokenExchangeRegistry() *TokenExchangeRegistry {
	r := &TokenExchangeRegistry{
		handlers: make(map[string]TokenExchangeHandler),
	}
	r.Register(&GoogleTokenExchange{})
	r.Register(&FacebookTokenExchange{})
	r.Register(&DiscordTokenExchange{})
	r.Register(&TwitchTokenExchange{})
	return r
}

// Register adds a handler to the registry.
func (r *TokenExchangeRegistry) Register(handler TokenExchangeHandler) {
	r.handlers[handler.PlatformID()] = handler
}

// Get returns the handler for a platform ID.
func (r *TokenExchangeRegistry) Get(platformID string) TokenExchangeHandler {
	return r.handlers[platformID]
}

// GoogleTokenExchange handles Google OAuth token exchange.
type GoogleTokenExchange struct{}

func (h *GoogleTokenExchange) PlatformID() string { return models.PlatformGoogle }

func (h *GoogleTokenExchange) ExchangeCode(ctx context.Context, pc *models.PlatformClient, code, redirectURI string) (*TokenExchangeResult, error) {
	// Exchange code for tokens
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err = http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfo struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return &TokenExchangeResult{
		UserInfo: &PlatformUserInfo{
			PlatformUserID: userInfo.ID,
			Email:          userInfo.Email,
			DisplayName:    userInfo.Name,
			AvatarURL:      userInfo.Picture,
		},
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

// FacebookTokenExchange handles Facebook OAuth token exchange.
type FacebookTokenExchange struct{}

func (h *FacebookTokenExchange) PlatformID() string { return models.PlatformFacebook }

func (h *FacebookTokenExchange) ExchangeCode(ctx context.Context, pc *models.PlatformClient, code, redirectURI string) (*TokenExchangeResult, error) {
	// Exchange code for tokens
	tokenURL := "https://graph.facebook.com/v18.0/oauth/access_token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL+"?"+data.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	userInfoURL := "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" + tokenResp.AccessToken
	req, err = http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfo struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return &TokenExchangeResult{
		UserInfo: &PlatformUserInfo{
			PlatformUserID: userInfo.ID,
			Email:          userInfo.Email,
			DisplayName:    userInfo.Name,
			AvatarURL:      userInfo.Picture.Data.URL,
		},
		AccessToken: tokenResp.AccessToken,
	}, nil
}

// DiscordTokenExchange handles Discord OAuth token exchange.
type DiscordTokenExchange struct{}

func (h *DiscordTokenExchange) PlatformID() string { return models.PlatformDiscord }

func (h *DiscordTokenExchange) ExchangeCode(ctx context.Context, pc *models.PlatformClient, code, redirectURI string) (*TokenExchangeResult, error) {
	tokenURL := "https://discord.com/api/oauth2/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	req, err = http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfo struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	avatarURL := ""
	if userInfo.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userInfo.ID, userInfo.Avatar)
	}

	return &TokenExchangeResult{
		UserInfo: &PlatformUserInfo{
			PlatformUserID: userInfo.ID,
			Email:          userInfo.Email,
			DisplayName:    userInfo.Username,
			AvatarURL:      avatarURL,
		},
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

// TwitchTokenExchange handles Twitch OAuth token exchange.
type TwitchTokenExchange struct{}

func (h *TwitchTokenExchange) PlatformID() string { return models.PlatformTwitch }

func (h *TwitchTokenExchange) ExchangeCode(ctx context.Context, pc *models.PlatformClient, code, redirectURI string) (*TokenExchangeResult, error) {
	tokenURL := "https://id.twitch.tv/oauth2/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	req, err = http.NewRequestWithContext(ctx, "GET", "https://api.twitch.tv/helix/users", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	req.Header.Set("Client-Id", pc.ClientID)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfoResp struct {
		Data []struct {
			ID              string `json:"id"`
			Login           string `json:"login"`
			DisplayName     string `json:"display_name"`
			Email           string `json:"email"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &userInfoResp); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	if len(userInfoResp.Data) == 0 {
		return nil, fmt.Errorf("no user data returned from Twitch")
	}

	user := userInfoResp.Data[0]
	return &TokenExchangeResult{
		UserInfo: &PlatformUserInfo{
			PlatformUserID: user.ID,
			Email:          user.Email,
			DisplayName:    user.DisplayName,
			AvatarURL:      user.ProfileImageURL,
		},
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}
