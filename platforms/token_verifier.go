package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
)

// Common errors for token verification
var (
	ErrInvalidPlatformToken  = errors.New("invalid platform token")
	ErrPlatformNotConfigured = errors.New("platform not configured")
	ErrPlatformUnavailable   = errors.New("platform service unavailable")
	ErrTokenExpired          = errors.New("platform token expired")
)

// PlatformUserInfo contains user information retrieved from the platform.
type PlatformUserInfo struct {
	PlatformUserID string `json:"platform_user_id"`
	DisplayName    string `json:"display_name"`
	Email          string `json:"email,omitempty"`
	AvatarURL      string `json:"avatar_url,omitempty"`
	// Platform-specific fields
	SteamID    string `json:"steam_id,omitempty"`
	XUID       string `json:"xuid,omitempty"`       // Xbox User ID
	OnlineID   string `json:"online_id,omitempty"` // PSN Online ID
	ExtraData  map[string]interface{} `json:"extra_data,omitempty"`
}

// TokenVerifier defines the interface for verifying platform tokens.
type TokenVerifier interface {
	// VerifyToken verifies a platform token and returns user information.
	VerifyToken(ctx context.Context, platformClient *models.PlatformClient, token string) (*PlatformUserInfo, error)
	// PlatformID returns the platform identifier.
	PlatformID() string
}

// TokenVerifierRegistry manages platform-specific token verifiers.
type TokenVerifierRegistry struct {
	verifiers  map[string]TokenVerifier
	httpClient *http.Client
}

// NewTokenVerifierRegistry creates a new registry with default verifiers.
func NewTokenVerifierRegistry() *TokenVerifierRegistry {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	r := &TokenVerifierRegistry{
		verifiers:  make(map[string]TokenVerifier),
		httpClient: httpClient,
	}

	// Register default verifiers
	r.Register(&GoogleTokenVerifier{client: httpClient})
	r.Register(&FacebookTokenVerifier{client: httpClient})
	r.Register(&DiscordTokenVerifier{client: httpClient})
	r.Register(&TwitchTokenVerifier{client: httpClient})
	r.Register(&EpicGamesTokenVerifier{client: httpClient})
	r.Register(&DeviceTokenVerifier{})
	r.Register(&GenericOIDCTokenVerifier{client: httpClient})

	return r
}

// Register adds a verifier to the registry.
func (r *TokenVerifierRegistry) Register(verifier TokenVerifier) {
	r.verifiers[verifier.PlatformID()] = verifier
}

// Get returns the verifier for a platform ID.
func (r *TokenVerifierRegistry) Get(platformID string) TokenVerifier {
	if v, ok := r.verifiers[platformID]; ok {
		return v
	}
	// Fall back to generic OIDC verifier
	return r.verifiers["generic"]
}

// GoogleTokenVerifier verifies Google OAuth tokens.
type GoogleTokenVerifier struct {
	client *http.Client
}

func (v *GoogleTokenVerifier) PlatformID() string { return models.PlatformGoogle }

func (v *GoogleTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	// Exchange code for token if it looks like an auth code
	accessToken := token
	if !strings.HasPrefix(token, "ya29.") && len(token) < 100 {
		// This looks like an authorization code, exchange it
		tokenResp, err := v.exchangeCode(ctx, pc, token)
		if err != nil {
			return nil, err
		}
		accessToken = tokenResp
	}

	// Get user info from Google
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidPlatformToken
	}

	var userInfo struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &PlatformUserInfo{
		PlatformUserID: userInfo.ID,
		DisplayName:    userInfo.Name,
		Email:          userInfo.Email,
		AvatarURL:      userInfo.Picture,
	}, nil
}

func (v *GoogleTokenVerifier) exchangeCode(ctx context.Context, pc *models.PlatformClient, code string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", pc.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// FacebookTokenVerifier verifies Facebook access tokens.
type FacebookTokenVerifier struct {
	client *http.Client
}

func (v *FacebookTokenVerifier) PlatformID() string { return models.PlatformFacebook }

func (v *FacebookTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	// Get user info from Facebook
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=%s", url.QueryEscape(token)), nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidPlatformToken
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

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &PlatformUserInfo{
		PlatformUserID: userInfo.ID,
		DisplayName:    userInfo.Name,
		Email:          userInfo.Email,
		AvatarURL:      userInfo.Picture.Data.URL,
	}, nil
}

// DiscordTokenVerifier verifies Discord OAuth tokens.
type DiscordTokenVerifier struct {
	client *http.Client
}

func (v *DiscordTokenVerifier) PlatformID() string { return models.PlatformDiscord }

func (v *DiscordTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	// Exchange code for token if needed
	accessToken := token
	if len(token) < 50 {
		tokenResp, err := v.exchangeCode(ctx, pc, token)
		if err != nil {
			return nil, err
		}
		accessToken = tokenResp
	}

	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidPlatformToken
	}

	var userInfo struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
		Email         string `json:"email"`
		Avatar        string `json:"avatar"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	displayName := userInfo.Username
	if userInfo.Discriminator != "0" {
		displayName = fmt.Sprintf("%s#%s", userInfo.Username, userInfo.Discriminator)
	}

	avatarURL := ""
	if userInfo.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userInfo.ID, userInfo.Avatar)
	}

	return &PlatformUserInfo{
		PlatformUserID: userInfo.ID,
		DisplayName:    displayName,
		Email:          userInfo.Email,
		AvatarURL:      avatarURL,
	}, nil
}

func (v *DiscordTokenVerifier) exchangeCode(ctx context.Context, pc *models.PlatformClient, code string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", pc.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://discord.com/api/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrInvalidPlatformToken
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// TwitchTokenVerifier verifies Twitch OAuth tokens.
type TwitchTokenVerifier struct {
	client *http.Client
}

func (v *TwitchTokenVerifier) PlatformID() string { return models.PlatformTwitch }

func (v *TwitchTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	// Exchange code for token if needed
	accessToken := token
	if len(token) < 30 {
		tokenResp, err := v.exchangeCode(ctx, pc, token)
		if err != nil {
			return nil, err
		}
		accessToken = tokenResp
	}

	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.twitch.tv/helix/users", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", pc.ClientID)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidPlatformToken
	}

	var result struct {
		Data []struct {
			ID              string `json:"id"`
			Login           string `json:"login"`
			DisplayName     string `json:"display_name"`
			Email           string `json:"email"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, ErrInvalidPlatformToken
	}

	user := result.Data[0]
	return &PlatformUserInfo{
		PlatformUserID: user.ID,
		DisplayName:    user.DisplayName,
		Email:          user.Email,
		AvatarURL:      user.ProfileImageURL,
	}, nil
}

func (v *TwitchTokenVerifier) exchangeCode(ctx context.Context, pc *models.PlatformClient, code string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", pc.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://id.twitch.tv/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrInvalidPlatformToken
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// EpicGamesTokenVerifier verifies Epic Games OAuth tokens.
type EpicGamesTokenVerifier struct {
	client *http.Client
}

func (v *EpicGamesTokenVerifier) PlatformID() string { return models.PlatformEpicGames }

func (v *EpicGamesTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	// Exchange code for token
	accessToken, accountID, err := v.exchangeCode(ctx, pc, token)
	if err != nil {
		return nil, err
	}

	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.epicgames.dev/epic/id/v1/accounts?accountId=%s", accountID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Return basic info from token exchange
		return &PlatformUserInfo{
			PlatformUserID: accountID,
			DisplayName:    accountID,
		}, nil
	}

	var users []struct {
		AccountID   string `json:"accountId"`
		DisplayName string `json:"displayName"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil || len(users) == 0 {
		return &PlatformUserInfo{
			PlatformUserID: accountID,
			DisplayName:    accountID,
		}, nil
	}

	return &PlatformUserInfo{
		PlatformUserID: users[0].AccountID,
		DisplayName:    users[0].DisplayName,
	}, nil
}

func (v *EpicGamesTokenVerifier) exchangeCode(ctx context.Context, pc *models.PlatformClient, code string) (string, string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.epicgames.dev/epic/oauth/v1/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(pc.ClientID, pc.Secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return "", "", ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", ErrInvalidPlatformToken
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		AccountID   string `json:"account_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", err
	}

	return tokenResp.AccessToken, tokenResp.AccountID, nil
}

// DeviceTokenVerifier handles device-based authentication.
type DeviceTokenVerifier struct{}

func (v *DeviceTokenVerifier) PlatformID() string { return "device" }

func (v *DeviceTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, deviceID string) (*PlatformUserInfo, error) {
	// Device ID is used directly as the platform user ID
	// No external verification needed
	if deviceID == "" {
		return nil, ErrInvalidPlatformToken
	}

	return &PlatformUserInfo{
		PlatformUserID: deviceID,
		DisplayName:    "Device User",
	}, nil
}

// GenericOIDCTokenVerifier handles generic OIDC platforms.
type GenericOIDCTokenVerifier struct {
	client *http.Client
}

func (v *GenericOIDCTokenVerifier) PlatformID() string { return "generic" }

func (v *GenericOIDCTokenVerifier) VerifyToken(ctx context.Context, pc *models.PlatformClient, token string) (*PlatformUserInfo, error) {
	if pc.TokenEndpoint == "" || pc.UserInfoEndpoint == "" {
		return nil, ErrPlatformNotConfigured
	}

	// Exchange code for token
	accessToken, err := v.exchangeCode(ctx, pc, token)
	if err != nil {
		return nil, err
	}

	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET", pc.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidPlatformToken
	}

	var userInfo struct {
		Sub     string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &PlatformUserInfo{
		PlatformUserID: userInfo.Sub,
		DisplayName:    userInfo.Name,
		Email:          userInfo.Email,
		AvatarURL:      userInfo.Picture,
	}, nil
}

func (v *GenericOIDCTokenVerifier) exchangeCode(ctx context.Context, pc *models.PlatformClient, code string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", pc.ClientID)
	data.Set("client_secret", pc.Secret)
	data.Set("redirect_uri", pc.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", pc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", ErrPlatformUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrInvalidPlatformToken
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}
