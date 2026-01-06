package platforms

import (
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4/models"
)

func TestAuthorizeHandlerRegistry_Get(t *testing.T) {
	registry := NewAuthorizeHandlerRegistry()

	tests := []struct {
		platformID   string
		expectedType string
	}{
		{models.PlatformGoogle, "*platforms.GoogleHandler"},
		{models.PlatformFacebook, "*platforms.FacebookHandler"},
		{models.PlatformApple, "*platforms.AppleHandler"},
		{models.PlatformDiscord, "*platforms.DiscordHandler"},
		{models.PlatformTwitch, "*platforms.TwitchHandler"},
		{models.PlatformSteam, "*platforms.SteamHandler"},
		{models.PlatformEpicGames, "*platforms.EpicGamesHandler"},
		{"unknown", "*platforms.GenericOIDCHandler"}, // Falls back to generic
	}

	for _, tc := range tests {
		t.Run(tc.platformID, func(t *testing.T) {
			handler := registry.Get(tc.platformID)
			if handler == nil {
				t.Fatalf("expected handler for %s, got nil", tc.platformID)
			}
		})
	}
}

func TestGoogleHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &GoogleHandler{}
	pc := &models.PlatformClient{
		ClientID: "google-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "abc123def456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify URL contains expected components
	if !strings.HasPrefix(url, "https://accounts.google.com/o/oauth2/v2/auth?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
	if !strings.Contains(url, "client_id=google-client-id") {
		t.Errorf("missing client_id in URL: %s", url)
	}
	if !strings.Contains(url, "state=abc123def456") {
		t.Errorf("missing state in URL: %s", url)
	}
	if !strings.Contains(url, "response_type=code") {
		t.Errorf("missing response_type in URL: %s", url)
	}
	if !strings.Contains(url, "redirect_uri=") {
		t.Errorf("missing redirect_uri in URL: %s", url)
	}
}

func TestFacebookHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &FacebookHandler{}
	pc := &models.PlatformClient{
		ClientID: "fb-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(url, "https://www.facebook.com/v18.0/dialog/oauth?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
	if !strings.Contains(url, "client_id=fb-client-id") {
		t.Errorf("missing client_id in URL: %s", url)
	}
}

func TestAppleHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &AppleHandler{}
	pc := &models.PlatformClient{
		ClientID: "apple-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(url, "https://appleid.apple.com/auth/authorize?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
	if !strings.Contains(url, "response_mode=form_post") {
		t.Errorf("Apple should use form_post response mode: %s", url)
	}
}

func TestDiscordHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &DiscordHandler{}
	pc := &models.PlatformClient{
		ClientID: "discord-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(url, "https://discord.com/api/oauth2/authorize?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
}

func TestTwitchHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &TwitchHandler{}
	pc := &models.PlatformClient{
		ClientID: "twitch-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(url, "https://id.twitch.tv/oauth2/authorize?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
}

func TestSteamHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &SteamHandler{}
	pc := &models.PlatformClient{
		ClientID: "steam-client-id", // Steam doesn't use OAuth client_id
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Steam uses OpenID 2.0
	if !strings.HasPrefix(url, "https://steamcommunity.com/openid/login?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
	if !strings.Contains(url, "openid.mode=checkid_setup") {
		t.Errorf("missing openid.mode in URL: %s", url)
	}
	if !strings.Contains(url, "openid.ns=") {
		t.Errorf("missing openid.ns in URL: %s", url)
	}
}

func TestEpicGamesHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &EpicGamesHandler{}
	pc := &models.PlatformClient{
		ClientID: "epic-client-id",
	}

	url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(url, "https://www.epicgames.com/id/authorize?") {
		t.Errorf("unexpected URL prefix: %s", url)
	}
}

func TestGenericOIDCHandler_BuildAuthorizeURL(t *testing.T) {
	handler := &GenericOIDCHandler{}

	t.Run("WithAuthorizationEndpoint", func(t *testing.T) {
		pc := &models.PlatformClient{
			PlatformID:            "custom-oidc",
			ClientID:              "custom-client-id",
			AuthorizationEndpoint: "https://custom-idp.example.com/authorize",
			Scopes:                "openid profile custom",
		}

		url, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.HasPrefix(url, "https://custom-idp.example.com/authorize?") {
			t.Errorf("unexpected URL prefix: %s", url)
		}
		if !strings.Contains(url, "scope=openid+profile+custom") {
			t.Errorf("missing custom scopes in URL: %s", url)
		}
	})

	t.Run("MissingAuthorizationEndpoint", func(t *testing.T) {
		pc := &models.PlatformClient{
			PlatformID: "custom-oidc",
			ClientID:   "custom-client-id",
			// No AuthorizationEndpoint
		}

		_, err := handler.BuildAuthorizeURL("https://iam.example.com", pc, "request123")
		if err == nil {
			t.Fatal("expected error for missing authorization_endpoint")
		}
	})
}
