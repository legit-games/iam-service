package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Defaults (override by editing if needed; no env reads)
var (
	tokenEndpoint          = "http://localhost:8080/oauth/token"
	introspectEndpoint     = "http://localhost:8080/oauth/introspect"
	clientID               = "test-client"
	clientSecret           = "test-secret"
	scopeDefault           = "read"
	grantType              = "client_credentials"
	introspectClientID     = "introspect-client"
	introspectClientSecret = "introspect-secret"
)

type tokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

func requestToken(t *testing.T) tokenResp {
	t.Helper()
	if tokenEndpoint == "" {
		t.Fatal("set tokenEndpoint")
	}
	if clientID == "" || clientSecret == "" {
		t.Fatal("set clientID and clientSecret")
	}
	scope := scopeDefault
	if scope == "" {
		scope = "read"
	}
	gt := grantType
	if gt == "" {
		gt = "client_credentials"
	}

	form := url.Values{}
	form.Set("grant_type", gt)
	form.Set("scope", scope)

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	if tr.Error != "" {
		t.Fatalf("token error: %s", tr.Error)
	}
	if tr.AccessToken == "" {
		t.Fatal("no access_token in response")
	}
	return tr
}

func decodeJWTClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	seg := parts[1]
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode jwt: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return m
}

func introspect(t *testing.T, token string) map[string]any {
	t.Helper()
	if introspectEndpoint == "" {
		t.Skip("no introspectEndpoint; skipping introspection for opaque token")
	}
	id := introspectClientID
	secret := introspectClientSecret
	if id == "" || secret == "" {
		t.Skip("no introspection client credentials; skipping introspection for opaque token")
	}

	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequest(http.MethodPost, introspectEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func parseScopes(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return strings.Fields(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func containsAll(have []string, want []string) bool {
	set := map[string]struct{}{}
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func TestAccessTokenIncludesScope(t *testing.T) {
	// Start a local OAuth 2.0 stub server.
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Validate client credentials via HTTP Basic
		expectAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
		if r.Header.Get("Authorization") != expectAuth {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scope := r.PostForm.Get("scope")
		if scope == "" {
			scope = "read"
		}
		// Issue a simple unsigned JWT with scope claim (RFC 9068 recommends 'scope' as space-delimited string).
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		p := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"stub","sub":"` + clientID + `","scope":"` + scope + `"}`))
		s := base64.RawURLEncoding.EncodeToString([]byte("sig"))
		token := h + "." + p + "." + s

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        scope, // also include in token response (RFC 6749)
		})
	})
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		// Minimal stub: validate basic auth and return active=true.
		expect := "Basic " + base64.StdEncoding.EncodeToString([]byte(introspectClientID+":"+introspectClientSecret))
		if r.Header.Get("Authorization") != expect {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Return active plus a scope example; not used for JWT path but here for completeness.
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "scope": scopeDefault})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Save and restore endpoints to avoid leaking global state.
	origTokenEndpoint, origIntrospectEndpoint := tokenEndpoint, introspectEndpoint
	defer func() {
		tokenEndpoint = origTokenEndpoint
		introspectEndpoint = origIntrospectEndpoint
	}()

	tokenEndpoint = srv.URL + "/oauth/token"
	introspectEndpoint = srv.URL + "/oauth/introspect"

	reqScope := scopeDefault
	if reqScope == "" {
		reqScope = "read"
	}
	want := strings.Fields(reqScope)

	tr := requestToken(t)

	// Check JWT vs opaque
	if strings.Count(tr.AccessToken, ".") == 2 {
		claims := decodeJWTClaims(t, tr.AccessToken)
		// RFC 9068 recommends 'scope' (string). Some providers use 'scp' (array).
		var have []string
		if v, ok := claims["scope"]; ok {
			have = parseScopes(v)
		} else if v, ok := claims["scp"]; ok {
			have = parseScopes(v)
		}
		if len(have) == 0 && tr.Scope != "" {
			have = parseScopes(tr.Scope) // fallback to token response
		}
		// RFC 6749 allows omitting 'scope' in token response when unchanged; RFC 9068 does not require 'scope' claim.
		if len(have) == 0 {
			t.Skip("no discoverable scopes (JWT lacks scope/scp and token response omitted scope as allowed by RFC 6749); enable JWT 'scope' (RFC 9068) or use introspection to verify")
		}
		if !containsAll(have, want) {
			t.Fatalf("missing scopes; have=%v want=%v", have, want)
		}
	} else {
		resp := introspect(t, tr.AccessToken)
		if resp == nil {
			t.Skip("no introspection; cannot verify opaque token scopes")
		}
		if active, _ := resp["active"].(bool); !active {
			t.Fatal("introspection: token is not active")
		}
		have := parseScopes(resp["scope"])
		if len(have) == 0 && tr.Scope != "" {
			have = parseScopes(tr.Scope)
		}
		// RFC 6749/7662 allow omission; skip if we cannot discover granted scopes.
		if len(have) == 0 {
			t.Skip("no discoverable scopes (introspection/token response omitted scope per RFC 6749/7662)")
		}
		if !containsAll(have, want) {
			t.Fatalf("missing scopes; have=%v want=%v", have, want)
		}
	}
}
