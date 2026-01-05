package server_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

func newOIDCTestServer(t *testing.T) (*server.Server, *httptest.Server) {
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	s := server.NewDefaultServer(m)
	// Allow client_id via form
	s.SetClientInfoHandler(server.ClientFormHandler)
	// Bypass login by returning a fixed user id
	s.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) { return "000000", nil })
	// Build gin engine
	e := server.NewGinEngine(s)
	ts := httptest.NewServer(e)
	return s, ts
}

func oidcRegisterPublicClient(t *testing.T, s *server.Server, domain string) (clientID string) {
	cs := store.NewClientStore()
	clientID = "pub-oidc"
	cs.Set(clientID, &models.Client{ID: clientID, Secret: "", Domain: domain, Public: true})
	// Map into the concrete manage.Manager if available
	if mm, ok := s.Manager.(*manage.Manager); ok {
		mm.MapClientStorage(cs)
	} else {
		t.Fatalf("manager type is not *manage.Manager")
	}
	return
}

func TestOIDC_DiscoveryAndJWKS(t *testing.T) {
	s, ts := newOIDCTestServer(t)
	defer ts.Close()
	_ = s // not used directly
	// discovery
	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("discovery status: %d", resp.StatusCode)
	}
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if meta["issuer"] == nil || meta["jwks_uri"] == nil {
		t.Fatalf("discovery missing fields: %v", meta)
	}
	// jwks
	resp2, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks get: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("jwks status: %d", resp2.StatusCode)
	}
	var jwks map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if _, ok := jwks["keys"]; !ok {
		t.Fatalf("jwks missing keys: %v", jwks)
	}
}

func TestOIDC_AuthorizationCode_OpenID_ReturnsIDToken_AndUserInfo(t *testing.T) {
	s, ts := newOIDCTestServer(t)
	defer ts.Close()
	clientID := oidcRegisterPublicClient(t, s, "http://client.example")
	// 1) authorize request, stop at redirect to capture code
	authURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":  {"code"},
		"client_id":      {clientID},
		"redirect_uri":   {"http://client.example/cb"},
		"scope":          {"openid profile"},
		"code_challenge": {"ThisIsAFourtyThreeCharactersLongStringThing"},
	}.Encode()
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize get: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}
	// 2) token exchange with code_verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {"http://client.example/cb"},
		"code":          {code},
		"code_verifier": {"ThisIsAFourtyThreeCharactersLongStringThing"},
	}
	resp2, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token post: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("token status: %d", resp2.StatusCode)
	}
	var tok map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	acc, _ := tok["access_token"].(string)
	idt, _ := tok["id_token"].(string)
	if acc == "" || idt == "" {
		t.Fatalf("missing tokens: %v", tok)
	}
	// 3) verify id_token using JWKS
	resp3, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks get: %v", err)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatalf("no jwks keys")
	}
	mod, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	expB, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	eVal := new(big.Int).SetBytes(expB).Int64()
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(mod), E: int(eVal)}
	parsed, err := jwt.Parse(idt, func(token *jwt.Token) (interface{}, error) { return pub, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("id_token invalid: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type mismatch")
	}
	if claims["aud"] != clientID {
		t.Fatalf("aud mismatch: %v", claims["aud"])
	}
	// 4) userinfo
	req3, _ := http.NewRequest("GET", ts.URL+"/oauth/userinfo", nil)
	req3.Header.Set("Authorization", "Bearer "+acc)
	resp4, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("userinfo get: %v", err)
	}
	if resp4.StatusCode != 200 {
		t.Fatalf("userinfo status: %d", resp4.StatusCode)
	}
	var ui map[string]any
	if err := json.NewDecoder(resp4.Body).Decode(&ui); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if ui["sub"] != "000000" {
		t.Fatalf("userinfo sub mismatch: %v", ui)
	}
}
