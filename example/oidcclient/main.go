package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	authBaseURL   = env("OIDC_AUTH_BASE_URL", "http://localhost:9096")
	clientID      = env("OIDC_CLIENT_ID", "222222")
	clientSecret  = env("OIDC_CLIENT_SECRET", "22222222")
	redirectURL   = env("OIDC_REDIRECT_URL", "http://localhost:9098/callback")
	codeVerifier  = env("OIDC_CODE_VERIFIER", "s256example")
	stateExpected = env("OIDC_STATE", "xyz")
)

var (
	accessToken  string
	refreshToken string
	idToken      string
	lastError    string
)

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/userinfo", handleUserInfo)

	port := os.Getenv("OIDC_CLIENT_PORT")
	if port == "" {
		port = "9098"
	}
	log.Printf("OIDC example client running at http://localhost:%s", port)
	log.Printf("Config: AUTH_BASE=%s CLIENT_ID=%s REDIRECT_URL=%s", authBaseURL, clientID, redirectURL)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	warn := ""
	if accessToken == "" {
		warn = `<div style="color:#b45309;background:#fff7ed;border:1px solid #fdba74;padding:8px;margin-bottom:8px;">No access token yet. Click "Authorize" to complete the flow. If it still fails, ensure the server has this redirect URL registered: <code>` + redirectURL + `</code>.</div>`
	}
	if lastError != "" {
		warn += `<div style="color:#991b1b;background:#fee2e2;border:1px solid #fca5a5;padding:8px;margin-bottom:8px;">` + lastError + `</div>`
	}
	fmt.Fprintf(w, `<h1>OIDC Example Client</h1>
	%s
	<ul>
		<li><a href="/register">Register test user (test/test)</a></li>
		<li><a href="/authorize">Start OIDC Authorization Code (PKCE)</a></li>
		<li><a href="/userinfo">Call UserInfo (requires access token)</a></li>
	</ul>
	<pre>access_token=%s
refresh_token=%s
id_token=%s</pre>`, warn, accessToken, refreshToken, idToken)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	payload := map[string]string{"username": "test", "password": "test"}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", authBaseURL+"/iam/v1/public/users", strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		lastError = "register request failed: " + err.Error()
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	chal := genS256(codeVerifier)
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURL}, "scope": {"openid profile"}, "state": {stateExpected}, "code_challenge": {chal}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, authBaseURL+"/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.Form.Get("state") != stateExpected {
		lastError = "invalid state returned from authorization server"
		http.Error(w, "invalid state", 400)
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		lastError = "authorization server did not return code"
		http.Error(w, "missing code", 400)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {redirectURL}, "code": {code}, "code_verifier": {codeVerifier}}
	req, _ := http.NewRequestWithContext(context.Background(), "POST", authBaseURL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		lastError = "token request failed: " + err.Error()
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		lastError = fmt.Sprintf("token endpoint returned %d: %s", resp.StatusCode, string(raw))
		http.Error(w, lastError, resp.StatusCode)
		return
	}
	var tok map[string]any
	if err := json.Unmarshal(raw, &tok); err != nil {
		lastError = "token response decode failed: " + err.Error()
		http.Error(w, err.Error(), 500)
		return
	}
	accessToken, _ = tok["access_token"].(string)
	refreshToken, _ = tok["refresh_token"].(string)
	idToken, _ = tok["id_token"].(string)
	if accessToken == "" {
		lastError = "no access_token in token response"
	} else {
		lastError = ""
	}
	respJSON(w, tok)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if accessToken == "" {
		http.Error(w, "missing access token; run /authorize first", 400)
		return
	}
	req, _ := http.NewRequest("GET", authBaseURL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		lastError = "userinfo request failed: " + err.Error()
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func genS256(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.EncodeToString(s[:])
}

func respJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
