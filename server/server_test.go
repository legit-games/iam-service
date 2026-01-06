package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

var (
	srv          *Server
	tsrv         *httptest.Server
	manager      *manage.Manager
	csrv         *httptest.Server
	clientID     = "111111"
	clientSecret = "11111111"

	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	s256Challenge  = "s256tests256tests256tests256tests256tests256test"
	// sha2562 := sha256.Sum256([]byte(s256Challenge))
	// fmt.Printf(base64.URLEncoding.EncodeToString(sha2562[:]))
	s256ChallengeHash = "To2Xqv01cm16bC9Sf7KRRS8CO2SFss_HSMQOr3sdCDE="
)

func init() {
	manager = manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
}

func clientStore(domain string, public bool) oauth2.ClientStore {
	clientStore := store.NewClientStore()
	var secret string
	if public {
		secret = ""
	} else {
		secret = clientSecret
	}
	_ = clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: secret,
		Domain: domain,
		Public: public,
	})
	return clientStore
}

func testServer(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "/token":
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestAuthorizeCode(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengePlain(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", plainChallenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})
	srv.SetClientInfoHandler(ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", plainChallenge).
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengeS256(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", s256Challenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})
	srv.SetClientInfoHandler(ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)
}

func TestImplicit(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, false))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "token").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestImplicitFlowDisabled(t *testing.T) {
	// setup manager and server
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	s := NewDefaultServer(m)
	// build gin engine with our server
	r := NewGinEngine(s)
	srv := httptest.NewServer(r)
	defer srv.Close()

	e := httpexpect.New(t, srv.URL)
	// call authorize with response_type=token (implicit) -> expect 400
	obj := e.GET("/oauth/authorize").
		WithQuery("response_type", "token").
		WithQuery("client_id", "dummy").
		WithQuery("redirect_uri", "http://localhost/callback").
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object()
	obj.Value("error").String().Equal("unsupported_response_type")
	obj.Value("error_description").String().Contains("Implicit flow is disabled")
}

func TestPasswordCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))
	srv = NewDefaultServer(manager)
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "admin" && password == "123456" {
			userID = "000000"
			return
		}
		err = fmt.Errorf("user not found")
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "admin").
		WithFormField("password", "123456").
		WithFormField("scope", "all").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestClientCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))

	srv = NewDefaultServer(manager)
	srv.SetClientInfoHandler(ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	srv.SetAllowedGrantType(oauth2.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestClientCredentials_PermissionsInJWT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// inline server for this test
		m := manage.NewDefaultManager()
		m.MustTokenStorage(store.NewMemoryTokenStore())
		m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
		cliStore := store.NewClientStore()
		_ = cliStore.Set("confidential", &models.Client{ID: "confidential", Secret: "secret", Permissions: []string{"ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_READ"}})
		m.MapClientStorage(cliStore)
		s := NewDefaultServer(m)
		s.SetAllowedGrantType(oauth2.ClientCredentials)
		s.SetClientInfoHandler(ClientFormHandler)
		if r.URL.Path == "/token" {
			_ = s.HandleTokenRequest(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	e := httpexpect.New(t, ts.URL)
	obj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		Expect().
		Status(http.StatusOK).
		JSON().Object()
	access := obj.Value("access_token").String().Raw()
	if access == "" {
		t.Fatalf("no access token returned")
	}
	parts := strings.Split(access, ".")
	if len(parts) < 2 {
		t.Fatalf("invalid jwt")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	perms, ok := claims["permissions"].([]any)
	if !ok || len(perms) == 0 {
		t.Fatalf("expected permissions in jwt, got: %v", claims)
	}
}

func TestRefreshing(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			jresObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", jresObj.Raw())

			validationAccessToken(t, jresObj.Value("access_token").String().Raw())

			resObj := e.POST("/token").
				WithFormField("grant_type", "refresh_token").
				WithFormField("scope", "one").
				WithFormField("refresh_token", jresObj.Value("refresh_token").String().Raw()).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

// validation access token
func validationAccessToken(t *testing.T, accessToken string) {
	req := httptest.NewRequest("GET", "http://example.com", nil)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	ti, err := srv.ValidationBearerToken(req)
	if err != nil {
		t.Error(err.Error())
		return
	}
	if ti.GetClientID() != clientID {
		t.Error("invalid access token")
	}
}

func TestTokenResponseContainsStandardFieldsOnly(t *testing.T) {
	m := manage.NewDefaultManager()
	m.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	m.MapAccessGenerate(generates.NewAccessGenerate())
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("clientA", &models.Client{ID: "clientA", Secret: "secretA", Domain: "http://localhost"})
	m.MapClientStorage(cs)
	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)
	// prepare a client_credentials grant request
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"clientA"},
		"client_secret": {"secretA"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	if err := s.HandleTokenRequest(w, r); err != nil {
		t.Fatalf("HandleTokenRequest error: %v", err)
	}
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// standard fields
	for _, k := range []string{"access_token", "token_type", "expires_in"} {
		if _, ok := resp[k]; !ok {
			t.Fatalf("missing standard field %s in response: %v", k, resp)
		}
	}
	// optional refresh_token may be absent; if present must be string
	if v, ok := resp["refresh_token"]; ok {
		if _, ok2 := v.(string); !ok2 {
			t.Fatalf("refresh_token must be a string, got: %T", v)
		}
	}
	// non-standard must be absent
	if _, ok := resp["access_exp_at"]; ok {
		t.Fatalf("unexpected non-standard field access_exp_at present: %v", resp)
	}
	if _, ok := resp["refresh_exp_at"]; ok {
		t.Fatalf("unexpected non-standard field refresh_exp_at present: %v", resp)
	}
	if _, ok := resp["expiry"]; ok {
		t.Fatalf("unexpected non-standard field expiry present: %v", resp)
	}
}

func TestRedirectURIValidation_PrefixUnit_Success(t *testing.T) {
	// Setup server with client domain
	manager.MapClientStorage(clientStore("http://example.com", true))
	s := NewDefaultServer(manager)
	// Build request
	r := httptest.NewRequest("GET", "/oauth/authorize", nil)
	q := r.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://example.com/oauth2/callback")
	r.URL.RawQuery = q.Encode()
	// Validate
	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.RedirectURI != "http://example.com/oauth2/callback" {
		t.Fatalf("redirect mismatch: %s", req.RedirectURI)
	}
}

func TestRedirectURIValidation_PrefixUnit_Invalid(t *testing.T) {
	manager.MapClientStorage(clientStore("http://example.com", true))
	s := NewDefaultServer(manager)
	r := httptest.NewRequest("GET", "/oauth/authorize", nil)
	q := r.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://evil.com/callback")
	r.URL.RawQuery = q.Encode()
	_, err := s.ValidationAuthorizeRequest(r)
	if err == nil {
		t.Fatalf("expected invalid redirect error, got nil")
	}
}

func TestPublicClient_DisallowPasswordAndClientCredentials(t *testing.T) {
	// Setup server with a public client (no secret)
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("pub", &models.Client{ID: "pub", Secret: "", Domain: "http://localhost", Public: true})
	m.MapClientStorage(cs)
	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)

	// Password grant should be unauthorized_client -> expect 401
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"password"},
		"client_id":  {"pub"},
		"username":   {"alice"},
		"password":   {"pass"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	_ = s.HandleTokenRequest(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for public password grant, got %d", w.Code)
	}
	// Client credentials should be unauthorized_client -> expect 401
	r2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"pub"},
		"client_secret": {""},
	}.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	_ = s.HandleTokenRequest(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for public client_credentials, got %d", w2.Code)
	}
}

func TestConfidentialClient_RequiresSecret(t *testing.T) {
	// Setup confidential client with a secret
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("conf", &models.Client{ID: "conf", Secret: "s3cr3t", Domain: "http://localhost", Public: false})
	m.MapClientStorage(cs)
	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)

	// Try client_credentials without providing secret -> invalid_client -> expect 401
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"conf"},
		// missing client_secret
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	_ = s.HandleTokenRequest(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing secret, got %d", w.Code)
	}
}

func TestForcePKCE_DeniesMissingCodeVerifier(t *testing.T) {
	// Setup public client with domain for authorize flow
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("pub", &models.Client{ID: "pub", Secret: "", Domain: "http://localhost", Public: true})
	m.MapClientStorage(cs)
	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)

	// First: authorize request with code_challenge (to pass authorize validation)
	ar := httptest.NewRequest("GET", "/oauth/authorize", nil)
	q := ar.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "pub")
	q.Set("redirect_uri", "http://localhost/callback")
	q.Set("code_challenge", "ThisIsAFourtyThreeCharactersLongStringThing")
	ar.URL.RawQuery = q.Encode()
	aw := httptest.NewRecorder()
	_ = s.HandleAuthorizeRequest(aw, ar)
	// Simulate token request missing code_verifier -> invalid_request due to ForcePKCE -> expect 401
	tr := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {"pub"},
		"redirect_uri": {"http://localhost/callback"},
		"code":         {"dummy_code"},
	}.Encode()))
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	_ = s.HandleTokenRequest(tw, tr)
	if tw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing code_verifier, got %d", tw.Code)
	}
}

func TestRefreshTokenRotation_ReuseDetection(t *testing.T) {
	// Setup server with explicit token store
	m := manage.NewDefaultManager()
	m.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	m.MapAccessGenerate(generates.NewAccessGenerate())
	ts, _ := store.NewMemoryTokenStore()
	m.MapTokenStorage(ts)
	cs := store.NewClientStore()
	cs.Set("clientB", &models.Client{ID: "clientB", Secret: "secretB", Domain: "http://localhost"})
	m.MapClientStorage(cs)
	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)

	// Insert an initial token with a refresh into the store
	ti := models.NewToken()
	ti.SetClientID("clientB")
	ti.SetAccess("accessX")
	ti.SetAccessCreateAt(time.Now())
	ti.SetAccessExpiresIn(time.Hour)
	ti.SetRefresh("refreshX")
	ti.SetRefreshCreateAt(time.Now())
	ti.SetRefreshExpiresIn(time.Hour)
	_ = ts.Create(context.Background(), ti)

	refresh := "refreshX"
	// First use of refresh should succeed (rotation occurs)
	r2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"clientB"},
		"client_secret": {"secretB"},
		"refresh_token": {refresh},
	}.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	_ = s.HandleTokenRequest(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("first refresh expected 200, got %d", w2.Code)
	}
	// Second use of the same refresh should be rejected due to reuse detection (expect 401 invalid_grant)
	r3 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"clientB"},
		"client_secret": {"secretB"},
		"refresh_token": {refresh},
	}.Encode()))
	r3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	_ = s.HandleTokenRequest(w3, r3)
	if w3.Code == http.StatusOK {
		t.Fatalf("expected reuse detection to fail, got 200")
	}
}
