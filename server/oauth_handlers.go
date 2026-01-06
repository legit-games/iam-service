package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/store"
)

// OAuth-related handlers and Swagger fragments

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// user authorization
	userID, err := s.UserAuthorizationHandler(w, r)
	if err != nil {
		return s.handleError(w, req, err)
	} else if userID == "" {
		return nil
	}
	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(w, r)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(w, r)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	ti, err := s.GetAuthorizeToken(ctx, req)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	return s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	if !(r.Method == "GET" || r.Method == "POST") ||
		clientID == "" {
		return nil, errors.ErrInvalidRequest
	}

	resType := oauth2.ResponseType(r.FormValue("response_type"))
	if resType.String() == "" {
		return nil, errors.ErrUnsupportedResponseType
	} else if allowed := s.CheckResponseType(resType); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	// Strict redirect URI check: when client has a registered domain, enforce that redirect_uri has that domain as prefix.
	if redirectURI != "" {
		cli, err := s.Manager.GetClient(r.Context(), clientID)
		if err != nil {
			return nil, err
		}
		if d := cli.GetDomain(); d != "" && !(redirectURI == d || strings.HasPrefix(redirectURI, strings.TrimRight(d, "/")+"/")) {
			return nil, errors.ErrInvalidRedirectURI
		}
	}

	cc := r.FormValue("code_challenge")
	// Do not enforce presence at authorize time; enforce at token exchange. Validate length if provided.
	if cc != "" && (len(cc) < 43 || len(cc) > 128) {
		return nil, errors.ErrInvalidCodeChallengeLen
	}

	ccm := oauth2.CodeChallengeMethod(r.FormValue("code_challenge_method"))
	// set default
	if ccm == "" {
		ccm = oauth2.CodeChallengePlain
	}
	if ccm != "" && !s.CheckCodeChallengeMethod(ccm) {
		return nil, errors.ErrUnsupportedCodeChallengeMethod
	}

	req := &AuthorizeRequest{
		RedirectURI:         redirectURI,
		ResponseType:        resType,
		ClientID:            clientID,
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		Request:             r,
		CodeChallenge:       cc,
		CodeChallengeMethod: ccm,
		Nonce:               r.FormValue("nonce"),
	}
	return req, nil
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt oauth2.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// CheckCodeChallengeMethod checks for allowed code challenge method
func (s *Server) CheckCodeChallengeMethod(ccm oauth2.CodeChallengeMethod) bool {
	for _, c := range s.Config.AllowedCodeChallengeMethods {
		if c == ccm {
			return true
		}
	}
	return false
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (oauth2.TokenInfo, error) {
	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {
		gt := oauth2.AuthorizationCode
		if req.ResponseType == oauth2.Token {
			gt = oauth2.Implicit
		}

		allowed, err := fn(req.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		AccessTokenExp: req.AccessTokenExp,
		Request:        req.Request,
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {
		allowed, err := fn(tgr)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrInvalidScope
		}
	}

	tgr.CodeChallenge = req.CodeChallenge
	tgr.CodeChallengeMethod = req.CodeChallengeMethod

	return s.Manager.GenerateAuthToken(ctx, req.ResponseType, tgr)
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt oauth2.ResponseType, ti oauth2.TokenInfo) map[string]interface{} {
	if rt == oauth2.Code {
		return map[string]interface{}{
			"code": ti.GetCode(),
		}
	}
	return s.GetTokenData(ti)
}

// GetTokenData token data
func (s *Server) GetTokenData(ti oauth2.TokenInfo) map[string]interface{} {
	data := map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}

	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}

	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return data
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	if v := r.Method; !(v == "POST" || (s.Config.AllowGetAccessRequest && v == "GET")) {
		return "", nil, errors.ErrInvalidRequest
	}

	gt := oauth2.GrantType(r.FormValue("grant_type"))
	if gt.String() == "" {
		return "", nil, errors.ErrUnsupportedGrantType
	}

	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return "", nil, err
	}

	// Load client and enforce confidential/public policies
	cli, err := s.Manager.GetClient(r.Context(), clientID)
	if err != nil {
		return "", nil, err
	}
	isPublic := false
	if pub, ok := cli.(interface{ IsPublic() bool }); ok {
		isPublic = pub.IsPublic()
	}
	// Confidential: require client_secret (Basic or form)
	if !isPublic {
		if clientSecret == "" && len(cli.GetSecret()) > 0 {
			return "", nil, errors.ErrInvalidClient
		}
	} else {
		// Public: must be secretless; restrict allowed grants to Authorization Code and Refresh
		// Ignore provided secret for public; if provided but client has non-empty secret registered, still treat as public
		if gt == oauth2.ClientCredentials || gt == oauth2.PasswordCredentials {
			return "", nil, errors.ErrUnauthorizedClient
		}
	}

	tgr := &oauth2.TokenGenerateRequest{ClientID: clientID, ClientSecret: clientSecret, Request: r}

	switch gt {
	case oauth2.AuthorizationCode:
		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")
		if tgr.RedirectURI == "" || tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		// Strict redirect URI check: when client has a registered domain, enforce prefix match.
		cli, err := s.Manager.GetClient(r.Context(), clientID)
		if err != nil {
			return "", nil, err
		}
		if d := cli.GetDomain(); d != "" && !(tgr.RedirectURI == d || strings.HasPrefix(tgr.RedirectURI, strings.TrimRight(d, "/")+"/")) {
			return "", nil, errors.ErrInvalidRedirectURI
		}
		// Pass through code_verifier for PKCE validation in the manager; do not hard-reject here.
		tgr.CodeVerifier = r.FormValue("code_verifier")
		// no preflight error here; manager will decide based on stored code_challenge
	case oauth2.PasswordCredentials:
		tgr.Scope = r.FormValue("scope")
		username, password := r.FormValue("username"), r.FormValue("password")
		if username == "" || password == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		userID, err := s.PasswordAuthorizationHandler(r.Context(), clientID, username, password)
		if err != nil {
			return "", nil, err
		} else if userID == "" {
			return "", nil, errors.ErrInvalidGrant
		}
		tgr.UserID = userID
	case oauth2.ClientCredentials:
		tgr.Scope = r.FormValue("scope")
	case oauth2.Refreshing:
		tgr.Refresh, err = s.RefreshTokenResolveHandler(r)
		tgr.Scope = r.FormValue("scope")
		if err != nil {
			return "", nil, err
		}
	}
	return gt, tgr, nil
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return s.tokenError(w, err)
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return s.tokenError(w, err)
	}
	// enrich context for JWT generator: namespace and permissions resolver
	ctx = context.WithValue(ctx, "ns", strings.ToUpper(strings.TrimSpace(FormValue(r, "ns"))))
	ctx = context.WithValue(ctx, "perm_resolver", func(c context.Context, userID, ns string) []string {
		// Resolve roles for user in namespace and flatten to permissions (string array)
		var out []string
		if s.userStore == nil {
			return out
		}
		// Use a read DB
		db, err := s.GetIAMReadDB()
		if err != nil {
			return out
		}
		roleStore := store.NewRoleStore(db)
		roles, err := roleStore.ListRoleAssignmentsForUser(c, userID, ns)
		if err != nil {
			return out
		}
		for _, r := range roles {
			if raw := r.Permissions; len(raw) > 0 {
				var j any
				if err := json.Unmarshal(raw, &j); err == nil {
					switch vv := j.(type) {
					case map[string]any:
						if arr, ok := vv["permissions"].([]any); ok {
							for _, v := range arr {
								if s2, ok2 := v.(string); ok2 {
									out = append(out, s2)
								}
							}
						} else {
							for k, v := range vv {
								if b, okb := v.(bool); okb && b {
									out = append(out, k)
								}
							}
						}
					case []any:
						for _, v := range vv {
							if s2, ok2 := v.(string); ok2 {
								out = append(out, s2)
							}
						}
					}
				}
			}
		}
		return out
	})
	return s.tokenWithContext(ctx, w, s.GetTokenData(ti), nil)
}

// tokenWithContext is like token() but passes custom context to access token generator
func (s *Server) tokenWithContext(ctx context.Context, w http.ResponseWriter, data map[string]interface{}, header map[string]string) error {
	if header == nil {
		header = map[string]string{}
	}
	for k, v := range header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(data)
}

// GetAccessToken access token
func (s *Server) GetAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo,
	error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	// Ban enforcement: deny access token issuance if user is banned in namespace or account is banned.
	// Determine namespace from request form (ns) or from issued token info for refresh.
	ns := strings.ToUpper(strings.TrimSpace(FormValue(tgr.Request, "ns")))
	if ns == "" {
		if v := ctx.Value("ns"); v != nil {
			if s2, ok := v.(string); ok {
				ns = strings.ToUpper(strings.TrimSpace(s2))
			}
		}
	}
	// Build permission resolver: prefer ctx-provided resolver, else default DB-backed resolver
	var permResolver func(context.Context, string, string) []string
	if rv := ctx.Value("perm_resolver"); rv != nil {
		if f, ok := rv.(func(context.Context, string, string) []string); ok {
			permResolver = f
		}
	}
	if permResolver == nil {
		permResolver = func(c context.Context, userID, ns string) []string {
			var out []string
			if s.userStore == nil {
				return out
			}
			db, err := s.GetIAMReadDB()
			if err != nil {
				return out
			}
			roleStore := store.NewRoleStore(db)
			roles, err := roleStore.ListRoleAssignmentsForUser(c, userID, ns)
			if err != nil {
				return out
			}
			for _, r := range roles {
				if raw := r.Permissions; len(raw) > 0 {
					var j any
					if err := json.Unmarshal(raw, &j); err == nil {
						switch vv := j.(type) {
						case map[string]any:
							if arr, ok := vv["permissions"].([]any); ok {
								for _, v := range arr {
									if s2, ok2 := v.(string); ok2 {
										out = append(out, s2)
									}
								}
							} else {
								for k, v := range vv {
									if b, okb := v.(bool); okb && b {
										out = append(out, k)
									}
								}
							}
						case []any:
							for _, v := range vv {
								if s2, ok2 := v.(string); ok2 {
									out = append(out, s2)
								}
							}
						}
					}
				}
			}
			return out
		}
	}
	// inject into ctx for generator
	ctx = context.WithValue(ctx, "ns", ns)
	ctx = context.WithValue(ctx, "perm_resolver", permResolver)

	switch gt {
	case oauth2.AuthorizationCode:
		// On code exchange, need to resolve userID via stored code; manager will produce ti; we can check after generate and before return.
		ti, err := s.Manager.GenerateAccessToken(ctx, gt, tgr)
		if err != nil {
			switch err {
			case errors.ErrInvalidAuthorizeCode, errors.ErrInvalidCodeChallenge, errors.ErrMissingCodeChallenge:
				return nil, errors.ErrInvalidGrant
			case errors.ErrInvalidClient:
				return nil, errors.ErrInvalidClient
			default:
				return nil, err
			}
		}
		if s.userStore != nil && ti.GetUserID() != "" && ns != "" {
			banned, berr := s.userStore.IsUserBannedByAccount(ctx, ti.GetUserID(), ns)
			if berr != nil {
				return nil, berr
			}
			if banned {
				return nil, errors.ErrUserBanned
			}
		}
		return ti, nil
	case oauth2.PasswordCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		// Ensure not banned for namespace or account
		if s.userStore != nil && tgr.UserID != "" && ns != "" {
			banned, berr := s.userStore.IsUserBannedByAccount(ctx, tgr.UserID, ns)
			if berr != nil {
				return nil, berr
			}
			if banned {
				return nil, errors.ErrUserBanned
			}
		}
		return s.Manager.GenerateAccessToken(ctx, gt, tgr)
	case oauth2.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		return s.Manager.GenerateAccessToken(ctx, gt, tgr)
	case oauth2.Refreshing:
		// On refresh, check ban for the user extracted from existing refresh token info if namespace is present.
		if scopeFn := s.RefreshingScopeHandler; tgr.Scope != "" && scopeFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}
			allowed, err := scopeFn(tgr, rti.GetScope())
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		if s.userStore != nil && ns != "" {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err == nil && rti != nil {
				uid := rti.GetUserID()
				if uid != "" {
					banned, berr := s.userStore.IsUserBannedByAccount(ctx, uid, ns)
					if berr != nil {
						return nil, berr
					}
					if banned {
						return nil, errors.ErrUserBanned
					}
				}
			}
		}

		ti, err := s.Manager.RefreshAccessToken(ctx, tgr)
		if err != nil {
			if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
				return nil, errors.ErrInvalidGrant
			}
			return nil, err
		}
		return ti, nil
	}

	return nil, errors.ErrUnsupportedGrantType
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// HandleRevocationRequest implements RFC 7009 Token Revocation.
func (s *Server) HandleRevocationRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	// client authentication (Basic or form)
	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return s.tokenError(w, errors.ErrInvalidClient)
	}
	// verify client credentials
	cli, err := s.Manager.GetClient(r.Context(), clientID)
	if err != nil {
		return s.tokenError(w, err)
	}
	if cliPass, ok := cli.(oauth2.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(clientSecret) {
			return s.tokenError(w, errors.ErrInvalidClient)
		}
	} else if len(cli.GetSecret()) > 0 && clientSecret != cli.GetSecret() {
		return s.tokenError(w, errors.ErrInvalidClient)
	}

	token := FormValue(r, "token")
	if token == "" {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	hint := FormValue(r, "token_type_hint")
	ctx := r.Context()

	// try revoke based on hint, then fallback
	success := false
	switch hint {
	case "access_token":
		if err := s.Manager.RemoveAccessToken(ctx, token); err == nil {
			success = true
		}
	case "refresh_token":
		if err := s.Manager.RemoveRefreshToken(ctx, token); err == nil {
			success = true
		}
	}
	if !success {
		// try both
		if err := s.Manager.RemoveAccessToken(ctx, token); err == nil {
			success = true
		} else if err := s.Manager.RemoveRefreshToken(ctx, token); err == nil {
			success = true
		}
	}

	// per RFC7009, always 200 OK even if the token was invalid/unknown
	w.WriteHeader(http.StatusOK)
	return nil
}

// HandleIntrospectionRequest implements RFC 7662 Token Introspection.
func (s *Server) HandleIntrospectionRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return s.tokenError(w, errors.ErrInvalidClient)
	}
	cli, err := s.Manager.GetClient(r.Context(), clientID)
	if err != nil {
		return s.tokenError(w, err)
	}
	if cliPass, ok := cli.(oauth2.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(clientSecret) {
			return s.tokenError(w, errors.ErrInvalidClient)
		}
	} else if len(cli.GetSecret()) > 0 && clientSecret != cli.GetSecret() {
		return s.tokenError(w, errors.ErrInvalidClient)
	}

	token := FormValue(r, "token")
	if token == "" {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	hint := FormValue(r, "token_type_hint")

	ctx := r.Context()
	var ti oauth2.TokenInfo
	var loadErr error

	switch hint {
	case "access_token":
		ti, loadErr = s.Manager.LoadAccessToken(ctx, token)
	case "refresh_token":
		ti, loadErr = s.Manager.LoadRefreshToken(ctx, token)
	default:
		// try access then refresh
		ti, loadErr = s.Manager.LoadAccessToken(ctx, token)
		if loadErr != nil {
			ti, loadErr = s.Manager.LoadRefreshToken(ctx, token)
		}
	}

	active := loadErr == nil && ti != nil
	resp := map[string]interface{}{
		"active": active,
	}
	if active {
		// RFC7662 fields where available
		resp["client_id"] = ti.GetClientID()
		resp["username"] = ti.GetUserID()
		resp["scope"] = ti.GetScope()
		resp["token_type"] = s.Config.TokenType
		resp["exp"] = ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix()
		resp["iat"] = ti.GetAccessCreateAt().Unix()
		resp["nbf"] = ti.GetAccessCreateAt().Unix()
		resp["sub"] = ti.GetUserID()
		resp["aud"] = ti.GetClientID()
		// iss, jti could be added when using JWT access tokens
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(resp)
}

func (s *Server) tokenError(w http.ResponseWriter, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.token(w, data, header, statusCode)
}

func (s *Server) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// --- Swagger fragments for OAuth paths ---

func (s *Server) swaggerAuthorizePath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Authorization Endpoint",
			"description": "Starts the OAuth 2.0 authorization flow. Redirect URI must match the registered client domain (prefix allowed). When ForcePKCE is enabled, code_challenge is required.",
			"parameters": []map[string]interface{}{
				{"name": "response_type", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "enum": []string{"code", "token"}}},
				{"name": "client_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
				{"name": "redirect_uri", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string", "format": "uri"}, "description": "Must equal or start with the client's registered domain."},
				{"name": "scope", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}},
				{"name": "state", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}},
				{"name": "nonce", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}, "description": "OIDC nonce to bind to the ID token."},
				{"name": "code_challenge", "in": "query", "required": s.Config != nil && s.Config.ForcePKCE, "schema": map[string]interface{}{"type": "string"}, "description": "Required when PKCE is enforced."},
				{"name": "code_challenge_method", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string", "enum": []string{"plain", "S256"}}},
			},
			"responses": map[string]interface{}{"302": map[string]interface{}{"description": "Redirect with code or token"}, "400": map[string]interface{}{"description": "Invalid request"}, "401": map[string]interface{}{"description": "Unauthorized client"}},
		},
	}
}

func (s *Server) swaggerTokenPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Token Endpoint",
			"description": "Issues tokens for supported grant types. Confidential clients must authenticate via Basic or form client_secret. Public clients are restricted to Authorization Code (with PKCE) and Refresh Token grants.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/x-www-form-urlencoded": map[string]interface{}{
						"schema": map[string]interface{}{"type": "object"},
						"examples": map[string]interface{}{
							"client_credentials": map[string]interface{}{"value": "grant_type=client_credentials&client_id=confidential&client_secret=secret", "summary": "Confidential client only"},
							"authorization_code": map[string]interface{}{"value": "grant_type=authorization_code&code=XXX&redirect_uri=...&code_verifier=...", "summary": "PKCE required when enforced"},
							"password":           map[string]interface{}{"value": "grant_type=password&username=foo&password=bar&client_id=confidential&client_secret=secret", "summary": "Discouraged; not allowed for public clients"},
							"refresh_token":      map[string]interface{}{"value": "grant_type=refresh_token&refresh_token=XXX", "summary": "Refresh token rotation enabled"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Token response",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
								"access_token":  map[string]interface{}{"type": "string"},
								"token_type":    map[string]interface{}{"type": "string"},
								"expires_in":    map[string]interface{}{"type": "integer"},
								"refresh_token": map[string]interface{}{"type": "string"},
								"scope":         map[string]interface{}{"type": "string"},
							}},
						},
					},
				},
				"400": map[string]interface{}{"description": "Invalid request"},
				"401": map[string]interface{}{"description": "Unauthorized client"},
			},
			"security": []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}

func (s *Server) swaggerIntrospectPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7662 Token Introspection",
			"description": "Introspects access or refresh tokens. Confidential clients must authenticate via Basic or form.",
			"requestBody": map[string]interface{}{"required": true, "content": map[string]interface{}{"application/x-www-form-urlencoded": map[string]interface{}{"schema": map[string]interface{}{"type": "object"}}}},
			"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Introspection result"}, "401": map[string]interface{}{"description": "Unauthorized client"}},
			"security":    []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}

func (s *Server) swaggerRevokePath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7009 Token Revocation",
			"description": "Revokes an access or refresh token. Confidential clients must authenticate using Basic or form parameters. Per RFC 7009, successful revocation returns 200 even if the token is invalid or already revoked.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/x-www-form-urlencoded": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"token":           map[string]interface{}{"type": "string", "description": "The token to revoke (access token or refresh token)."},
								"token_type_hint": map[string]interface{}{"type": "string", "description": "Optional hint of the token type: 'access_token' or 'refresh_token'."},
								"client_id":       map[string]interface{}{"type": "string", "description": "Client ID (if not using Basic auth)."},
								"client_secret":   map[string]interface{}{"type": "string", "description": "Client secret (if not using Basic auth)."},
							},
							"required": []string{"token"},
						},
						"examples": map[string]interface{}{
							"access_token":     map[string]interface{}{"value": "token=eyJhbGciOi...&token_type_hint=access_token"},
							"refresh_token":    map[string]interface{}{"value": "token=def502...&token_type_hint=refresh_token"},
							"form_client_auth": map[string]interface{}{"value": "token=eyJ...&client_id=my-client&client_secret=s3cr3t"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Revocation acknowledged (token invalidated or was already invalid)",
					"content":     map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object"}}},
				},
				"400": map[string]interface{}{
					"description": "Invalid request (e.g., missing token)",
					"content":     map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"error": map[string]interface{}{"type": "string"}, "error_description": map[string]interface{}{"type": "string"}}}}},
				},
				"401": map[string]interface{}{
					"description": "Unauthorized client",
					"content":     map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"error": map[string]interface{}{"type": "string"}, "error_description": map[string]interface{}{"type": "string"}}}}},
				},
			},
			"security": []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}
