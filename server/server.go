package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"database/sql"

	_ "github.com/lib/pq"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager oauth2.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handlers
	srv.ClientInfoHandler = ClientBasicHandler
	srv.RefreshTokenResolveHandler = RefreshTokenFormResolveHandler
	srv.AccessTokenResolveHandler = AccessTokenDefaultResolveHandler

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(ctx context.Context, clientID, username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}
	return srv
}

// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      oauth2.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingValidationHandler  RefreshingValidationHandler
	PreRedirectErrorHandler      PreRedirectErrorHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
	ResponseTokenHandler         ResponseTokenHandler
	RefreshTokenResolveHandler   RefreshTokenResolveHandler
	AccessTokenResolveHandler    AccessTokenResolveHandler
}

func (s *Server) handleError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(w, req, err)
	}

	return s.redirectError(w, req, err)
}

func (s *Server) redirectError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)
	return s.redirect(w, req, data)
}

func (s *Server) redirect(w http.ResponseWriter, req *AuthorizeRequest, data map[string]interface{}) error {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return err
	}

	w.Header().Set("Location", uri)
	w.WriteHeader(302)
	return nil
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

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case oauth2.Code:
		u.RawQuery = q.Encode()
	case oauth2.Token:
		u.RawQuery = ""
		fragment, err := url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
		u.Fragment = fragment
	}

	return u.String(), nil
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

	cc := r.FormValue("code_challenge")
	if cc == "" && s.Config.ForcePKCE {
		return nil, errors.ErrCodeChallengeRquired
	}
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
	}
	return req, nil
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

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	if v := r.Method; !(v == "POST" ||
		(s.Config.AllowGetAccessRequest && v == "GET")) {
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

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Request:      r,
	}

	switch gt {
	case oauth2.AuthorizationCode:
		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")
		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		tgr.CodeVerifier = r.FormValue("code_verifier")
		if s.Config.ForcePKCE && tgr.CodeVerifier == "" {
			return "", nil, errors.ErrInvalidRequest
		}
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

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
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

	switch gt {
	case oauth2.AuthorizationCode:
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
		return ti, nil
	case oauth2.PasswordCredentials, oauth2.ClientCredentials:
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
		// check scope
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

		if validationFn := s.RefreshingValidationHandler; validationFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}
			allowed, err := validationFn(rti)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
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

	return s.token(w, s.GetTokenData(ti), nil)
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (map[string]interface{}, int, http.Header) {
	var re errors.Response
	if v, ok := errors.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if v := fn(err); v != nil {
				re = *v
			}
		}

		if re.Error == nil {
			re.Error = errors.ErrServerError
			re.Description = errors.Descriptions[errors.ErrServerError]
			re.StatusCode = errors.StatusCodes[errors.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(&re)
	}

	data := make(map[string]interface{})
	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}

	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}

	if v := re.Description; v != "" {
		data["error_description"] = v
	}

	if v := re.URI; v != "" {
		data["error_uri"] = v
	}

	statusCode := http.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}

	return data, statusCode, re.Header
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(r *http.Request) (oauth2.TokenInfo, error) {
	ctx := r.Context()

	accessToken, ok := s.AccessTokenResolveHandler(r)
	if !ok {
		return nil, errors.ErrInvalidAccessToken
	}

	return s.Manager.LoadAccessToken(ctx, accessToken)
}

// HandleRevocationRequest implements RFC 7009 Token Revocation.
// POST with form fields: token (required), token_type_hint (optional: access_token|refresh_token).
// Successful revocation MUST return 200 OK with empty body.
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
// Requires client authentication. Returns token metadata JSON.
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

// HandleClientRegistrationRequest implements a minimal RFC 7591 Dynamic Client Registration.
// Persists client into PostgreSQL table oauth2_clients. Configure DSN via REG_DB_DSN env var.
func (s *Server) HandleClientRegistrationRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	dsn := strings.TrimSpace(os.Getenv("REG_DB_DSN"))
	if dsn == "" {
		w.WriteHeader(http.StatusNotImplemented)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "not_implemented",
			"error_description": "set REG_DB_DSN to enable PostgreSQL-backed client registration",
		})
	}

	// Parse JSON input (subset of RFC 7591). Accepts optional client_id, client_secret, redirect_uris.
	var payload struct {
		ClientID                string   `json:"client_id"`
		ClientSecret            string   `json:"client_secret"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload",
		})
	}

	// Generate client_id/secret if not provided
	if strings.TrimSpace(payload.ClientID) == "" {
		payload.ClientID = genRandomID(24)
	}
	if strings.TrimSpace(payload.ClientSecret) == "" {
		payload.ClientSecret = genRandomID(32)
	}
	// Domain (redirect_uri) required for this implementation; use first redirect_uris entry
	domain := ""
	if len(payload.RedirectURIs) > 0 {
		domain = payload.RedirectURIs[0]
	}
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_client_metadata",
			"error_description": "redirect_uris is required",
		})
	}

	// Insert into Postgres
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(
		`INSERT INTO oauth2_clients (id, secret, domain, user_id, created_at) VALUES ($1, $2, $3, $4, NOW())`,
		payload.ClientID, payload.ClientSecret, domain, "",
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("insert client: %v", err),
		})
	}

	// Success response (subset of RFC 7591)
	resp := map[string]interface{}{
		"client_id":                  payload.ClientID,
		"client_secret":              payload.ClientSecret,
		"redirect_uris":              payload.RedirectURIs,
		"client_name":                payload.ClientName,
		"token_endpoint_auth_method": payload.TokenEndpointAuthMethod,
		"client_id_issued_at":        time.Now().Unix(),
	}
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(resp)
}

// genRandomID generates a hex string of n bytes length.
func genRandomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Swagger / OpenAPI support ---

// path spec builders allow each endpoint to co-locate and maintain its API docs.
func (s *Server) swaggerAuthorizePath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary": "Authorization Endpoint",
			"parameters": []map[string]interface{}{
				{"name": "response_type", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string", "enum": []string{"code", "token"}}},
				{"name": "client_id", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
				{"name": "redirect_uri", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string", "format": "uri"}},
				{"name": "scope", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}},
				{"name": "state", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}},
				{"name": "code_challenge", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string"}},
				{"name": "code_challenge_method", "in": "query", "required": false, "schema": map[string]interface{}{"type": "string", "enum": []string{"plain", "S256"}}},
			},
			"responses": map[string]interface{}{"302": map[string]interface{}{"description": "Redirect with code or token"}},
		},
	}
}

func (s *Server) swaggerTokenPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary": "Token Endpoint",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/x-www-form-urlencoded": map[string]interface{}{
						"schema": map[string]interface{}{"type": "object"},
						"examples": map[string]interface{}{
							"client_credentials": map[string]interface{}{"value": "grant_type=client_credentials&scope=read"},
							"authorization_code": map[string]interface{}{"value": "grant_type=authorization_code&code=XXX&redirect_uri=..."},
							"password":           map[string]interface{}{"value": "grant_type=password&username=foo&password=bar"},
							"refresh_token":      map[string]interface{}{"value": "grant_type=refresh_token&refresh_token=XXX"},
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
			},
		},
	}
}

func (s *Server) swaggerIntrospectPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7662 Token Introspection",
			"requestBody": map[string]interface{}{"required": true, "content": map[string]interface{}{"application/x-www-form-urlencoded": map[string]interface{}{"schema": map[string]interface{}{"type": "object"}}}},
			"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Introspection result"}},
			"security":    []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}

func (s *Server) swaggerRevokePath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7009 Token Revocation",
			"description": "Revokes an access or refresh token. The client must authenticate using Basic auth or form parameters. Per RFC 7009, successful revocation returns 200 even if the token is invalid or already revoked.",
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

func (s *Server) swaggerRegisterPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7591 Dynamic Client Registration",
			"description": "Registers a new OAuth2 client. When REG_DB_DSN is configured, persists to PostgreSQL and returns 201.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"client_id":                  map[string]interface{}{"type": "string"},
								"client_secret":              map[string]interface{}{"type": "string"},
								"redirect_uris":              map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "format": "uri"}},
								"client_name":                map[string]interface{}{"type": "string"},
								"token_endpoint_auth_method": map[string]interface{}{"type": "string"},
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{
					"description": "Client registered",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"client_id":                  map[string]interface{}{"type": "string"},
									"client_secret":              map[string]interface{}{"type": "string"},
									"redirect_uris":              map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "format": "uri"}},
									"client_name":                map[string]interface{}{"type": "string"},
									"token_endpoint_auth_method": map[string]interface{}{"type": "string"},
									"client_id_issued_at":        map[string]interface{}{"type": "integer", "format": "int64"},
								},
							},
						},
					},
				},
				"501": map[string]interface{}{
					"description": "Not Implemented (REG_DB_DSN not set)",
				},
			},
		},
	}
}

// HandleSwaggerJSON serves an OpenAPI 3.0 spec that documents the available endpoints.
func (s *Server) HandleSwaggerJSON(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "OAuth2 Authorization Server",
			"version":     "1.0.0",
			"description": "OpenAPI for OAuth2 endpoints (RFC 6749, 6750, 7009, 7662, 7591).",
		},
		"servers": []map[string]interface{}{{"url": "/"}},
		"paths": map[string]interface{}{
			"/oauth/authorize":  s.swaggerAuthorizePath(),
			"/oauth/token":      s.swaggerTokenPath(),
			"/oauth/introspect": s.swaggerIntrospectPath(),
			"/oauth/revoke":     s.swaggerRevokePath(),
			"/register":         s.swaggerRegisterPath(),
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{"basicAuth": map[string]interface{}{"type": "http", "scheme": "basic"}},
		},
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(spec)
}

// HandleSwaggerUI serves a minimal Swagger UI that points to /swagger.json
func (s *Server) HandleSwaggerUI(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	html := `<!doctype html><html><head><meta charset="utf-8"/><title>Swagger UI</title>
	<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
	</head><body><div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
	<script>window.ui = SwaggerUIBundle({ url: '/swagger.json', dom_id: '#swagger-ui' });</script>
	</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
	return nil
}
