package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

	// centralized DB handles (lazy-initialized)
	dbMu      sync.Mutex
	userRead  *gorm.DB
	userWrite *gorm.DB
	primary   *gorm.DB
}

// GetPrimaryDB returns a shared primary connection based on user DSNs.
func (s *Server) GetPrimaryDB() (*gorm.DB, error) {
	cfg := GetConfig()
	candidates := []string{
		strings.TrimSpace(cfg.UserWriteDSN()),
		strings.TrimSpace(cfg.UserReadDSN()),
	}
	var dsn string
	for _, v := range candidates {
		if v != "" {
			dsn = v
			break
		}
	}
	if dsn == "" {
		return nil, ErrUserDBDSNNotSet
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.primary != nil {
		return s.primary, nil
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	s.primary = db
	// Also seed regWrite/userRead caches to the same pointer for consistency
	s.userWrite = db
	s.userRead = db
	return db, nil
}

// GetIAMReadDB returns the accounts read DB.
func (s *Server) GetIAMReadDB() (*gorm.DB, error) {
	dsn := GetConfig().UserReadDSN()
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrUserDBDSNNotSet
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.userWrite != nil {
		return s.userWrite, nil
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	s.userWrite = db
	return db, nil
}

// GetIAMWriteDB returns the accounts write DB.
func (s *Server) GetIAMWriteDB() (*gorm.DB, error) {
	dsn := GetConfig().UserWriteDSN()
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrUserDBDSNNotSet
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.userWrite != nil {
		return s.userWrite, nil
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	s.userWrite = db
	return db, nil
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
