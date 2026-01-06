package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	// use local store package
	"github.com/go-oauth2/oauth2/v4/store"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager oauth2.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	s := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handlers
	s.ClientInfoHandler = ClientBasicHandler
	s.RefreshTokenResolveHandler = RefreshTokenFormResolveHandler
	s.AccessTokenResolveHandler = AccessTokenDefaultResolveHandler

	s.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "", errors.ErrAccessDenied
	}

	s.PasswordAuthorizationHandler = func(ctx context.Context, clientID, username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}

	// OIDC setup: generate RSA key and attach id_token via ExtensionFieldsHandler
	if s.Config != nil && s.Config.OIDCEnabled {
		_ = s.ensureOIDCKeys()
		prevExt := s.ExtensionFieldsHandler
		s.ExtensionFieldsHandler = func(ti oauth2.TokenInfo) map[string]interface{} {
			fields := map[string]interface{}{}
			if prevExt != nil {
				for k, v := range prevExt(ti) {
					fields[k] = v
				}
			}
			if strings.Contains(" "+ti.GetScope()+" ", " openid ") {
				if idt, err := s.signIDToken(ti); err == nil && idt != "" {
					fields["id_token"] = idt
				}
			}
			return fields
		}
	}

	// initialize stores if DB available
	if db, err := s.GetPrimaryDB(); err == nil {
		s.nsStore = store.NewNamespaceStore(db)
		s.userStore = store.NewUserStore(db)
	}
	// gin routes will be registered via NewGinEngine

	// Apply operator-configured refresh rotation to manager
	if m, ok := manager.(*manage.Manager); ok && cfg != nil {
		rc := &manage.RefreshingConfig{
			IsGenerateRefresh:  cfg.RefreshRotation.GenerateNew,
			IsResetRefreshTime: cfg.RefreshRotation.ResetTime,
			IsRemoveAccess:     cfg.RefreshRotation.RemoveOldAccess,
			IsRemoveRefreshing: cfg.RefreshRotation.RemoveOldRefresh,
		}
		if cfg.RefreshRotation.AccessExpOverride > 0 {
			rc.AccessTokenExp = cfg.RefreshRotation.AccessExpOverride
		}
		if cfg.RefreshRotation.RefreshExpOverride > 0 {
			rc.RefreshTokenExp = cfg.RefreshRotation.RefreshExpOverride
		}
		m.SetRefreshTokenCfg(rc)
	}

	return s
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

	nsStore   *store.NamespaceStore
	userStore *store.UserStore

	// centralized DB handles (lazy-initialized)
	dbMu      sync.Mutex
	userRead  *gorm.DB
	userWrite *gorm.DB
	primary   *gorm.DB

	// OIDC signing state
	kid     string
	privKey *rsa.PrivateKey

	// App configuration
	appConfig *Config
}

func (s *Server) ensureOIDCKeys() error {
	if s.privKey != nil {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.privKey = key
	// simple kid value; in production, use stable rotation strategy
	s.kid = "k1"
	return nil
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	s.userWrite = db
	return db, nil
}

// LoadAppConfig loads the application configuration
func LoadAppConfig() (*Config, error) {
	// For testing purposes, return a default config
	// In production, this would load from actual config files
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		OIDCEnabled: false,
		RefreshRotation: RefreshRotationConfig{
			GenerateNew:        true,
			ResetTime:          true,
			RemoveOldAccess:    true,
			RemoveOldRefresh:   true,
			AccessExpOverride:  0,
			RefreshExpOverride: 0,
		},
	}, nil
}

// Initialize initializes the server with configuration and database connections
func (s *Server) Initialize() error {
	// Load configuration
	cfg, err := LoadAppConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	s.appConfig = cfg

	// Initialize database connections
	err = s.initializeDatabases()
	if err != nil {
		return fmt.Errorf("failed to initialize databases: %w", err)
	}

	// Initialize OAuth manager if not already set
	if s.Manager == nil {
		m := manage.NewDefaultManager()
		m.MustTokenStorage(store.NewMemoryTokenStore())

		// Setup client store from database
		if db, err := s.GetPrimaryDB(); err == nil {
			m.MapClientStorage(store.NewDBClientStore(db))
		}

		s.Manager = m
	}

	// Set default configuration if not already set
	if s.Config == nil {
		s.Config = &Config{
			TokenType:            "Bearer",
			AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
			AllowedGrantTypes: []oauth2.GrantType{
				oauth2.AuthorizationCode,
				oauth2.PasswordCredentials,
				oauth2.ClientCredentials,
				oauth2.Refreshing,
			},
		}
	}

	// Setup default handlers
	s.SetClientInfoHandler(ClientFormHandler)

	return nil
}

// initializeDatabases initializes database connections
func (s *Server) initializeDatabases() error {
	// This will trigger the lazy initialization of databases
	_, err := s.GetPrimaryDB()
	if err != nil {
		return fmt.Errorf("failed to initialize primary DB: %w", err)
	}

	// Initialize stores if DB is available
	if db, err := s.GetPrimaryDB(); err == nil {
		s.nsStore = store.NewNamespaceStore(db)
		s.userStore = store.NewUserStore(db)
	}

	return nil
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
