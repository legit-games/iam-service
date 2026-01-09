package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/go-oauth2/oauth2/v4/generates"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	// migrations and seed data on start (optional)
	"github.com/go-oauth2/oauth2/v4/migrate"
	"github.com/go-oauth2/oauth2/v4/seed"
)

//go:embed static/*
var staticFS embed.FS

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
	globalSrv *server.Server // Global server reference for login handler
)

func init() {
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "222222", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "22222222", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:9098", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}

	// Optionally run DB migrations (like flyway) before server starts.
	// Configure via environment variables (see migrate.RunFromEnv docs):
	// MIGRATE_ON_START=1 MIGRATE_DRIVER=sqlite MIGRATE_DSN=./oauth2.db
	if err := migrate.RunFromEnv(); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	// Optionally run seed data after migrations.
	// Configure via environment variables (see seed.RunFromEnv docs):
	// SEED_ON_START=1 (uses same MIGRATE_DRIVER and MIGRATE_DSN by default)
	if err := seed.RunFromEnv(); err != nil {
		log.Fatalf("seed failed: %v", err)
	}

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store: prefer Valkey when VALKEY_ADDR provided; else memory
	valkeyAddr := os.Getenv("VALKEY_ADDR")
	if valkeyAddr == "" {
		valkeyAddr = "127.0.0.1:6379"
	}
	// Try Valkey first, then fallback to memory
	if _, err := store.NewValkeyTokenStore(valkeyAddr, "oauth2:"); err == nil {
		manager.MustTokenStorage(store.NewValkeyTokenStore(valkeyAddr, "oauth2:"))
		log.Printf("Using Valkey token store at %s", valkeyAddr)
	} else {
		log.Printf("Valkey not available (%v), falling back to memory store", err)
		manager.MustTokenStorage(store.NewMemoryTokenStore())
	}

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	// If you prefer opaque tokens, switch back to generates.NewAccessGenerate()
	// manager.MapAccessGenerate(generates.NewAccessGenerate())

	// Create server first to access DB
	srv := server.NewServer(server.NewConfig(), manager)
	globalSrv = srv // Set global reference for login handler

	// Use DB client store if available, fallback to in-memory
	if db, err := srv.GetPrimaryDB(); err == nil && db != nil {
		dbClientStore := store.NewDBClientStore(db)
		manager.MapClientStorage(dbClientStore)
		log.Println("Using database client store")
	} else {
		clientStore := store.NewClientStore()
		clientStore.Set(idvar, &models.Client{
			ID:     idvar,
			Secret: secretvar,
			Domain: domainvar,
		})
		manager.MapClientStorage(clientStore)
		log.Printf("Using in-memory client store: id=%s redirect_domain=%s", idvar, domainvar)
	}

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		} else {
			err = errors.New("invalid username or password")
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// Allow basic or form auth globally for revoke/introspect endpoints
	srv.SetClientInfoHandler(server.ClientBasicOrFormHandler)

	// Build Gin engine and replace net/http mux completely
	engine := server.NewGinEngine(srv)

	// Existing custom endpoints using net/http handlers can be wrapped for Gin
	engine.GET("/login", func(c *gin.Context) { loginHandler(c.Writer, c.Request) })
	engine.POST("/login", func(c *gin.Context) { loginHandler(c.Writer, c.Request) })
	engine.GET("/auth", func(c *gin.Context) { authHandler(c.Writer, c.Request) })
	engine.GET("/test", func(c *gin.Context) {
		// reuse logic with net/http signature
		if dumpvar {
			_ = dumpRequest(os.Stdout, "test", c.Request)
		}
		token, err := srv.ValidationBearerToken(c.Request)
		if err != nil {
			http.Error(c.Writer, err.Error(), http.StatusBadRequest)
			return
		}
		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(c.Writer)
		e.SetIndent("", "  ")
		_ = e.Encode(data)
	})

	log.Printf("Server is running at %d port.", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	log.Fatal(engine.Run(fmt.Sprintf(":%d", portvar)))
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		log.Printf("userAuthorizeHandler: session.Start error: %v", err)
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	log.Printf("userAuthorizeHandler: LoggedInUserID found=%v, value=%v", ok, uid)
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}
		// Store OAuth params in session (backup) and pass via URL query
		store.Set("ReturnUri", r.Form)
		store.Save()

		// Pass OAuth params via URL to avoid session issues across redirects
		redirectURL := "/login?" + r.URL.RawQuery
		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "login", r) // Ignore the error
	}
	sessionStore, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store OAuth params from URL query in session for later use
	// Don't overwrite OAuth params with error params (from failed login redirect)
	if r.URL.RawQuery != "" && r.Method == "GET" {
		params, _ := url.ParseQuery(r.URL.RawQuery)
		if params.Get("error") == "" {
			sessionStore.Set("OAuthQuery", r.URL.RawQuery)
			sessionStore.Save()
		}
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Try database authentication first
		var userID string
		var authenticated bool

		if globalSrv != nil {
			if db, err := globalSrv.GetPrimaryDB(); err == nil && db != nil {
				var accountID, passwordHash string
				row := db.Raw("SELECT id, password_hash FROM accounts WHERE username = ?", username).Row()
				if err := row.Scan(&accountID, &passwordHash); err == nil {
					if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil {
						userID = accountID
						authenticated = true
					}
				}
			}
		}

		// Fallback to test/test for backward compatibility
		if !authenticated && username == "test" && password == "test" {
			userID = "test"
			authenticated = true
		}

		if authenticated {
			sessionStore.Set("LoggedInUserID", userID)
			sessionStore.Save()

			// Record login history
			if globalSrv != nil {
				if db, err := globalSrv.GetPrimaryDB(); err == nil && db != nil {
					loginID := models.LegitID()
					ipAddress := r.RemoteAddr
					if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
						ipAddress = strings.Split(xff, ",")[0]
					}
					userAgent := r.Header.Get("User-Agent")
					db.Exec("INSERT INTO login_history (id, account_id, ip_address, user_agent, success) VALUES (?, ?, ?, ?, ?)",
						loginID, userID, ipAddress, userAgent, true)
				}
			}

			// Pass OAuth params to /auth via URL query
			oauthQuery := ""
			if v, ok := sessionStore.Get("OAuthQuery"); ok {
				if q, ok := v.(string); ok {
					oauthQuery = q
				}
			}
			redirectURL := "/auth"
			if oauthQuery != "" {
				redirectURL = "/auth?" + oauthQuery
			}
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		} else {
			// Redirect to login page with error message, preserving OAuth params
			redirectURL := "/login?error=invalid_credentials&error_description=" + url.QueryEscape("Invalid username or password")
			// Preserve OAuth params so the flow can continue after successful login
			if v, ok := sessionStore.Get("OAuthQuery"); ok {
				if q, ok := v.(string); ok && q != "" {
					redirectURL += "&" + q
				}
			}
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "auth", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	// Get OAuth params from URL query or session (passed through the login flow)
	queryStr := r.URL.RawQuery
	// If no URL query, try to get from session
	if queryStr == "" {
		if v, ok := store.Get("OAuthQuery"); ok {
			if q, ok := v.(string); ok {
				queryStr = q
			}
		}
	}

	var hiddenFields string
	var clientID, scopeStr string
	if queryStr != "" {
		params, _ := url.ParseQuery(queryStr)
		for key, values := range params {
			for _, val := range values {
				// Skip scope - it will be handled separately via checkboxes
				if key == "scope" {
					scopeStr = val
					continue
				}
				hiddenFields += fmt.Sprintf(`<input type="hidden" name="%s" value="%s" />`, key, val)
				if key == "client_id" {
					clientID = val
				}
			}
		}
	}

	// Parse scopes for checkbox display
	var scopeCheckboxes string
	if scopeStr != "" {
		scopes := strings.Split(scopeStr, " ")
		for i, scope := range scopes {
			if scope == "" {
				continue
			}
			scopeCheckboxes += fmt.Sprintf(`
            <label class="scope-item">
              <input type="checkbox" name="scope_item" value="%s" checked data-index="%d" />
              <span class="checkmark"></span>
              <span class="scope-name">%s</span>
            </label>`, scope, i, scope)
		}
	}

	// Generate dynamic auth page with modern design and scope checkboxes
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Authorize Application</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .auth-card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 420px;
      width: 100%%;
      overflow: hidden;
    }
    .auth-header {
      background: linear-gradient(135deg, #4f46e5 0%%, #7c3aed 100%%);
      padding: 32px 24px;
      text-align: center;
    }
    .auth-icon {
      width: 64px;
      height: 64px;
      background: rgba(255, 255, 255, 0.2);
      border-radius: 50%%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 16px;
    }
    .auth-icon svg {
      width: 32px;
      height: 32px;
      fill: white;
    }
    .auth-header h1 {
      color: white;
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .auth-header p {
      color: rgba(255, 255, 255, 0.8);
      font-size: 14px;
    }
    .auth-body {
      padding: 24px;
    }
    .client-info {
      background: #f8fafc;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 20px;
      border: 1px solid #e2e8f0;
    }
    .client-info-label {
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    .client-info-value {
      font-size: 16px;
      color: #1e293b;
      font-weight: 500;
      word-break: break-all;
    }
    .permissions-section h3 {
      font-size: 14px;
      color: #475569;
      margin-bottom: 12px;
      font-weight: 600;
    }
    .permissions-list {
      background: #f8fafc;
      border-radius: 12px;
      padding: 8px 16px;
      border: 1px solid #e2e8f0;
      margin-bottom: 24px;
    }
    .scope-item {
      display: flex;
      align-items: center;
      padding: 10px 0;
      cursor: pointer;
      border-bottom: 1px solid #e2e8f0;
      user-select: none;
    }
    .scope-item:last-child {
      border-bottom: none;
    }
    .scope-item input[type="checkbox"] {
      display: none;
    }
    .scope-item .checkmark {
      width: 20px;
      height: 20px;
      border: 2px solid #cbd5e1;
      border-radius: 4px;
      margin-right: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
      flex-shrink: 0;
    }
    .scope-item input[type="checkbox"]:checked + .checkmark {
      background: #4f46e5;
      border-color: #4f46e5;
    }
    .scope-item input[type="checkbox"]:checked + .checkmark::after {
      content: '';
      width: 6px;
      height: 10px;
      border: solid white;
      border-width: 0 2px 2px 0;
      transform: rotate(45deg);
      margin-bottom: 2px;
    }
    .scope-item:hover .checkmark {
      border-color: #4f46e5;
    }
    .scope-name {
      font-size: 14px;
      color: #334155;
    }
    .scope-item input[type="checkbox"]:not(:checked) ~ .scope-name {
      color: #94a3b8;
      text-decoration: line-through;
    }
    .select-controls {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
    }
    .select-btn {
      font-size: 12px;
      color: #4f46e5;
      background: none;
      border: none;
      cursor: pointer;
      padding: 0;
    }
    .select-btn:hover {
      text-decoration: underline;
    }
    .button-group {
      display: flex;
      gap: 12px;
    }
    .btn {
      flex: 1;
      padding: 14px 24px;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #4f46e5 0%%, #7c3aed 100%%);
      color: white;
    }
    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(79, 70, 229, 0.4);
    }
    .btn-primary:disabled {
      background: #cbd5e1;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .btn-secondary {
      background: #f1f5f9;
      color: #475569;
    }
    .btn-secondary:hover {
      background: #e2e8f0;
    }
    .footer-note {
      text-align: center;
      margin-top: 16px;
      font-size: 12px;
      color: #94a3b8;
    }
  </style>
</head>
<body>
  <div class="auth-card">
    <div class="auth-header">
      <div class="auth-icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
        </svg>
      </div>
      <h1>Authorization Request</h1>
      <p>An application is requesting access to your account</p>
    </div>
    <div class="auth-body">
      <form id="authForm" action="/oauth/authorize" method="POST">
        %s
        <input type="hidden" id="scopeField" name="scope" value="" />
        <div class="client-info">
          <div class="client-info-label">Application</div>
          <div class="client-info-value">%s</div>
        </div>
        <div class="permissions-section">
          <h3>Requested Permissions</h3>
          <div class="select-controls">
            <button type="button" class="select-btn" onclick="selectAll()">Select All</button>
            <button type="button" class="select-btn" onclick="deselectAll()">Deselect All</button>
          </div>
          <div class="permissions-list">
            %s
          </div>
        </div>
        <div class="button-group">
          <button type="button" class="btn btn-secondary" onclick="window.history.back()">Deny</button>
          <button type="submit" id="authorizeBtn" class="btn btn-primary">Authorize</button>
        </div>
      </form>
      <p class="footer-note">By authorizing, you allow this app to access your data.</p>
    </div>
  </div>
  <script>
    function updateScope() {
      const checkboxes = document.querySelectorAll('input[name="scope_item"]:checked');
      const scopes = Array.from(checkboxes).map(cb => cb.value);
      document.getElementById('scopeField').value = scopes.join(' ');
      document.getElementById('authorizeBtn').disabled = scopes.length === 0;
    }
    function selectAll() {
      document.querySelectorAll('input[name="scope_item"]').forEach(cb => cb.checked = true);
      updateScope();
    }
    function deselectAll() {
      document.querySelectorAll('input[name="scope_item"]').forEach(cb => cb.checked = false);
      updateScope();
    }
    document.querySelectorAll('input[name="scope_item"]').forEach(cb => {
      cb.addEventListener('change', updateScope);
    });
    // Initialize scope field on page load
    updateScope();
  </script>
</body>
</html>`, hiddenFields, clientID, scopeCheckboxes)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	data, err := staticFS.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, req, filename, time.Now(), bytes.NewReader(data))
}
