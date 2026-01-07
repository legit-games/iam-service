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

	// migrations on start (optional)
	"github.com/go-oauth2/oauth2/v4/migrate"
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
	if r.URL.RawQuery != "" && r.Method == "GET" {
		sessionStore.Set("OAuthQuery", r.URL.RawQuery)
		sessionStore.Save()
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
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
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

	// Get OAuth params from URL query (passed through the login flow)
	var hiddenFields string
	if r.URL.RawQuery != "" {
		params, _ := url.ParseQuery(r.URL.RawQuery)
		for key, values := range params {
			for _, val := range values {
				hiddenFields += fmt.Sprintf(`<input type="hidden" name="%s" value="%s" />`, key, val)
			}
		}
	}

	// Generate dynamic auth page with hidden fields
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Authorize Application</title>
  <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" />
</head>
<body>
  <div class="container">
    <div class="jumbotron">
      <form action="/oauth/authorize" method="POST">
        %s
        <h1>Authorize</h1>
        <p>The client would like to perform actions on your behalf.</p>
        <p>
          <button type="submit" class="btn btn-primary btn-lg" style="width:200px;">Allow</button>
        </p>
      </form>
    </div>
  </div>
</body>
</html>`, hiddenFields)

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
