package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
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

	// migrations on start (optional)
	"github.com/go-oauth2/oauth2/v4/migrate"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
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

	clientStore := store.NewClientStore()
	clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
	manager.MapClientStorage(clientStore)

	log.Printf("Registered OAuth2 client: id=%s redirect_domain=%s", idvar, domainvar)

	srv := server.NewServer(server.NewConfig(), manager)

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
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}
		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
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
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if r.Form.Get("username") == "test" && r.Form.Get("password") == "test" {
			store.Set("LoggedInUserID", r.Form.Get("username"))
			store.Save()

			w.Header().Set("Location", "/auth")
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
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}
