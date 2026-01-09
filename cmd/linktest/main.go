package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// App holds application dependencies
type App struct {
	db            *gorm.DB
	userStore     *store.UserStore
	linkCodeStore *store.LinkCodeStore
}

// SessionData represents a logged-in session
type SessionData struct {
	AccountID   string
	Username    string
	AccountType string
	Email       string
}

var sessions = make(map[string]*SessionData)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable"
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	app := &App{
		db:            db,
		userStore:     store.NewUserStore(db),
		linkCodeStore: store.NewLinkCodeStore(db),
	}

	gin.SetMode(gin.DebugMode)
	r := gin.Default()

	// Load HTML templates
	r.SetHTMLTemplate(loadTemplates())

	// Routes
	r.GET("/", app.handleHome)
	r.GET("/login", app.handleLoginPage)
	r.POST("/login", app.handleLogin)
	r.GET("/register", app.handleRegisterPage)
	r.POST("/register", app.handleRegister)
	r.GET("/logout", app.handleLogout)

	// Headless account simulation
	r.POST("/create-headless", app.handleCreateHeadless)

	// Link code operations
	r.POST("/generate-link-code", app.handleGenerateLinkCode)
	r.POST("/link-with-code", app.handleLinkWithCode)

	// Account info
	r.GET("/accounts", app.handleListAccounts)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}

	fmt.Printf("\n===========================================\n")
	fmt.Printf("  Link Test Application\n")
	fmt.Printf("  Open http://localhost:%s in your browser\n", port)
	fmt.Printf("===========================================\n\n")

	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (app *App) getSession(c *gin.Context) *SessionData {
	cookie, err := c.Cookie("session_id")
	if err != nil {
		return nil
	}
	return sessions[cookie]
}

func (app *App) setSession(c *gin.Context, session *SessionData) {
	sessionID := generateSessionID()
	sessions[sessionID] = session
	c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
}

func (app *App) handleHome(c *gin.Context) {
	session := app.getSession(c)

	// Get all accounts with their namespace info
	var accounts []struct {
		ID          string
		Username    string
		Email       *string
		AccountType string
		CreatedAt   time.Time
		Namespace   *string
	}
	app.db.Raw(`
		SELECT a.id, a.username, a.email, a.account_type, a.created_at,
		       (SELECT u.namespace FROM users u JOIN account_users au ON u.id = au.user_id
		        WHERE au.account_id = a.id AND u.user_type = 'BODY' LIMIT 1) as namespace
		FROM accounts a ORDER BY a.created_at DESC
	`).Scan(&accounts)

	// Get all link codes
	var linkCodes []store.LinkCode
	app.db.Raw(`SELECT * FROM link_codes WHERE used = FALSE AND expires_at > NOW() ORDER BY created_at DESC`).Scan(&linkCodes)

	c.HTML(http.StatusOK, "home", gin.H{
		"Session":   session,
		"Accounts":  accounts,
		"LinkCodes": linkCodes,
	})
}

func (app *App) handleLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login", gin.H{})
}

func (app *App) handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var account struct {
		ID           string
		Username     string
		PasswordHash string
		Email        *string
		AccountType  string
	}

	err := app.db.Raw(`SELECT id, username, password_hash, email, account_type FROM accounts WHERE username = ?`, username).Scan(&account).Error
	if err != nil || account.ID == "" {
		c.HTML(http.StatusOK, "login", gin.H{"Error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		c.HTML(http.StatusOK, "login", gin.H{"Error": "Invalid username or password"})
		return
	}

	email := ""
	if account.Email != nil {
		email = *account.Email
	}

	app.setSession(c, &SessionData{
		AccountID:   account.ID,
		Username:    account.Username,
		AccountType: account.AccountType,
		Email:       email,
	})

	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleRegisterPage(c *gin.Context) {
	c.HTML(http.StatusOK, "register", gin.H{})
}

func (app *App) handleRegister(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	email := c.PostForm("email")

	if username == "" || password == "" || email == "" {
		c.HTML(http.StatusOK, "register", gin.H{"Error": "All fields are required"})
		return
	}

	// Check if username exists
	var count int64
	app.db.Raw(`SELECT COUNT(*) FROM accounts WHERE username = ?`, username).Scan(&count)
	if count > 0 {
		c.HTML(http.StatusOK, "register", gin.H{"Error": "Username already exists"})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusOK, "register", gin.H{"Error": "Failed to hash password"})
		return
	}

	// Create HEAD account
	accountID := models.LegitID()
	_, err = app.userStore.CreateHeadAccount(context.Background(), accountID, username, string(hash), &email, nil)
	if err != nil {
		c.HTML(http.StatusOK, "register", gin.H{"Error": fmt.Sprintf("Failed to create account: %v", err)})
		return
	}

	// Auto login
	app.setSession(c, &SessionData{
		AccountID:   accountID,
		Username:    username,
		AccountType: string(models.AccountHead),
		Email:       email,
	})

	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleLogout(c *gin.Context) {
	cookie, _ := c.Cookie("session_id")
	delete(sessions, cookie)
	c.SetCookie("session_id", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleCreateHeadless(c *gin.Context) {
	namespace := c.PostForm("namespace")
	providerType := c.PostForm("provider_type")
	providerAccountID := c.PostForm("provider_account_id")

	if namespace == "" {
		namespace = "TESTGAME"
	}
	if providerType == "" {
		providerType = "google"
	}
	if providerAccountID == "" {
		providerAccountID = fmt.Sprintf("google_%d", time.Now().UnixNano())
	}

	accountID := models.LegitID()
	err := app.userStore.CreateHeadlessAccount(context.Background(), accountID, namespace, providerType, providerAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleGenerateLinkCode(c *gin.Context) {
	accountID := c.PostForm("account_id")
	namespace := c.PostForm("namespace")

	if namespace == "" {
		namespace = "TESTGAME"
	}

	// Get platform info
	platforms, err := app.userStore.GetLinkedPlatformsByNamespace(context.Background(), accountID, namespace)
	if err != nil || len(platforms) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No platform linked in this namespace"})
		return
	}

	platform := platforms[0]
	linkCode, err := app.linkCodeStore.CreateLinkCode(context.Background(), accountID, namespace, platform.ProviderType, platform.ProviderAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":       linkCode.Code,
		"expires_at": linkCode.ExpiresAt,
	})
}

func (app *App) handleLinkWithCode(c *gin.Context) {
	session := app.getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Please login first"})
		return
	}

	code := c.PostForm("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code is required"})
		return
	}

	// Validate code
	linkCode, err := app.linkCodeStore.ValidateLinkCode(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if linkCode == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired link code"})
		return
	}

	// Check eligibility
	eligibility, err := app.userStore.CheckLinkEligibility(context.Background(), linkCode.Namespace, session.AccountID, linkCode.HeadlessAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !eligibility.Eligible {
		c.JSON(http.StatusConflict, gin.H{"error": eligibility.Reason})
		return
	}

	// Perform link
	err = app.userStore.Link(context.Background(), linkCode.Namespace, session.AccountID, linkCode.HeadlessAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Mark code as used
	app.linkCodeStore.UseLinkCode(context.Background(), code, session.AccountID)

	// Update session
	session.AccountType = string(models.AccountFull)

	c.JSON(http.StatusOK, gin.H{
		"success":             true,
		"headless_account_id": linkCode.HeadlessAccountID,
		"namespace":           linkCode.Namespace,
	})
}

func (app *App) handleListAccounts(c *gin.Context) {
	var accounts []struct {
		ID          string
		Username    string
		Email       *string
		AccountType string
	}
	app.db.Raw(`SELECT id, username, email, account_type FROM accounts ORDER BY created_at DESC`).Scan(&accounts)

	c.JSON(http.StatusOK, accounts)
}

func loadTemplates() *template.Template {
	tmpl := template.New("")

	// Home template
	tmpl = template.Must(tmpl.New("home").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Link Test - Home</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #333; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f9f9f9; }
        .btn { display: inline-block; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; border: none; cursor: pointer; font-size: 14px; }
        .btn:hover { background: #0056b3; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #1e7e34; }
        .btn-warning { background: #ffc107; color: #333; }
        .btn-danger { background: #dc3545; }
        .btn-sm { padding: 4px 8px; font-size: 12px; }
        input[type="text"], input[type="password"], input[type="email"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 200px; }
        .type-head { color: #28a745; font-weight: bold; }
        .type-headless { color: #ffc107; font-weight: bold; }
        .type-full { color: #007bff; font-weight: bold; }
        .type-orphan { color: #6c757d; font-weight: bold; }
        .user-info { display: flex; align-items: center; gap: 20px; }
        .flash { padding: 10px; border-radius: 4px; margin-bottom: 10px; }
        .flash-success { background: #d4edda; color: #155724; }
        .flash-error { background: #f8d7da; color: #721c24; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .code-display { font-family: monospace; font-size: 24px; background: #f0f0f0; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        #linkResult, #generateResult { margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="user-info">
                <h1>Account Linking Test</h1>
                {{if .Session}}
                <div style="margin-left: auto;">
                    Logged in as: <strong>{{.Session.Username}}</strong>
                    ({{.Session.AccountType}})
                    <a href="/logout" class="btn btn-sm btn-danger" style="margin-left: 10px;">Logout</a>
                </div>
                {{else}}
                <div style="margin-left: auto;">
                    <a href="/login" class="btn">Login</a>
                    <a href="/register" class="btn btn-success">Register</a>
                </div>
                {{end}}
            </div>
        </div>

        {{if .Session}}
        <div class="card">
            <h3>Link Headless Account (Enter Code)</h3>
            <p>If you have a link code from a headless account, enter it here to link that account to yours.</p>
            <form id="linkForm" onsubmit="return linkWithCode(event)">
                <div class="form-group">
                    <label>Link Code:</label>
                    <input type="text" name="code" id="linkCode" placeholder="e.g., a1b2c3d4" required>
                </div>
                <button type="submit" class="btn btn-success">Link Account</button>
            </form>
            <div id="linkResult"></div>
        </div>
        {{end}}

        <div class="card">
            <h3>Create Headless Account (Simulate Platform Login)</h3>
            <p>This simulates a user logging in via a platform (e.g., Google) without having a head account.</p>
            <form action="/create-headless" method="POST" style="display: flex; gap: 10px; align-items: end;">
                <div>
                    <label>Namespace:</label><br>
                    <input type="text" name="namespace" value="TESTGAME">
                </div>
                <div>
                    <label>Provider:</label><br>
                    <input type="text" name="provider_type" value="google">
                </div>
                <div>
                    <label>Provider Account ID:</label><br>
                    <input type="text" name="provider_account_id" placeholder="Auto-generated if empty">
                </div>
                <button type="submit" class="btn btn-warning">Create Headless Account</button>
            </form>
        </div>

        <div class="card">
            <h3>All Accounts</h3>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Type</th>
                    <th>Namespace</th>
                    <th>Actions</th>
                </tr>
                {{range .Accounts}}
                <tr>
                    <td><code style="font-size: 11px;">{{.ID}}</code></td>
                    <td>{{.Username}}</td>
                    <td>{{if .Email}}{{.Email}}{{else}}<em>-</em>{{end}}</td>
                    <td>
                        {{if eq .AccountType "HEAD"}}<span class="type-head">HEAD</span>
                        {{else if eq .AccountType "HEADLESS"}}<span class="type-headless">HEADLESS</span>
                        {{else if eq .AccountType "FULL"}}<span class="type-full">FULL</span>
                        {{else}}<span class="type-orphan">ORPHAN</span>
                        {{end}}
                    </td>
                    <td>{{if .Namespace}}{{.Namespace}}{{else if eq .AccountType "HEAD"}}PUBLISHER{{else if eq .AccountType "FULL"}}PUBLISHER{{else}}<em>-</em>{{end}}</td>
                    <td>
                        {{if eq .AccountType "HEADLESS"}}
                        <button class="btn btn-sm btn-success" onclick="generateLinkCode('{{.ID}}', '{{.Namespace}}')">Generate Link Code</button>
                        {{end}}
                    </td>
                </tr>
                {{else}}
                <tr><td colspan="6">No accounts found. Register or create a headless account to get started.</td></tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h3>Active Link Codes</h3>
            <table>
                <tr>
                    <th>Code</th>
                    <th>Headless Account</th>
                    <th>Namespace</th>
                    <th>Provider</th>
                    <th>Expires At</th>
                </tr>
                {{range .LinkCodes}}
                <tr>
                    <td><span class="code-display" style="font-size: 16px;">{{.Code}}</span></td>
                    <td><code style="font-size: 11px;">{{.HeadlessAccountID}}</code></td>
                    <td>{{.Namespace}}</td>
                    <td>{{.ProviderType}}</td>
                    <td>{{.ExpiresAt.Format "2006-01-02 15:04:05"}}</td>
                </tr>
                {{else}}
                <tr><td colspan="5">No active link codes. Generate one from a headless account.</td></tr>
                {{end}}
            </table>
        </div>

        <div id="generateResult"></div>
    </div>

    <script>
        function generateLinkCode(accountId, namespace) {
            fetch('/generate-link-code', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'account_id=' + accountId + '&namespace=' + encodeURIComponent(namespace)
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    document.getElementById('generateResult').innerHTML =
                        '<div class="card flash flash-error">' + data.error + '</div>';
                } else {
                    document.getElementById('generateResult').innerHTML =
                        '<div class="card flash flash-success">Link Code Generated: <span class="code-display">' + data.code + '</span><br>Expires at: ' + data.expires_at + '</div>';
                    setTimeout(() => location.reload(), 2000);
                }
            });
        }

        function linkWithCode(event) {
            event.preventDefault();
            const code = document.getElementById('linkCode').value;

            fetch('/link-with-code', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'code=' + code
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    document.getElementById('linkResult').innerHTML =
                        '<div class="flash flash-error">' + data.error + '</div>';
                } else {
                    document.getElementById('linkResult').innerHTML =
                        '<div class="flash flash-success">Successfully linked! Headless account ' + data.headless_account_id + ' is now linked.</div>';
                    setTimeout(() => location.reload(), 2000);
                }
            });
            return false;
        }
    </script>
</body>
</html>
`))

	// Login template
	tmpl = template.Must(tmpl.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Link Test - Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 350px; }
        h2 { margin-top: 0; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { display: block; width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #0056b3; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Login</h2>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form action="/login" method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="links">
            <a href="/register">Don't have an account? Register</a><br><br>
            <a href="/">Back to Home</a>
        </div>
    </div>
</body>
</html>
`))

	// Register template
	tmpl = template.Must(tmpl.New("register").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Link Test - Register</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 400px; }
        h2 { margin-top: 0; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { display: block; width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #1e7e34; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .info { background: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; }
        .namespace-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .ns-publisher { background: #007bff; color: white; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Register Account</h2>
        <div class="info">
            <strong>Namespace:</strong> <span class="namespace-badge ns-publisher">PUBLISHER</span><br><br>
            This creates a HEAD account in the PUBLISHER namespace.<br>
            HEAD accounts can link with HEADLESS accounts from game namespaces.
        </div>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form action="/register" method="POST">
            <input type="hidden" name="namespace" value="PUBLISHER">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Register (PUBLISHER)</button>
        </form>
        <div class="links">
            <a href="/login">Already have an account? Login</a><br><br>
            <a href="/">Back to Home</a>
        </div>
    </div>
</body>
</html>
`))

	return tmpl
}
