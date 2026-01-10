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

// Session represents a logged-in user session
type Session struct {
	AccountID   string
	Username    string
	AccountType string
	Email       string
}

// AccountInfo represents account data for display
type AccountInfo struct {
	ID          string
	Username    string
	Email       *string
	AccountType string
	CreatedAt   time.Time
	Users       []UserInfo
}

// UserInfo represents user data within an account
type UserInfo struct {
	ID                string
	UserType          string
	Namespace         *string
	ProviderType      *string
	ProviderAccountID *string
}

var sessions = make(map[string]*Session)

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

	r := gin.Default()
	r.SetHTMLTemplate(loadTemplates())

	// Routes
	r.GET("/", app.handleHome)
	r.POST("/platform-login", app.handlePlatformLogin)
	r.GET("/register", app.handleRegisterPage)
	r.POST("/register", app.handleRegister)
	r.GET("/login", app.handleLoginPage)
	r.POST("/login", app.handleLogin)
	r.GET("/logout", app.handleLogout)
	r.POST("/generate-link-code", app.handleGenerateLinkCode)
	r.POST("/link-with-code", app.handleLinkWithCode)
	r.POST("/unlink", app.handleUnlink)
	r.GET("/merge/check", app.handleCheckMergeEligibility)
	r.POST("/merge", app.handleMerge)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("  Account Link Test Application\n")
	fmt.Printf("  http://localhost:%s\n", port)
	fmt.Printf("========================================\n\n")

	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (app *App) getSession(c *gin.Context) *Session {
	cookie, err := c.Cookie("session_id")
	if err != nil {
		return nil
	}
	return sessions[cookie]
}

func (app *App) setSession(c *gin.Context, session *Session) {
	sessionID := generateSessionID()
	sessions[sessionID] = session
	c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
}

func (app *App) clearSession(c *gin.Context) {
	cookie, _ := c.Cookie("session_id")
	delete(sessions, cookie)
	c.SetCookie("session_id", "", -1, "/", "", false, true)
}

// getAccounts returns all accounts with their users
func (app *App) getAccounts() []AccountInfo {
	var accounts []AccountInfo

	// Get all accounts
	var rawAccounts []struct {
		ID          string
		Username    string
		Email       *string
		AccountType string
		CreatedAt   time.Time
	}
	app.db.Raw(`SELECT id, username, email, account_type, created_at FROM accounts ORDER BY created_at DESC`).Scan(&rawAccounts)

	for _, acc := range rawAccounts {
		info := AccountInfo{
			ID:          acc.ID,
			Username:    acc.Username,
			Email:       acc.Email,
			AccountType: acc.AccountType,
			CreatedAt:   acc.CreatedAt,
		}

		// Get users for this account
		var users []UserInfo
		app.db.Raw(`
			SELECT u.id, u.user_type, u.namespace, u.provider_type, u.provider_account_id
			FROM users u
			JOIN account_users au ON u.id = au.user_id
			WHERE au.account_id = ?
			ORDER BY u.user_type
		`, acc.ID).Scan(&users)
		info.Users = users

		accounts = append(accounts, info)
	}

	return accounts
}

// getLinkCodes returns active link codes
func (app *App) getLinkCodes() []store.LinkCode {
	var codes []store.LinkCode
	app.db.Raw(`SELECT * FROM link_codes WHERE used = FALSE AND expires_at > NOW() ORDER BY created_at DESC`).Scan(&codes)
	return codes
}

func (app *App) handleHome(c *gin.Context) {
	session := app.getSession(c)
	accounts := app.getAccounts()
	linkCodes := app.getLinkCodes()

	c.HTML(http.StatusOK, "home", gin.H{
		"Session":   session,
		"Accounts":  accounts,
		"LinkCodes": linkCodes,
	})
}

func (app *App) handlePlatformLogin(c *gin.Context) {
	namespace := c.PostForm("namespace")
	providerType := c.PostForm("provider_type")
	providerAccountID := c.PostForm("provider_account_id")

	if namespace == "" || providerType == "" || providerAccountID == "" {
		c.Redirect(http.StatusFound, "/?error=All+fields+are+required")
		return
	}

	accountID := models.LegitID()
	err := app.userStore.CreateHeadlessAccount(context.Background(), accountID, namespace, providerType, providerAccountID)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/?success=HEADLESS+account+created")
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

	var count int64
	app.db.Raw(`SELECT COUNT(*) FROM accounts WHERE username = ?`, username).Scan(&count)
	if count > 0 {
		c.HTML(http.StatusOK, "register", gin.H{"Error": "Username already exists"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusOK, "register", gin.H{"Error": "Failed to hash password"})
		return
	}

	accountID := models.LegitID()
	_, err = app.userStore.CreateHeadAccount(context.Background(), accountID, username, string(hash), &email, nil)
	if err != nil {
		c.HTML(http.StatusOK, "register", gin.H{"Error": err.Error()})
		return
	}

	app.setSession(c, &Session{
		AccountID:   accountID,
		Username:    username,
		AccountType: string(models.AccountHead),
		Email:       email,
	})

	c.Redirect(http.StatusFound, "/")
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

	app.setSession(c, &Session{
		AccountID:   account.ID,
		Username:    account.Username,
		AccountType: account.AccountType,
		Email:       email,
	})

	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleLogout(c *gin.Context) {
	app.clearSession(c)
	c.Redirect(http.StatusFound, "/")
}

func (app *App) handleGenerateLinkCode(c *gin.Context) {
	accountID := c.PostForm("account_id")
	namespace := c.PostForm("namespace")

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

	linkCode, err := app.linkCodeStore.ValidateLinkCode(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if linkCode == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired link code"})
		return
	}

	eligibility, err := app.userStore.CheckLinkEligibility(context.Background(), linkCode.Namespace, session.AccountID, linkCode.HeadlessAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !eligibility.Eligible {
		response := gin.H{
			"error":  eligibility.Reason,
			"reason": eligibility.Reason,
		}
		// Include conflict info for merge API usage
		if eligibility.Conflict != nil {
			response["conflict"] = eligibility.Conflict
			response["message"] = "Use Merge API to resolve this conflict"
		}
		c.JSON(http.StatusConflict, response)
		return
	}

	err = app.userStore.Link(context.Background(), linkCode.Namespace, session.AccountID, linkCode.HeadlessAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	app.linkCodeStore.UseLinkCode(context.Background(), code, session.AccountID)
	session.AccountType = string(models.AccountFull)

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"namespace": linkCode.Namespace,
	})
}

func (app *App) handleUnlink(c *gin.Context) {
	accountID := c.PostForm("account_id")
	namespace := c.PostForm("namespace")

	log.Printf("[Unlink] account_id=%s, namespace=%s", accountID, namespace)

	if accountID == "" || namespace == "" {
		log.Printf("[Unlink] Error: account_id and namespace are required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id and namespace are required"})
		return
	}

	restoredID, err := app.userStore.UnlinkNamespace(context.Background(), accountID, namespace)
	if err != nil {
		log.Printf("[Unlink] Error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[Unlink] Success: restored HEADLESS account %s", restoredID)

	session := app.getSession(c)
	if session != nil && session.AccountID == accountID {
		var accountType string
		app.db.Raw(`SELECT account_type FROM accounts WHERE id = ?`, accountID).Row().Scan(&accountType)
		session.AccountType = accountType
	}

	c.JSON(http.StatusOK, gin.H{
		"success":              true,
		"restored_headless_id": restoredID,
	})
}

func (app *App) handleCheckMergeEligibility(c *gin.Context) {
	targetAccountID := c.Query("target_account_id")
	sourceAccountID := c.Query("source_account_id")

	if targetAccountID == "" || sourceAccountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_account_id and source_account_id are required"})
		return
	}

	eligibility, err := app.userStore.CheckMergeEligibility(context.Background(), sourceAccountID, targetAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, eligibility)
}

func (app *App) handleMerge(c *gin.Context) {
	session := app.getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Please login first"})
		return
	}

	var req struct {
		SourceAccountID     string                     `json:"source_account_id"`
		ConflictResolutions []store.ConflictResolution `json:"conflict_resolutions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targetAccountID := session.AccountID

	eligibility, err := app.userStore.CheckMergeEligibility(context.Background(), req.SourceAccountID, targetAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if !eligibility.Eligible && eligibility.Reason != "conflict_detected" {
		c.JSON(http.StatusBadRequest, gin.H{"error": eligibility.Reason})
		return
	}

	if len(eligibility.Conflicts) > 0 {
		resolutionMap := make(map[string]bool)
		for _, r := range req.ConflictResolutions {
			resolutionMap[r.Namespace] = true
		}
		for _, conflict := range eligibility.Conflicts {
			if !resolutionMap[conflict.Namespace] {
				c.JSON(http.StatusConflict, gin.H{
					"error":     "conflict_requires_resolution",
					"conflicts": eligibility.Conflicts,
				})
				return
			}
		}
	}

	result, err := app.userStore.Merge(context.Background(), req.SourceAccountID, targetAccountID, req.ConflictResolutions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session.AccountType = string(models.AccountFull)

	c.JSON(http.StatusOK, gin.H{
		"success":           true,
		"merged_namespaces": result.MergedNamespaces,
		"orphaned_users":    result.OrphanedUsers,
	})
}

func loadTemplates() *template.Template {
	tmpl := template.New("")

	tmpl = template.Must(tmpl.New("home").Parse(homeTemplate))
	tmpl = template.Must(tmpl.New("login").Parse(loginTemplate))
	tmpl = template.Must(tmpl.New("register").Parse(registerTemplate))

	return tmpl
}

const homeTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Account Link Test</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 20px; background: #f0f2f5;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 20px 30px; border-radius: 12px; margin-bottom: 20px;
            display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { margin: 0; font-size: 24px; }
        .user-badge {
            background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px;
            display: flex; align-items: center; gap: 10px;
        }
        .card {
            background: white; padding: 24px; border-radius: 12px; margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .card h2 {
            margin: 0 0 8px 0; font-size: 18px; color: #333;
            display: flex; align-items: center; gap: 8px;
        }
        .card .desc { color: #666; font-size: 14px; margin-bottom: 20px; }
        .step-badge {
            background: #667eea; color: white; font-size: 12px; padding: 2px 8px;
            border-radius: 10px; font-weight: bold;
        }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        .form-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: end; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; font-size: 13px; color: #555; }
        input, select {
            padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px;
            font-size: 14px; width: 100%;
        }
        input:focus, select:focus { outline: none; border-color: #667eea; }
        .btn {
            padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer;
            font-size: 14px; font-weight: 600; transition: all 0.2s;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5a6fd6; }
        .btn-success { background: #10b981; color: white; }
        .btn-success:hover { background: #059669; }
        .btn-warning { background: #f59e0b; color: white; }
        .btn-warning:hover { background: #d97706; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-danger:hover { background: #dc2626; }
        .btn-sm { padding: 6px 12px; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f8f9fa; text-align: left; padding: 12px; font-weight: 600; color: #555; }
        td { padding: 12px; border-bottom: 1px solid #eee; vertical-align: top; }
        .type-badge {
            display: inline-block; padding: 4px 10px; border-radius: 12px;
            font-size: 11px; font-weight: 700; text-transform: uppercase;
        }
        .type-HEAD { background: #dcfce7; color: #166534; }
        .type-HEADLESS { background: #fef3c7; color: #92400e; }
        .type-FULL { background: #dbeafe; color: #1e40af; }
        .type-ORPHAN { background: #f3f4f6; color: #6b7280; }
        .platform-badge {
            display: inline-block; padding: 3px 8px; border-radius: 4px;
            font-size: 11px; font-weight: 600; margin-right: 4px;
        }
        .platform-xbox { background: #107c10; color: white; }
        .platform-playstation { background: #003791; color: white; }
        .platform-steam { background: #1b2838; color: white; }
        .platform-google { background: #4285f4; color: white; }
        .platform-apple { background: #000; color: white; }
        .platform-default { background: #6b7280; color: white; }
        .user-row { margin: 4px 0; padding: 6px 10px; background: #f8f9fa; border-radius: 6px; }
        .user-type { font-weight: 600; font-size: 11px; color: #666; }
        .namespace { color: #667eea; font-weight: 600; }
        .code-box {
            font-family: 'Monaco', 'Consolas', monospace; font-size: 20px;
            background: #f0f0f0; padding: 12px 20px; border-radius: 8px;
            letter-spacing: 2px; display: inline-block;
        }
        .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 15px; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .alert-warning { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
        .id-text { font-family: monospace; font-size: 11px; color: #666; }
        .actions { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
        .generated-code {
            display: inline-block; margin-left: 8px; padding: 4px 12px;
            background: #10b981; color: white; border-radius: 6px;
            font-family: 'Monaco', 'Consolas', monospace; font-size: 14px;
            font-weight: bold; letter-spacing: 1px;
        }
        #result { margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Account Link & Merge Test</h1>
            {{if .Session}}
            <div class="user-badge">
                <span>{{.Session.Username}}</span>
                <span class="type-badge type-{{.Session.AccountType}}">{{.Session.AccountType}}</span>
                <a href="/logout" class="btn btn-sm btn-danger">Logout</a>
            </div>
            {{else}}
            <div>
                <a href="/login" class="btn btn-primary" style="margin-right: 8px;">Login</a>
                <a href="/register" class="btn btn-success">Register</a>
            </div>
            {{end}}
        </div>

        <div class="grid">
            <!-- Step 1 & 2: Create HEADLESS -->
            <div class="card">
                <h2><span class="step-badge">Step 1-2</span> Platform Login (HEADLESS)</h2>
                <p class="desc">Create a HEADLESS account by simulating platform login (Xbox, PlayStation, etc.)</p>
                <form action="/platform-login" method="POST">
                    <div class="form-group">
                        <label>Namespace (Game)</label>
                        <input type="text" name="namespace" value="TESTGAME" required>
                    </div>
                    <div class="form-row">
                        <div class="form-group" style="flex: 1;">
                            <label>Platform Type</label>
                            <select name="provider_type" required>
                                <option value="xbox">Xbox</option>
                                <option value="playstation">PlayStation</option>
                                <option value="steam">Steam</option>
                                <option value="google">Google</option>
                                <option value="apple">Apple</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex: 2;">
                            <label>Platform User ID</label>
                            <input type="text" name="provider_account_id" placeholder="e.g., xbox_user_001" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-warning">Create HEADLESS Account</button>
                </form>
            </div>

            <!-- Step 3: Create HEAD -->
            <div class="card">
                <h2><span class="step-badge">Step 3</span> Register (HEAD)</h2>
                <p class="desc">Create a HEAD account with email/password in PUBLISHER namespace.</p>
                {{if .Session}}
                <div class="alert alert-success">
                    Logged in as <strong>{{.Session.Username}}</strong> ({{.Session.AccountType}})
                </div>
                {{else}}
                <a href="/register" class="btn btn-success">Go to Register Page</a>
                {{end}}
            </div>
        </div>

        {{if .Session}}
        <div class="grid">
            <!-- Step 4: Link -->
            <div class="card">
                <h2><span class="step-badge">Step 4</span> Link Account (Code)</h2>
                <p class="desc">Link a HEADLESS account to your HEAD account using a link code.</p>
                <form id="linkForm" onsubmit="return linkWithCode(event)">
                    <div class="form-row">
                        <div class="form-group" style="flex: 1;">
                            <label>Link Code</label>
                            <input type="text" id="linkCode" placeholder="Enter 8-character code" required>
                        </div>
                        <button type="submit" class="btn btn-success" style="margin-bottom: 15px;">Link</button>
                    </div>
                </form>
                <div id="linkResult"></div>
            </div>

            <!-- Step 5-6: Merge -->
            <div class="card">
                <h2><span class="step-badge">Step 5-6</span> Merge Account</h2>
                <p class="desc">Merge another account into yours. Handles conflicts when same namespace exists.</p>
                <div class="form-row">
                    <div class="form-group" style="flex: 1;">
                        <label>Source Account ID</label>
                        <input type="text" id="mergeSourceId" placeholder="Account ID to merge">
                    </div>
                    <button class="btn btn-primary" onclick="checkMergeEligibility()" style="margin-bottom: 15px;">Check</button>
                </div>
                <div id="mergeResult"></div>
            </div>
        </div>
        {{end}}

        <!-- Accounts Table -->
        <div class="card">
            <h2>All Accounts</h2>
            <p class="desc">List of all accounts with their users (HEAD and BODY)</p>
            <table>
                <thead>
                    <tr>
                        <th>Account ID</th>
                        <th>Username / Email</th>
                        <th>Type</th>
                        <th>Namespace</th>
                        <th>Platform</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Accounts}}
                <tr>
                    <td><span class="id-text">{{.ID}}</span></td>
                    <td>
                        <strong>{{.Username}}</strong>
                        {{if .Email}}<br><span style="color: #666; font-size: 12px;">{{.Email}}</span>{{end}}
                    </td>
                    <td><span class="type-badge type-{{.AccountType}}">{{.AccountType}}</span></td>
                    <td>
                        {{range .Users}}
                            {{if eq .UserType "HEAD"}}
                            <div class="user-row"><span style="color: #999;">PUBLISHER</span></div>
                            {{else if .Namespace}}
                            <div class="user-row"><span class="namespace">{{.Namespace}}</span></div>
                            {{end}}
                        {{else}}
                        <span style="color: #999;">-</span>
                        {{end}}
                    </td>
                    <td>
                        {{range .Users}}
                            {{if .ProviderType}}
                            <div class="user-row">
                                <span class="platform-badge platform-{{.ProviderType}}">{{.ProviderType}}</span>
                                <br><span class="id-text">{{.ProviderAccountID}}</span>
                            </div>
                            {{else if eq .UserType "HEAD"}}
                            <div class="user-row"><span style="color: #999;">Email/Password</span></div>
                            {{end}}
                        {{else}}
                        <span style="color: #999;">-</span>
                        {{end}}
                    </td>
                    <td class="actions">
                        {{if eq .AccountType "HEADLESS"}}
                            {{$ns := ""}}{{range .Users}}{{if .Namespace}}{{$ns = .Namespace}}{{end}}{{end}}
                            <button class="btn btn-sm btn-success" onclick="generateLinkCode('{{.ID}}', '{{$ns}}')">Generate Code</button>
                            {{if $.Session}}<button class="btn btn-sm btn-primary" onclick="startMerge('{{.ID}}')">Merge</button>{{end}}
                            <span id="code-{{.ID}}" class="generated-code"></span>
                        {{else if eq .AccountType "FULL"}}
                            {{$accountID := .ID}}
                            {{range .Users}}
                                {{if and .Namespace (ne .UserType "HEAD")}}
                                <button class="btn btn-sm btn-danger" onclick="unlinkAccount('{{$accountID}}', '{{.Namespace}}')">Unlink {{.Namespace}}</button>
                                {{end}}
                            {{end}}
                            {{if $.Session}}{{if ne .ID $.Session.AccountID}}<button class="btn btn-sm btn-primary" onclick="startMerge('{{.ID}}')">Merge</button>{{end}}{{end}}
                        {{else if eq .AccountType "HEAD"}}
                            {{if $.Session}}{{if ne .ID $.Session.AccountID}}<button class="btn btn-sm btn-primary" onclick="startMerge('{{.ID}}')">Merge</button>{{end}}{{end}}
                        {{end}}
                    </td>
                </tr>
                {{else}}
                <tr><td colspan="6" style="text-align: center; color: #999;">No accounts yet. Create a HEADLESS or register a HEAD account.</td></tr>
                {{end}}
                </tbody>
            </table>
        </div>

        <!-- Link Codes Table -->
        <div class="card">
            <h2>Active Link Codes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Code</th>
                        <th>Account</th>
                        <th>Namespace</th>
                        <th>Platform</th>
                        <th>Expires</th>
                    </tr>
                </thead>
                <tbody>
                {{range .LinkCodes}}
                <tr>
                    <td><span class="code-box">{{.Code}}</span></td>
                    <td><span class="id-text">{{.HeadlessAccountID}}</span></td>
                    <td><span class="namespace">{{.Namespace}}</span></td>
                    <td><span class="platform-badge platform-{{.ProviderType}}">{{.ProviderType}}</span></td>
                    <td>{{.ExpiresAt.Format "15:04:05"}}</td>
                </tr>
                {{else}}
                <tr><td colspan="5" style="text-align: center; color: #999;">No active link codes</td></tr>
                {{end}}
                </tbody>
            </table>
        </div>

        <div id="result"></div>
    </div>

    <script>
        function showResult(id, html) {
            document.getElementById(id).innerHTML = html;
        }

        function generateLinkCode(accountId, namespace) {
            fetch('/generate-link-code', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'account_id=' + accountId + '&namespace=' + encodeURIComponent(namespace)
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    showResult('result', '<div class="alert alert-error">' + data.error + '</div>');
                } else {
                    // Show code next to the account
                    const codeSpan = document.getElementById('code-' + accountId);
                    if (codeSpan) {
                        codeSpan.textContent = data.code;
                    }
                }
            });
        }

        function linkWithCode(e) {
            e.preventDefault();
            const code = document.getElementById('linkCode').value;
            fetch('/link-with-code', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'code=' + code
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    // Check if it's a conflict that can be resolved with Merge (different platform types)
                    if (data.conflict && data.reason === 'conflict_different_platform_same_namespace') {
                        let c = data.conflict;
                        let html = '<div class="alert alert-warning">';
                        html += '<strong>Conflict Detected!</strong> Different platforms in same namespace<br><br>';
                        html += '<table style="width:100%; margin: 10px 0;">';
                        html += '<tr><th>Namespace</th><th>Your Platform (Target)</th><th>Source Platform</th></tr>';
                        html += '<tr>';
                        html += '<td class="namespace">' + c.namespace + '</td>';
                        html += '<td><span class="platform-badge platform-' + c.target_provider_type + '">' + c.target_provider_type + '</span> ' + c.target_provider_account_id + '</td>';
                        html += '<td><span class="platform-badge platform-' + c.source_provider_type + '">' + c.source_provider_type + '</span> ' + c.source_provider_account_id + '</td>';
                        html += '</tr></table>';
                        html += '<p>You can resolve this conflict using the Merge API to choose which platform to keep.</p>';
                        html += '<button class="btn btn-warning" onclick="startMergeFromConflict(\'' + c.source_account_id + '\')">Resolve with Merge</button>';
                        html += '</div>';
                        showResult('linkResult', html);
                    } else if (data.reason && data.reason.startsWith('same_platform_already_linked')) {
                        // Same platform type - cannot be resolved with merge
                        let html = '<div class="alert alert-error">';
                        html += '<strong>Cannot Link!</strong><br><br>';
                        html += 'You already have a different account linked with the same platform type.<br>';
                        html += 'This cannot be resolved with Merge because both accounts use the same platform.';
                        html += '</div>';
                        showResult('linkResult', html);
                    } else {
                        showResult('linkResult', '<div class="alert alert-error">' + data.error + '</div>');
                    }
                } else {
                    showResult('linkResult', '<div class="alert alert-success">Linked successfully!</div>');
                    setTimeout(() => location.reload(), 1500);
                }
            });
            return false;
        }

        function startMergeFromConflict(sourceAccountId) {
            document.getElementById('mergeSourceId').value = sourceAccountId;
            checkMergeEligibility();
            document.getElementById('mergeSourceId').scrollIntoView({ behavior: 'smooth' });
        }

        function unlinkAccount(accountId, namespace) {
            if (!confirm('Unlink ' + namespace + '? This will restore the original HEADLESS account.')) return;
            fetch('/unlink', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'account_id=' + accountId + '&namespace=' + encodeURIComponent(namespace)
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    showResult('result', '<div class="alert alert-error">Unlink failed: ' + data.error + '</div>');
                } else {
                    showResult('result', '<div class="alert alert-success">Unlinked! HEADLESS restored: ' + data.restored_headless_id + '</div>');
                    setTimeout(() => location.reload(), 1500);
                }
            })
            .catch(err => {
                showResult('result', '<div class="alert alert-error">Unlink request failed: ' + err.message + '</div>');
            });
        }

        var mergeConflicts = [];
        var mergeSourceId = '';

        function startMerge(accountId) {
            document.getElementById('mergeSourceId').value = accountId;
            checkMergeEligibility();
        }

        function checkMergeEligibility() {
            mergeSourceId = document.getElementById('mergeSourceId').value;
            if (!mergeSourceId) { alert('Enter source account ID'); return; }

            fetch('/merge/check?target_account_id={{if .Session}}{{.Session.AccountID}}{{end}}&source_account_id=' + mergeSourceId)
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    showResult('mergeResult', '<div class="alert alert-error">' + data.error + '</div>');
                    return;
                }

                mergeConflicts = data.conflicts || [];
                let html = '';

                if (data.eligible) {
                    html = '<div class="alert alert-success">Ready to merge! Namespaces: ' + (data.namespaces||[]).join(', ') + '</div>';
                    html += '<button class="btn btn-success" onclick="executeMerge()">Execute Merge</button>';
                } else if (data.reason === 'conflict_detected') {
                    html = '<div class="alert alert-warning">Conflicts detected! Select which platform to keep:</div>';
                    html += '<table style="margin: 10px 0;"><tr><th>Namespace</th><th>Source</th><th>Target</th><th>Keep</th></tr>';
                    mergeConflicts.forEach((c, i) => {
                        html += '<tr><td class="namespace">' + c.namespace + '</td>';
                        html += '<td><span class="platform-badge platform-' + c.source_provider_type + '">' + c.source_provider_type + '</span></td>';
                        html += '<td><span class="platform-badge platform-' + c.target_provider_type + '">' + c.target_provider_type + '</span></td>';
                        html += '<td><select id="res_' + i + '" data-ns="' + c.namespace + '">';
                        html += '<option value="SOURCE">SOURCE (' + c.source_provider_type + ')</option>';
                        html += '<option value="TARGET">TARGET (' + c.target_provider_type + ')</option>';
                        html += '</select></td></tr>';
                    });
                    html += '</table>';
                    if (data.namespaces && data.namespaces.length > 0) {
                        html += '<p>Non-conflict namespaces: ' + data.namespaces.join(', ') + '</p>';
                    }
                    html += '<button class="btn btn-warning" onclick="executeMerge()">Execute Merge</button>';
                } else if (data.reason && data.reason.startsWith('same_platform_not_mergeable')) {
                    // Same platform type - cannot merge
                    html = '<div class="alert alert-error">';
                    html += '<strong>Cannot Merge!</strong><br><br>';
                    html += 'Both accounts have the same platform type in the same namespace.<br>';
                    html += 'Merge is only possible when accounts have <strong>different platform types</strong> (e.g., Xbox vs PlayStation).';
                    html += '</div>';
                } else {
                    html = '<div class="alert alert-error">' + data.reason + '</div>';
                }
                showResult('mergeResult', html);
            });
        }

        function executeMerge() {
            let resolutions = [];
            mergeConflicts.forEach((c, i) => {
                let sel = document.getElementById('res_' + i);
                if (sel) resolutions.push({ namespace: c.namespace, keep: sel.value });
            });

            fetch('/merge', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ source_account_id: mergeSourceId, conflict_resolutions: resolutions })
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    showResult('mergeResult', '<div class="alert alert-error">' + data.error + '</div>');
                } else {
                    showResult('mergeResult', '<div class="alert alert-success">Merged! Namespaces: ' + (data.merged_namespaces||[]).join(', ') + '</div>');
                    setTimeout(() => location.reload(), 1500);
                }
            });
        }
    </script>
</body>
</html>`

const loginTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 20px; background: #f0f2f5;
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
        }
        .card { background: white; padding: 40px; border-radius: 12px; width: 360px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h2 { margin: 0 0 30px 0; text-align: center; color: #333; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; color: #555; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
        .btn { width: 100%; padding: 14px; background: #667eea; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #5a6fd6; }
        .error { background: #fee2e2; color: #991b1b; padding: 12px; border-radius: 6px; margin-bottom: 20px; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Login</h2>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form action="/login" method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="links">
            <a href="/register">Create account</a> | <a href="/">Back</a>
        </div>
    </div>
</body>
</html>`

const registerTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 20px; background: #f0f2f5;
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
        }
        .card { background: white; padding: 40px; border-radius: 12px; width: 400px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h2 { margin: 0 0 10px 0; text-align: center; color: #333; }
        .subtitle { text-align: center; color: #666; margin-bottom: 20px; }
        .badge { display: inline-block; background: #667eea; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; color: #555; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
        .btn { width: 100%; padding: 14px; background: #10b981; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #059669; }
        .btn-secondary { background: #6b7280; margin-bottom: 15px; }
        .btn-secondary:hover { background: #4b5563; }
        .error { background: #fee2e2; color: #991b1b; padding: 12px; border-radius: 6px; margin-bottom: 20px; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Register HEAD Account</h2>
        <p class="subtitle">Namespace: <span class="badge">PUBLISHER</span></p>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <button type="button" class="btn btn-secondary" onclick="fillRandom()">Fill Random Values</button>
        <form action="/register" method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" id="email" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" id="password" required>
            </div>
            <button type="submit" class="btn">Register</button>
        </form>
        <div class="links">
            <a href="/login">Already have account?</a> | <a href="/">Back</a>
        </div>
    </div>
    <script>
        function fillRandom() {
            const rand = Math.random().toString(36).substring(2, 8);
            document.getElementById('username').value = 'user_' + rand;
            document.getElementById('email').value = 'user_' + rand + '@test.com';
            document.getElementById('password').value = 'pass123';
        }
        // Auto-fill on page load for convenience
        fillRandom();
    </script>
</body>
</html>`
