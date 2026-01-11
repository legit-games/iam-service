package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/email"
	"github.com/go-oauth2/oauth2/v4/geoip"
	"github.com/go-oauth2/oauth2/v4/models"
	"golang.org/x/crypto/bcrypt"
)

// JSON API handlers and swagger fragments

// HandleAPIRegisterUser registers a new user.
func (s *Server) HandleAPIRegisterUser(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload",
		})
	}
	payload.Username = strings.TrimSpace(payload.Username)
	payload.Password = strings.TrimSpace(payload.Password)
	if payload.Username == "" || payload.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "username and password are required",
		})
	}

	dbRead, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]interface{}{"error": "not_implemented", "error_description": "set USER_DB_DSN (or MIGRATE_DSN) to enable user registration"})
		}
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
	}
	var exists int
	res := dbRead.WithContext(r.Context()).Raw(`SELECT 1 FROM accounts WHERE username=$1 LIMIT 1`, payload.Username)
	// Scan into exists; if no rows, Scan returns ErrRecordNotFound in GORM v2 when using First
	if err := res.Row().Scan(&exists); err == nil {
		w.WriteHeader(http.StatusConflict)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "conflict",
			"error_description": "username already exists",
		})
	}
	userID := models.LegitID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	dbWrite, err := s.GetIAMWriteDB()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}
	// insert via raw SQL
	if err := dbWrite.WithContext(r.Context()).Exec(`INSERT INTO accounts (id, username, password_hash) VALUES ($1, $2, $3)`, userID, payload.Username, string(hash)).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("insert user: %v", err),
		})
	}

	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(map[string]interface{}{"user_id": userID})
}

// HandleAPIRegisterUserGin registers a new user via Gin.
// After successful registration, sends email verification code.
// Accepts an optional namespace parameter to check namespace-specific settings.
func (s *Server) HandleAPIRegisterUserGin(c *gin.Context) {
	if s.userStore == nil {
		NotImplementedGin(c, "user store not initialized")
		return
	}
	var payload struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Email     string `json:"email"`
		Namespace string `json:"namespace"` // Optional: used to check namespace-specific registration settings
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON payload"})
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	payload.Password = strings.TrimSpace(payload.Password)
	payload.Email = strings.TrimSpace(payload.Email)
	if payload.Username == "" || payload.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "username and password are required"})
		return
	}
	if payload.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "email is required"})
		return
	}
	if !isValidEmail(payload.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid email format"})
		return
	}

	dbRead, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			NotImplementedGin(c, "set USER_DB_DSN or MIGRATE_DSN to enable user registration")
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}

	// Check if username already exists
	var exists int
	if err := dbRead.WithContext(c.Request.Context()).Raw(`SELECT 1 FROM accounts WHERE username=$1 LIMIT 1`, payload.Username).Row().Scan(&exists); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "error_description": "username already exists"})
		return
	}

	// Check if email already exists
	if err := dbRead.WithContext(c.Request.Context()).Raw(`SELECT 1 FROM accounts WHERE email=$1 LIMIT 1`, payload.Email).Row().Scan(&exists); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "error_description": "email already exists"})
		return
	}

	// Get client IP and lookup country
	clientIP := geoip.GetClientIP(c.Request)
	geoClient := geoip.NewClient()
	countryCode := geoClient.LookupCountry(c.Request.Context(), clientIP)
	var country *string
	if countryCode != "" {
		country = &countryCode
	}

	accountID := models.LegitID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	userID, err := s.userStore.CreateHeadAccount(c.Request.Context(), accountID, payload.Username, string(hash), &payload.Email, country)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("create account: %v", err)})
		return
	}

	// Check if email verification is required for the specified namespace
	namespace := strings.ToUpper(strings.TrimSpace(payload.Namespace))
	requireEmailVerification := true
	if s.settingsStore != nil {
		requireEmailVerification = s.settingsStore.IsEmailVerificationRequired(c.Request.Context(), namespace)
	}

	// If email verification is not required, mark email as verified immediately
	if !requireEmailVerification {
		_ = s.userStore.MarkAccountEmailVerified(c.Request.Context(), accountID)
		c.JSON(http.StatusCreated, gin.H{
			"user_id":                     userID,
			"email_verification_required": false,
		})
		return
	}

	// Send email verification code
	response := gin.H{
		"user_id":                     userID,
		"email_verification_required": true,
	}

	if s.emailVerificationStore != nil {
		// Use empty namespace for global account verification
		namespaceID := ""
		result, err := s.emailVerificationStore.CreateVerificationCode(c.Request.Context(), accountID, payload.Email, namespaceID)
		if err == nil && result.Code != nil {
			// Send verification email
			expiresInSecs := int(s.emailVerificationStore.Config.CodeTTL.Seconds())
			expiresInMin := expiresInSecs / 60

			// Try to get namespace-specific sender, fall back to console sender
			sender := s.emailSender
			if s.emailProviderStore != nil && namespaceID != "" {
				if nsSender, err := s.emailProviderStore.GetSender(c.Request.Context(), namespaceID); err == nil {
					sender = nsSender
				}
			}

			if sender != nil {
				emailData := email.EmailVerificationEmailData{
					To:           payload.Email,
					Username:     payload.Username,
					Code:         result.Code.Code,
					ExpiresInMin: expiresInMin,
					AppName:      "OAuth2 Service",
					SupportEmail: "",
				}
				if err := sender.SendEmailVerification(c.Request.Context(), emailData); err != nil {
					// Log error but don't fail registration
					// User can resend verification later
				}
			}

			response["expires_in_secs"] = expiresInSecs
		}
	}

	c.JSON(http.StatusCreated, response)
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	// Basic email validation: must contain @ and at least one . after @
	atIdx := strings.Index(email, "@")
	if atIdx < 1 {
		return false
	}
	domain := email[atIdx+1:]
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return false
	}
	// Check no spaces
	if strings.ContainsAny(email, " \t\n\r") {
		return false
	}
	return true
}

// Swagger fragments for API paths
func (s *Server) swaggerAPILoginPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "IAM login and token issuance",
			"description": "Authenticates a user against the users table and issues access/refresh tokens. Client must authenticate using HTTP Basic.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"username": map[string]interface{}{"type": "string"},
								"password": map[string]interface{}{"type": "string"},
							},
							"required": []string{"username", "password"},
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
				"401": map[string]interface{}{"description": "Unauthorized"},
				"400": map[string]interface{}{"description": "Invalid request"},
			},
			"security": []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}

func (s *Server) swaggerRegisterUserPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "IAM registration",
			"description": "Registers a new user with username and password (bcrypt-hashed).",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type":       "object",
							"properties": map[string]interface{}{"username": map[string]interface{}{"type": "string"}, "password": map[string]interface{}{"type": "string"}},
							"required":   []string{"username", "password"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{"description": "IAM created", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"user_id": map[string]interface{}{"type": "string", "description": "Hyphenless UUID string"}}}}}},
				"400": map[string]interface{}{"description": "Invalid request"},
				"409": map[string]interface{}{"description": "Username conflict"},
			},
		},
	}
}

type BanRequest struct {
	Type   models.BanType `json:"type" binding:"required"` // PERMANENT or TIMED
	Reason string         `json:"reason"`
	Until  *time.Time     `json:"until"` // required when type=TIMED
	// ActorID is no longer accepted from client; derived from caller's access token
}

func (s *Server) HandleBanUserGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	var req BanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if req.Type == models.BanTimed && req.Until == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "until is required for TIMED ban"})
		return
	}
	// Get caller user ID from context (set by TokenMiddleware)
	callerUserID := GetUserIDFromContext(c)
	if callerUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "missing user id in token"})
		return
	}
	// lookup account_id by user id via account_users bridge table
	db, dberr := s.GetIAMReadDB()
	if dberr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": dberr.Error()})
		return
	}
	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=$1`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	userID := c.Param("id")
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	if err := s.userStore.BanUser(c.Request.Context(), userID, ns, req.Type, req.Reason, req.Until, actorAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "banned", "user_id": userID, "namespace": ns, "type": req.Type, "actor_account_id": actorAccountID})
}

func (s *Server) HandleUnbanUserGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	// Get caller user ID from context (set by TokenMiddleware)
	callerUserID := GetUserIDFromContext(c)
	if callerUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "missing user id in token"})
		return
	}
	db, dberr := s.GetIAMReadDB()
	if dberr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": dberr.Error()})
		return
	}
	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=$1`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	userID := c.Param("id")
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	if err := s.userStore.UnbanUser(c.Request.Context(), userID, ns, req.Reason, actorAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unbanned", "user_id": userID, "namespace": ns, "actor_account_id": actorAccountID})
}

// ListUsers returns a list of users with optional filters
// Query parameters:
// - search_type: "user_id", "account_id", "username" (optional, for keyword search)
// - q: search keyword (optional)
// - created_from: start date for created_at filter (RFC3339 format)
// - created_to: end date for created_at filter (RFC3339 format)
// - limit: max results (default 50, max 100)
// - offset: pagination offset (default 0)
//
// Namespace handling (following justice-iam-service pattern):
// - When namespace type is 'publisher': Returns HEAD users only
// - When namespace type is 'game': Returns BODY users for that namespace
//   with publisher (HEAD) user's display_name and email
// - Each account appears only once in the list regardless of how many users it has
func (s *Server) HandleListUsersGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	searchType := strings.TrimSpace(c.Query("search_type"))
	searchQuery := strings.TrimSpace(c.Query("q"))
	createdFrom := strings.TrimSpace(c.Query("created_from"))
	createdTo := strings.TrimSpace(c.Query("created_to"))

	// Parse limit and offset
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &limit); err == nil && parsed > 0 {
			if limit > 100 {
				limit = 100
			}
		}
	}
	offset := 0
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}

	db := s.userStore.DB

	// Check namespace type to determine query strategy
	isPublisherNamespace := false
	if ns != "" {
		var nsType string
		if err := db.WithContext(c.Request.Context()).Raw(`SELECT type FROM namespaces WHERE name = ?`, ns).Row().Scan(&nsType); err == nil {
			isPublisherNamespace = (nsType == "publisher")
		}
	}

	var users []map[string]interface{}
	var query string
	args := []interface{}{}

	if ns != "" && !isPublisherNamespace {
		// Game namespace: Query BODY users for specific namespace
		// Use subquery to get HEAD user's display_name to avoid duplicates
		query = `
			SELECT
				u.id,
				au.account_id,
				u.namespace,
				u.user_type,
				COALESCE(
					(SELECT hu.display_name FROM users hu
					 JOIN account_users hau ON hu.id = hau.user_id
					 WHERE hau.account_id = au.account_id AND hu.user_type = 'HEAD' LIMIT 1),
					u.display_name
				) as display_name,
				u.provider_type,
				u.provider_account_id,
				u.orphaned,
				u.created_at,
				u.updated_at,
				a.email as publisher_email,
				a.username as publisher_username,
				a.account_type
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			LEFT JOIN accounts a ON au.account_id = a.id
			WHERE u.namespace = ? AND u.user_type = 'BODY'`
		args = append(args, ns)
	} else {
		// Publisher namespace or no namespace: Query HEAD users only
		// Each account appears once through its HEAD user
		query = `
			SELECT
				u.id,
				au.account_id,
				u.namespace,
				u.user_type,
				u.display_name,
				u.provider_type,
				u.provider_account_id,
				u.orphaned,
				u.created_at,
				u.updated_at,
				a.email as publisher_email,
				a.username as publisher_username,
				a.account_type
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			LEFT JOIN accounts a ON au.account_id = a.id
			WHERE u.user_type = 'HEAD'`
	}

	// Keyword search based on search_type
	if searchQuery != "" {
		switch searchType {
		case "user_id":
			query += ` AND u.id LIKE ?`
			args = append(args, "%"+searchQuery+"%")
		case "account_id":
			query += ` AND au.account_id LIKE ?`
			args = append(args, "%"+searchQuery+"%")
		case "username":
			query += ` AND a.username LIKE ?`
			args = append(args, "%"+searchQuery+"%")
		default:
			// Search all fields
			query += ` AND (u.id LIKE ? OR au.account_id LIKE ? OR a.username LIKE ?)`
			args = append(args, "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%")
		}
	}

	// Date range filter
	if createdFrom != "" {
		if t, err := time.Parse(time.RFC3339, createdFrom); err == nil {
			query += ` AND u.created_at >= ?`
			args = append(args, t)
		}
	}
	if createdTo != "" {
		if t, err := time.Parse(time.RFC3339, createdTo); err == nil {
			query += ` AND u.created_at <= ?`
			args = append(args, t)
		}
	}

	query += ` ORDER BY u.created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	if err := db.WithContext(c.Request.Context()).Raw(query, args...).Scan(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	if users == nil {
		users = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"users": users, "count": len(users)})
}

// GetUser returns user details by ID within a namespace
// Supports search_type query parameter: "user_id" or "account_id"
// If no search_type is provided, searches by user ID, account ID, or username
//
// Namespace handling (following justice-iam-service pattern):
// - When namespace type is 'publisher': Returns HEAD user only
// - When namespace type is 'game': Returns the BODY user for that namespace
//   with publisher (HEAD) user's display_name and email
func (s *Server) HandleGetUserGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	searchID := strings.TrimSpace(c.Param("id"))
	searchType := strings.TrimSpace(c.Query("search_type"))
	if searchID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "user ID is required"})
		return
	}

	var user map[string]interface{}
	db := s.userStore.DB

	// Check namespace type to determine query strategy
	isPublisherNamespace := false
	if ns != "" {
		var nsType string
		if err := db.WithContext(c.Request.Context()).Raw(`SELECT type FROM namespaces WHERE name = ?`, ns).Row().Scan(&nsType); err == nil {
			isPublisherNamespace = (nsType == "publisher")
		}
	}

	var baseSelect string
	var baseFrom string
	var whereClause string
	args := []interface{}{}

	if ns != "" && !isPublisherNamespace {
		// Game namespace: Get BODY user with publisher info
		// Use subquery to get HEAD user's display_name to avoid duplicates
		baseSelect = `
			SELECT
				u.id,
				au.account_id,
				u.namespace,
				u.user_type,
				COALESCE(
					(SELECT hu.display_name FROM users hu
					 JOIN account_users hau ON hu.id = hau.user_id
					 WHERE hau.account_id = au.account_id AND hu.user_type = 'HEAD' LIMIT 1),
					u.display_name
				) as display_name,
				u.provider_type,
				u.provider_account_id,
				u.orphaned,
				u.created_at,
				u.updated_at,
				a.email as publisher_email,
				a.username as publisher_username,
				a.country,
				a.account_type`
		baseFrom = `
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			LEFT JOIN accounts a ON au.account_id = a.id`
		whereClause = ` WHERE u.namespace = ? AND u.user_type = 'BODY'`
		args = append(args, ns)
	} else {
		// Publisher namespace or no namespace: Get HEAD user only
		baseSelect = `
			SELECT
				u.id,
				au.account_id,
				u.namespace,
				u.user_type,
				u.display_name,
				u.provider_type,
				u.provider_account_id,
				u.orphaned,
				u.created_at,
				u.updated_at,
				a.email as publisher_email,
				a.username as publisher_username,
				a.country,
				a.account_type`
		baseFrom = `
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			LEFT JOIN accounts a ON au.account_id = a.id`
		whereClause = ` WHERE u.user_type = 'HEAD'`
	}

	// Build query based on search type
	switch searchType {
	case "user_id":
		whereClause += ` AND u.id = ?`
		args = append(args, searchID)
	case "account_id":
		whereClause += ` AND au.account_id = ?`
		args = append(args, searchID)
	case "username":
		whereClause += ` AND a.username = ?`
		args = append(args, searchID)
	default:
		// Default: search by user ID, account ID, or username
		whereClause += ` AND (u.id = ? OR au.account_id = ? OR a.username = ?)`
		args = append(args, searchID, searchID, searchID)
	}

	query := baseSelect + baseFrom + whereClause + ` LIMIT 1`

	if err := db.WithContext(c.Request.Context()).Raw(query, args...).Scan(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	if user == nil || len(user) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// List bans for a user in a namespace
func (s *Server) HandleListUserBansGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("id"))
	var rows []map[string]interface{}
	db := s.userStore.DB
	if err := db.WithContext(c.Request.Context()).Raw(`SELECT id, user_id, namespace, type, reason, until, created_at FROM user_bans WHERE user_id=? AND namespace=? ORDER BY created_at DESC`, userID, ns).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bans": rows})
}

// List bans in a namespace, optional active=true filters to current bans only
func (s *Server) HandleListNamespaceBansGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	active := strings.EqualFold(strings.TrimSpace(c.Query("active")), "true")
	var rows []map[string]interface{}
	db := s.userStore.DB
	query := `SELECT id, user_id, namespace, type, reason, until, created_at FROM user_bans WHERE namespace=?`
	if active {
		query += ` AND (type='PERMANENT' OR (type='TIMED' AND (until IS NULL OR until>NOW())))`
	}
	query += ` ORDER BY created_at DESC`
	if err := db.WithContext(c.Request.Context()).Raw(query, ns).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bans": rows})
}

type AccountBanRequest struct {
	Type   models.BanType `json:"type" binding:"required"` // PERMANENT or TIMED
	Reason string         `json:"reason"`
	Until  *time.Time     `json:"until"` // required when type=TIMED
}

func (s *Server) HandleBanAccountGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	var req AccountBanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if req.Type == models.BanTimed && req.Until == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "until is required for TIMED ban"})
		return
	}
	// Get caller user ID from context (set by TokenMiddleware)
	callerUserID := GetUserIDFromContext(c)
	if callerUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "missing user id in token"})
		return
	}
	db, dberr := s.GetIAMReadDB()
	if dberr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": dberr.Error()})
		return
	}
	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=$1`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	accountID := c.Param("id")
	if err := s.userStore.BanAccount(c.Request.Context(), accountID, req.Type, req.Reason, req.Until, actorAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "banned", "account_id": accountID, "type": req.Type, "actor_account_id": actorAccountID})
}

func (s *Server) HandleUnbanAccountGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	// Get caller user ID from context (set by TokenMiddleware)
	callerUserID := GetUserIDFromContext(c)
	if callerUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "missing user id in token"})
		return
	}
	db, dberr := s.GetIAMReadDB()
	if dberr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": dberr.Error()})
		return
	}
	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=$1`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	accountID := c.Param("id")
	if err := s.userStore.UnbanAccount(c.Request.Context(), accountID, req.Reason, actorAccountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unbanned", "account_id": accountID, "actor_account_id": actorAccountID})
}

// List bans for an account
func (s *Server) HandleListAccountBansGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	accountID := strings.TrimSpace(c.Param("id"))
	var rows []map[string]interface{}
	db := s.userStore.DB
	if err := db.WithContext(c.Request.Context()).Raw(`SELECT id, account_id, type, reason, until, created_at FROM account_bans WHERE account_id=? ORDER BY created_at DESC`, accountID).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bans": rows})
}

// HandleListLoginHistoryGin returns login history for an account
// Query parameters:
// - limit: max results (default 50, max 100)
// - offset: pagination offset (default 0)
func (s *Server) HandleListLoginHistoryGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	accountID := strings.TrimSpace(c.Param("id"))
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "account ID is required"})
		return
	}

	// Parse limit and offset
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &limit); err == nil && parsed > 0 {
			if limit > 100 {
				limit = 100
			}
		}
	}
	offset := 0
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}

	var rows []map[string]interface{}
	db := s.userStore.DB
	query := `SELECT id, account_id, login_at, ip_address, user_agent, success, failure_reason
		FROM login_history
		WHERE account_id = ?
		ORDER BY login_at DESC
		LIMIT ? OFFSET ?`
	if err := db.WithContext(c.Request.Context()).Raw(query, accountID, limit, offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	if rows == nil {
		rows = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"login_history": rows, "count": len(rows)})
}

// HandleGetSignupStatsGin returns signup statistics for the dashboard.
// Returns today's signups, this week's signups, this month's signups, and monthly breakdown.
// Path param :ns specifies the namespace to filter by. If empty, returns global stats.
// HEAD and BODY users linked to the same account are counted as 1 user.
func (s *Server) HandleGetSignupStatsGin(c *gin.Context) {
	if s.userStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "user store not initialized"})
		return
	}
	namespace := strings.TrimSpace(c.Param("ns"))
	stats, err := s.userStore.GetSignupStats(c.Request.Context(), namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}
