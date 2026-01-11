package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"golang.org/x/crypto/bcrypt"
)

// HandleAPILogin authenticates a user and issues access/refresh tokens via JSON API.
func (s *Server) HandleAPILogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	var payload struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload",
		})
	}
	if strings.TrimSpace(payload.Username) == "" || strings.TrimSpace(payload.Password) == "" || strings.TrimSpace(payload.Namespace) == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "username, password and namespace are required",
		})
	}

	// Open GORM connection (raw SQL only)
	db, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			return NotImplemented(w, "set USER_DB_DSN to enable login")
		}
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}

	var (
		uid           string
		hash          string
		emailVerified bool
	)
	// Raw query via GORM - also get email_verified status
	row := db.WithContext(r.Context()).Raw(`SELECT id, password_hash, COALESCE(email_verified, FALSE) FROM accounts WHERE username=$1`, payload.Username).Row()
	if err := row.Scan(&uid, &hash, &emailVerified); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "invalid username or password",
		})
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(payload.Password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "invalid username or password",
		})
	}

	// Set namespace for later use
	ns := strings.ToUpper(strings.TrimSpace(payload.Namespace))

	// Check email verification status if required for this namespace
	requireEmailVerification := true
	if s.settingsStore != nil {
		requireEmailVerification = s.settingsStore.IsEmailVerificationRequired(r.Context(), ns)
	}
	if requireEmailVerification && !emailVerified {
		w.WriteHeader(http.StatusForbidden)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "email_verification_required",
			"error_description": "email verification is required before login",
			"account_id":        uid,
		})
	}

	// Set namespace in context for permission resolution
	ctx := r.Context()
	ctx = context.WithValue(ctx, "ns", ns)

	clientID, clientSecret, _ := s.ClientInfoHandler(r)
	tgr := &oauth2.TokenGenerateRequest{ClientID: clientID, ClientSecret: clientSecret, UserID: uid, Request: r}

	// Use GetAccessToken to properly set up perm_resolver, roles_resolver, and user_id in context
	ti, genErr := s.GetAccessToken(ctx, oauth2.PasswordCredentials, tgr)
	if genErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("token generation: %v", genErr),
		})
	}
	return s.token(w, s.GetTokenData(ti), nil)
}

// HandleAPILoginGin authenticates a user using Gin and issues tokens.
func (s *Server) HandleAPILoginGin(c *gin.Context) {
	var payload struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Namespace string `json:"namespace"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON payload"})
		return
	}
	if strings.TrimSpace(payload.Username) == "" || strings.TrimSpace(payload.Password) == "" || strings.TrimSpace(payload.Namespace) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "username, password and namespace are required"})
		return
	}
	db, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			NotImplementedGin(c, "set USER_DB_DSN to enable login")
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}
	var uid, hash string
	var emailVerified bool
	row := db.WithContext(c.Request.Context()).Raw(`SELECT id, password_hash, COALESCE(email_verified, FALSE) FROM accounts WHERE username=$1`, payload.Username).Row()
	if err := row.Scan(&uid, &hash, &emailVerified); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant", "error_description": "invalid username or password"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(payload.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant", "error_description": "invalid username or password"})
		return
	}

	// Set namespace for later use
	ns := strings.ToUpper(strings.TrimSpace(payload.Namespace))

	// Check email verification status if required for this namespace
	requireEmailVerification := true
	if s.settingsStore != nil {
		requireEmailVerification = s.settingsStore.IsEmailVerificationRequired(c.Request.Context(), ns)
	}
	if requireEmailVerification && !emailVerified {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "email_verification_required",
			"error_description": "email verification is required before login",
			"account_id":        uid,
		})
		return
	}

	// Set namespace in context for permission resolution
	ctx := c.Request.Context()
	ctx = context.WithValue(ctx, "ns", ns)

	clientID, clientSecret, _ := s.ClientInfoHandler(c.Request)
	tgr := &oauth2.TokenGenerateRequest{ClientID: clientID, ClientSecret: clientSecret, UserID: uid, Request: c.Request}

	// Use GetAccessToken to properly set up perm_resolver, roles_resolver, and user_id in context
	ti, genErr := s.GetAccessToken(ctx, oauth2.PasswordCredentials, tgr)
	if genErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("token generation: %v", genErr)})
		return
	}
	c.Header("Content-Type", "application/json;charset=UTF-8")
	s.token(c.Writer, s.GetTokenData(ti), nil)
}
