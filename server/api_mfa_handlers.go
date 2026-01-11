package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/store"
	"golang.org/x/crypto/bcrypt"
)

// ========== User MFA Endpoints ==========

// HandleMFASetupGin initiates MFA setup for the authenticated user
// GET /iam/v1/auth/mfa/setup
func (s *Server) HandleMFASetupGin(c *gin.Context) {
	// Get account ID from token context (set by TokenMiddleware)
	accountID := c.GetString("account_id")
	if accountID == "" {
		// Try to get from user_id claim
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	// Get account name (username or email) for TOTP display
	accountName := c.GetString("username")
	if accountName == "" {
		accountName = accountID
	}

	// Initiate MFA setup
	result, err := s.mfaStore.InitiateTOTPSetup(c.Request.Context(), accountID, accountName)
	if err != nil {
		if strings.Contains(err.Error(), "already enabled") {
			c.JSON(http.StatusConflict, gin.H{"error": "mfa_already_enabled", "error_description": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":      result.Secret,
		"qr_code_url": result.QRCodeURL,
		"issuer":      result.Issuer,
	})
}

// HandleMFASetupVerifyGin verifies TOTP and enables MFA
// POST /iam/v1/auth/mfa/setup/verify
func (s *Server) HandleMFASetupVerifyGin(c *gin.Context) {
	accountID := c.GetString("account_id")
	if accountID == "" {
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	var payload struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code is required"})
		return
	}

	result, err := s.mfaStore.VerifyAndEnableTOTP(c.Request.Context(), accountID, payload.Code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	if !result.Success {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_code",
			"error_description": result.Message,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"backup_codes": result.BackupCodes,
		"message":      result.Message,
	})
}

// HandleMFAStatusGin returns user's MFA status
// GET /iam/v1/auth/mfa/status
func (s *Server) HandleMFAStatusGin(c *gin.Context) {
	accountID := c.GetString("account_id")
	if accountID == "" {
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	status, err := s.mfaStore.GetMFAStatus(c.Request.Context(), accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// HandleMFABackupCodesGin returns remaining backup code count
// GET /iam/v1/auth/mfa/backup-codes
func (s *Server) HandleMFABackupCodesGin(c *gin.Context) {
	accountID := c.GetString("account_id")
	if accountID == "" {
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	count, err := s.mfaStore.GetBackupCodeCount(c.Request.Context(), accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"remaining_count": count})
}

// HandleMFABackupCodesRegenerateGin generates new backup codes
// POST /iam/v1/auth/mfa/backup-codes/regenerate
func (s *Server) HandleMFABackupCodesRegenerateGin(c *gin.Context) {
	accountID := c.GetString("account_id")
	if accountID == "" {
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	var payload struct {
		Code     string `json:"code" binding:"required"`
		CodeType string `json:"code_type" binding:"required"` // "totp" or "backup"
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code and code_type are required"})
		return
	}

	// Verify the code before regenerating
	valid, err := s.verifyMFACode(c.Request.Context(), accountID, payload.Code, payload.CodeType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code", "error_description": "invalid verification code"})
		return
	}

	// Generate new backup codes
	codes, err := s.mfaStore.GenerateBackupCodes(c.Request.Context(), accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"backup_codes": codes,
		"message":      "Backup codes regenerated successfully",
	})
}

// HandleMFADisableGin disables MFA for the user
// POST /iam/v1/auth/mfa/disable
func (s *Server) HandleMFADisableGin(c *gin.Context) {
	accountID := c.GetString("account_id")
	if accountID == "" {
		if userID := c.GetString("user_id"); userID != "" {
			accountID = userID
		}
	}
	if accountID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "authentication required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	var payload struct {
		Password string `json:"password" binding:"required"`
		Code     string `json:"code" binding:"required"`
		CodeType string `json:"code_type" binding:"required"` // "totp" or "backup"
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "password, code, and code_type are required"})
		return
	}

	// Verify password
	db, err := s.GetIAMReadDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "database unavailable"})
		return
	}

	var hash string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT password_hash FROM accounts WHERE id=$1`, accountID).Row()
	if err := row.Scan(&hash); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "account not found"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(payload.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_password", "error_description": "invalid password"})
		return
	}

	// Verify MFA code
	valid, err := s.verifyMFACode(c.Request.Context(), accountID, payload.Code, payload.CodeType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code", "error_description": "invalid verification code"})
		return
	}

	// Disable MFA
	if err := s.mfaStore.DisableMFA(c.Request.Context(), accountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "MFA disabled successfully",
	})
}

// ========== Public Login MFA Endpoint ==========

// HandleLoginMFAVerifyGin completes MFA verification during login
// POST /iam/v1/public/login/mfa/verify
func (s *Server) HandleLoginMFAVerifyGin(c *gin.Context) {
	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	var payload struct {
		MFAToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
		CodeType string `json:"code_type" binding:"required"` // "totp" or "backup"
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "mfa_token, code, and code_type are required"})
		return
	}

	// Validate MFA token
	tokenResult, err := s.mfaStore.ValidateMFAToken(c.Request.Context(), payload.MFAToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	if tokenResult.NotFound {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "MFA token not found"})
		return
	}
	if tokenResult.AlreadyUsed {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token_used", "error_description": "MFA token already used"})
		return
	}
	if tokenResult.Expired {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token_expired", "error_description": "MFA token expired"})
		return
	}
	if !tokenResult.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "invalid MFA token"})
		return
	}

	// Check rate limiting
	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	rateLimit, err := s.mfaStore.CheckRateLimit(c.Request.Context(), tokenResult.AccountID, "login")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	if !rateLimit.Allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":             "rate_limited",
			"error_description": "too many failed attempts",
			"retry_after_secs":  rateLimit.RetryAfterSec,
		})
		return
	}

	// Verify MFA code
	valid, err := s.verifyMFACode(c.Request.Context(), tokenResult.AccountID, payload.Code, payload.CodeType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	// Record attempt
	if err := s.mfaStore.RecordAttempt(c.Request.Context(), tokenResult.AccountID, "login", valid, ip, userAgent); err != nil {
		// Log but don't fail
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code", "error_description": "invalid verification code"})
		return
	}

	// Generate OAuth tokens
	ctx := c.Request.Context()
	ctx = context.WithValue(ctx, "ns", tokenResult.Namespace)

	clientID := tokenResult.ClientID
	if clientID == "" {
		clientID, _, _ = s.ClientInfoHandler(c.Request)
	}
	tgr := &oauth2.TokenGenerateRequest{
		ClientID: clientID,
		UserID:   tokenResult.AccountID,
		Request:  c.Request,
	}

	ti, genErr := s.GetAccessToken(ctx, oauth2.PasswordCredentials, tgr)
	if genErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "token generation failed"})
		return
	}

	c.Header("Content-Type", "application/json;charset=UTF-8")
	s.token(c.Writer, s.GetTokenData(ti), nil)
}

// ========== Admin Endpoints ==========

// HandleAdminGetNamespaceMFAGin gets MFA settings for namespace
// GET /iam/v1/admin/namespaces/:ns/mfa/settings
func (s *Server) HandleAdminGetNamespaceMFAGin(c *gin.Context) {
	namespace := c.Param("ns")
	if namespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "namespace is required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	settings, err := s.mfaStore.GetNamespaceMFASettings(c.Request.Context(), namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	if settings == nil {
		c.JSON(http.StatusOK, gin.H{
			"namespace":         namespace,
			"mfa_required":      false,
			"grace_period_days": 0,
		})
		return
	}

	c.JSON(http.StatusOK, settings)
}

// HandleAdminSetNamespaceMFAGin sets MFA requirement for namespace
// POST /iam/v1/admin/namespaces/:ns/mfa/settings
func (s *Server) HandleAdminSetNamespaceMFAGin(c *gin.Context) {
	namespace := c.Param("ns")
	if namespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "namespace is required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	var payload struct {
		MFARequired     bool `json:"mfa_required"`
		GracePeriodDays int  `json:"grace_period_days"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if err := s.mfaStore.SetNamespaceMFASettings(c.Request.Context(), namespace, payload.MFARequired, payload.GracePeriodDays); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":           true,
		"namespace":         namespace,
		"mfa_required":      payload.MFARequired,
		"grace_period_days": payload.GracePeriodDays,
	})
}

// HandleAdminGetUserMFAStatusGin checks user MFA status
// GET /iam/v1/admin/namespaces/:ns/users/:userId/mfa/status
func (s *Server) HandleAdminGetUserMFAStatusGin(c *gin.Context) {
	userID := c.Param("userId")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "userId is required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	// Get account ID from user ID
	accountID, err := s.getAccountIDFromUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	status, err := s.mfaStore.GetMFAStatus(c.Request.Context(), accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":            userID,
		"account_id":         accountID,
		"mfa_enabled":        status.Enabled,
		"totp_verified":      status.TOTPVerified,
		"backup_codes_count": status.BackupCodesCount,
		"enabled_at":         status.EnabledAt,
	})
}

// HandleAdminDisableUserMFAGin admin force-disables user MFA
// DELETE /iam/v1/admin/namespaces/:ns/users/:userId/mfa
func (s *Server) HandleAdminDisableUserMFAGin(c *gin.Context) {
	userID := c.Param("userId")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "userId is required"})
		return
	}

	if s.mfaStore == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "MFA is not configured"})
		return
	}

	// Get account ID from user ID
	accountID, err := s.getAccountIDFromUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "user not found"})
		return
	}

	if err := s.mfaStore.DisableMFA(c.Request.Context(), accountID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"user_id":    userID,
		"account_id": accountID,
		"message":    "MFA disabled successfully",
	})
}

// ========== Helper Functions ==========

// verifyMFACode verifies a TOTP or backup code
func (s *Server) verifyMFACode(ctx context.Context, accountID, code, codeType string) (bool, error) {
	switch codeType {
	case "totp":
		return s.mfaStore.ValidateTOTPCode(ctx, accountID, code)
	case "backup":
		return s.mfaStore.ValidateBackupCode(ctx, accountID, code)
	default:
		return false, nil
	}
}

// getAccountIDFromUserID retrieves account ID from user ID
func (s *Server) getAccountIDFromUserID(ctx context.Context, userID string) (string, error) {
	db, err := s.GetIAMReadDB()
	if err != nil {
		return "", err
	}

	var accountID string
	// First try if userID is actually an account ID
	row := db.WithContext(ctx).Raw(`SELECT id FROM accounts WHERE id=$1`, userID).Row()
	if err := row.Scan(&accountID); err == nil {
		return accountID, nil
	}

	// Try to get account ID from users table via account_users
	row = db.WithContext(ctx).Raw(`
		SELECT au.account_id FROM account_users au
		WHERE au.user_id = $1
		LIMIT 1
	`, userID).Row()
	if err := row.Scan(&accountID); err != nil {
		return "", err
	}

	return accountID, nil
}

// checkMFAForLogin checks MFA status for login flow and returns appropriate response
// Returns: (mfaRequired bool, mfaToken string, err error)
func (s *Server) checkMFAForLogin(ctx context.Context, accountID, namespace, clientID string) (bool, string, error) {
	if s.mfaStore == nil {
		return false, "", nil
	}

	// Check if MFA is enabled for this account
	mfaEnabled, err := s.mfaStore.IsMFAEnabled(ctx, accountID)
	if err != nil {
		return false, "", err
	}

	if mfaEnabled {
		// Create MFA token for two-phase login
		mfaToken, err := s.mfaStore.CreateMFAToken(ctx, accountID, namespace, clientID)
		if err != nil {
			return false, "", err
		}
		return true, mfaToken, nil
	}

	return false, "", nil
}

// isMFASetupRequired checks if MFA setup is required for a namespace but user hasn't set it up
func (s *Server) isMFASetupRequired(ctx context.Context, accountID, namespace string) bool {
	if s.mfaStore == nil {
		return false
	}

	// Check if namespace requires MFA
	if !s.mfaStore.IsMFARequiredForNamespace(ctx, namespace) {
		return false
	}

	// Check if user has MFA enabled
	mfaEnabled, err := s.mfaStore.IsMFAEnabled(ctx, accountID)
	if err != nil {
		return false
	}

	return !mfaEnabled
}

// GetMFAStore returns the MFA store for external use
func (s *Server) GetMFAStore() *store.MFAStore {
	return s.mfaStore
}
