package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/email"
)

// RequestEmailVerificationRequest is the request body for requesting email verification
type RequestEmailVerificationRequest struct {
	Email string `json:"email" binding:"required"`
}

// RequestEmailVerificationResponse is the response for email verification request
type RequestEmailVerificationResponse struct {
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	ExpiresInSecs   int    `json:"expires_in_secs,omitempty"`
	AlreadyVerified bool   `json:"already_verified,omitempty"`
}

// HandleRequestEmailVerificationGin handles POST /iam/v1/public/users/request-email-verification
// Initiates email verification flow by generating code and sending email
func (s *Server) HandleRequestEmailVerificationGin(c *gin.Context) {
	if s.emailVerificationStore == nil {
		NotImplementedGin(c, "email verification not configured")
		return
	}

	var req RequestEmailVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload or missing email",
		})
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	if emailAddr == "" || !isValidEmail(emailAddr) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "valid email is required",
		})
		return
	}

	// Get the account ID from bearer token or session
	accountID, namespaceID, err := s.getAccountFromRequest(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	// Get username from database for email
	var username string
	db, err := s.GetIAMReadDB()
	if err == nil {
		row := db.WithContext(c.Request.Context()).Raw(
			`SELECT username FROM accounts WHERE id = $1 LIMIT 1`, accountID,
		).Row()
		_ = row.Scan(&username)
	}

	// Create verification code
	result, err := s.emailVerificationStore.CreateVerificationCode(c.Request.Context(), accountID, emailAddr, namespaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create verification code",
		})
		return
	}

	// Handle already verified
	if result.AlreadyVerified {
		c.JSON(http.StatusOK, RequestEmailVerificationResponse{
			Success:         true,
			Message:         "Email is already verified",
			AlreadyVerified: true,
		})
		return
	}

	// Handle rate limiting
	if result.RateLimited {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":             "rate_limited",
			"error_description": "too many verification requests, please try again later",
			"retry_after":       result.RetryAfterSecs,
		})
		return
	}

	// If existing code, just acknowledge
	if result.ExistingCodeExp != nil {
		c.JSON(http.StatusOK, RequestEmailVerificationResponse{
			Success:       true,
			Message:       "Verification code has been sent to your email",
			ExpiresInSecs: int(time.Until(*result.ExistingCodeExp).Seconds()),
		})
		return
	}

	// Send email with code using namespace-specific email sender
	if result.Code != nil {
		sender, senderErr := s.emailProviderStore.GetSender(c.Request.Context(), namespaceID)
		if senderErr != nil {
			// Fallback to console sender
			sender = s.emailSender
		}

		if sender != nil {
			emailData := email.EmailVerificationEmailData{
				To:           emailAddr,
				Username:     username,
				Code:         result.Code.Code,
				ExpiresInMin: int(s.emailVerificationStore.Config.CodeTTL.Minutes()),
				AppName:      "OAuth2 Service",
				SupportEmail: "",
			}
			if err := sender.SendEmailVerification(c.Request.Context(), emailData); err != nil {
				// Log error but don't expose to user
			}
		}
	}

	c.JSON(http.StatusOK, RequestEmailVerificationResponse{
		Success:       true,
		Message:       "Verification code has been sent to your email",
		ExpiresInSecs: int(s.emailVerificationStore.Config.CodeTTL.Seconds()),
	})
}

// ValidateEmailVerificationResponse is the response for code validation
type ValidateEmailVerificationResponse struct {
	Valid             bool   `json:"valid"`
	Reason            string `json:"reason,omitempty"`
	RemainingAttempts int    `json:"remaining_attempts,omitempty"`
	LockedUntil       string `json:"locked_until,omitempty"` // RFC3339 format
}

// HandleValidateEmailVerificationCodeGin handles GET /iam/v1/public/users/verify-email/validate
// Validates a verification code without consuming it
func (s *Server) HandleValidateEmailVerificationCodeGin(c *gin.Context) {
	if s.emailVerificationStore == nil {
		NotImplementedGin(c, "email verification not configured")
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(c.Query("email")))
	code := strings.TrimSpace(c.Query("code"))

	if emailAddr == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "email and code are required",
		})
		return
	}

	// Get namespace from request
	_, namespaceID, err := s.getAccountFromRequest(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	// Validate code format (6 digits)
	if len(code) != 6 || !isNumeric(code) {
		c.JSON(http.StatusOK, ValidateEmailVerificationResponse{
			Valid:  false,
			Reason: "invalid_code_format",
		})
		return
	}

	result, err := s.emailVerificationStore.ValidateCodeOnly(c.Request.Context(), emailAddr, code, namespaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "validation failed",
		})
		return
	}

	resp := ValidateEmailVerificationResponse{
		Valid:             result.Valid,
		RemainingAttempts: result.RemainingAttempts,
	}

	if result.NotFound {
		resp.Reason = "code_not_found"
	} else if result.AlreadyVerified {
		resp.Reason = "already_verified"
	} else if result.Expired {
		resp.Reason = "code_expired"
	} else if result.Locked {
		resp.Reason = "account_locked"
		if result.LockedUntil != nil {
			resp.LockedUntil = result.LockedUntil.Format(time.RFC3339)
		}
	} else if !result.Valid {
		resp.Reason = "invalid_code"
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyEmailRequest is the request for email verification execution
type VerifyEmailRequest struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// VerifyEmailResponse is the response for email verification
type VerifyEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// HandleVerifyEmailGin handles POST /iam/v1/public/users/verify-email
// Verifies an email address using the verification code
func (s *Server) HandleVerifyEmailGin(c *gin.Context) {
	if s.emailVerificationStore == nil {
		NotImplementedGin(c, "email verification not configured")
		return
	}

	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		})
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	code := strings.TrimSpace(req.Code)

	// Validate inputs
	if emailAddr == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "email and code are required",
		})
		return
	}

	// Get namespace from request
	_, namespaceID, err := s.getAccountFromRequest(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	// Validate code format
	if len(code) != 6 || !isNumeric(code) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_code",
			"error_description": "code must be 6 digits",
		})
		return
	}

	// Verify the code
	result, err := s.emailVerificationStore.VerifyCode(c.Request.Context(), emailAddr, code, namespaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "verification failed",
		})
		return
	}

	if !result.Valid {
		status := http.StatusBadRequest
		resp := gin.H{"error": "invalid_code"}

		if result.Locked {
			status = http.StatusTooManyRequests
			resp["error"] = "account_locked"
			resp["error_description"] = "too many failed attempts, verification temporarily locked"
			if result.LockedUntil != nil {
				resp["locked_until"] = result.LockedUntil.Format(time.RFC3339)
			}
		} else if result.AlreadyVerified {
			// Email is already verified, return success
			c.JSON(http.StatusOK, VerifyEmailResponse{
				Success: true,
				Message: "Email is already verified",
			})
			return
		} else if result.Expired {
			resp["error_description"] = "code has expired"
		} else if result.NotFound {
			resp["error_description"] = "no active verification code found"
		} else {
			resp["error_description"] = "invalid code"
			resp["remaining_attempts"] = result.RemainingAttempts
		}

		c.JSON(status, resp)
		return
	}

	// Update user's email_verified status in database
	if result.Code != nil {
		db, err := s.GetIAMWriteDB()
		if err == nil {
			now := time.Now().UTC()
			db.WithContext(c.Request.Context()).Exec(
				`UPDATE users SET email_verified = true, email_verified_at = $1 WHERE id = $2`,
				now, result.Code.AccountID,
			)
		}
	}

	c.JSON(http.StatusOK, VerifyEmailResponse{
		Success: true,
		Message: "Email has been verified successfully",
	})
}

// HandleResendEmailVerificationGin handles POST /iam/v1/public/users/resend-email-verification
// Resends the verification code by invalidating existing codes and creating a new one
func (s *Server) HandleResendEmailVerificationGin(c *gin.Context) {
	if s.emailVerificationStore == nil {
		NotImplementedGin(c, "email verification not configured")
		return
	}

	var req RequestEmailVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload or missing email",
		})
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	if emailAddr == "" || !isValidEmail(emailAddr) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "valid email is required",
		})
		return
	}

	// Get the account ID from bearer token or session
	accountID, namespaceID, err := s.getAccountFromRequest(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	// Get username from database for email
	var username string
	db, err := s.GetIAMReadDB()
	if err == nil {
		row := db.WithContext(c.Request.Context()).Raw(
			`SELECT username FROM accounts WHERE id = $1 LIMIT 1`, accountID,
		).Row()
		_ = row.Scan(&username)
	}

	// Resend verification code (invalidates existing and creates new)
	result, err := s.emailVerificationStore.ResendVerificationCode(c.Request.Context(), accountID, emailAddr, namespaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to resend verification code",
		})
		return
	}

	// Handle already verified
	if result.AlreadyVerified {
		c.JSON(http.StatusOK, RequestEmailVerificationResponse{
			Success:         true,
			Message:         "Email is already verified",
			AlreadyVerified: true,
		})
		return
	}

	// Handle rate limiting
	if result.RateLimited {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":             "rate_limited",
			"error_description": "too many verification requests, please try again later",
			"retry_after":       result.RetryAfterSecs,
		})
		return
	}

	// Send email with code using namespace-specific email sender
	if result.Code != nil {
		sender, senderErr := s.emailProviderStore.GetSender(c.Request.Context(), namespaceID)
		if senderErr != nil {
			// Fallback to console sender
			sender = s.emailSender
		}

		if sender != nil {
			emailData := email.EmailVerificationEmailData{
				To:           emailAddr,
				Username:     username,
				Code:         result.Code.Code,
				ExpiresInMin: int(s.emailVerificationStore.Config.CodeTTL.Minutes()),
				AppName:      "OAuth2 Service",
				SupportEmail: "",
			}
			if err := sender.SendEmailVerification(c.Request.Context(), emailData); err != nil {
				// Log error but don't expose to user
			}
		}
	}

	c.JSON(http.StatusOK, RequestEmailVerificationResponse{
		Success:       true,
		Message:       "Verification code has been resent to your email",
		ExpiresInSecs: int(s.emailVerificationStore.Config.CodeTTL.Seconds()),
	})
}

// getAccountFromRequest extracts account ID and namespace ID from bearer token
func (s *Server) getAccountFromRequest(c *gin.Context) (accountID string, namespaceID string, err error) {
	// First try to get from bearer token
	tokenInfo, err := s.ValidationBearerToken(c.Request)
	if err == nil {
		accountID = tokenInfo.GetUserID()
		// Extract namespace from scope or client configuration
		namespaceID = s.extractNamespaceFromToken(tokenInfo)
		if namespaceID != "" {
			return accountID, namespaceID, nil
		}
	}

	// Fallback to header-based namespace
	namespaceID = c.GetHeader("X-Namespace-ID")
	if namespaceID == "" {
		namespaceID = "default" // Default namespace
	}

	if accountID == "" {
		return "", "", err
	}

	return accountID, namespaceID, nil
}

// extractNamespaceFromToken extracts namespace from token info
func (s *Server) extractNamespaceFromToken(tokenInfo interface{}) string {
	// Default implementation - override if needed
	return ""
}

// GetEmailVerificationStatusResponse is the response for email verification status
type GetEmailVerificationStatusResponse struct {
	Email       string `json:"email"`
	Verified    bool   `json:"verified"`
	VerifiedAt  string `json:"verified_at,omitempty"`
	PendingCode bool   `json:"pending_code,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// HandleGetEmailVerificationStatusGin handles GET /iam/v1/users/email-verification-status
// Returns the email verification status for the current user
func (s *Server) HandleGetEmailVerificationStatusGin(c *gin.Context) {
	if s.emailVerificationStore == nil {
		NotImplementedGin(c, "email verification not configured")
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(c.Query("email")))
	if emailAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "email is required",
		})
		return
	}

	// Get namespace from request
	_, namespaceID, err := s.getAccountFromRequest(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	code, err := s.emailVerificationStore.GetVerificationStatus(c.Request.Context(), emailAddr, namespaceID)
	if err != nil {
		c.JSON(http.StatusOK, GetEmailVerificationStatusResponse{
			Email:    emailAddr,
			Verified: false,
		})
		return
	}

	resp := GetEmailVerificationStatusResponse{
		Email:    emailAddr,
		Verified: code.Verified,
	}

	if code.Verified && code.VerifiedAt != nil {
		resp.VerifiedAt = code.VerifiedAt.Format(time.RFC3339)
	}

	if !code.Verified && time.Now().Before(code.ExpiresAt) {
		resp.PendingCode = true
		resp.ExpiresAt = code.ExpiresAt.Format(time.RFC3339)
	}

	c.JSON(http.StatusOK, resp)
}
