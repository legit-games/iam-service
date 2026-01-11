package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/email"
	"golang.org/x/crypto/bcrypt"
)

// ForgotPasswordRequest is the request body for forgot-password endpoint
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required"`
}

// ForgotPasswordResponse is the response for forgot-password endpoint
type ForgotPasswordResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	ExpiresInSecs int    `json:"expires_in_secs,omitempty"`
}

// HandleForgotPasswordGin handles POST /iam/v1/public/users/forgot-password
// Initiates password reset flow by generating code and sending email
func (s *Server) HandleForgotPasswordGin(c *gin.Context) {
	if s.passwordResetStore == nil {
		NotImplementedGin(c, "password reset not configured")
		return
	}

	var req ForgotPasswordRequest
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

	// Look up account by email
	db, err := s.GetIAMReadDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "database unavailable",
		})
		return
	}

	var accountID, username string
	row := db.WithContext(c.Request.Context()).Raw(
		`SELECT id, username FROM accounts WHERE email = $1 LIMIT 1`, emailAddr,
	).Row()

	if err := row.Scan(&accountID, &username); err != nil {
		// SECURITY: Don't reveal whether email exists
		// Always return success to prevent email enumeration
		c.JSON(http.StatusOK, ForgotPasswordResponse{
			Success: true,
			Message: "If an account exists with this email, a reset code has been sent.",
		})
		return
	}

	// Create reset code
	result, err := s.passwordResetStore.CreateResetCode(c.Request.Context(), accountID, emailAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create reset code",
		})
		return
	}

	// Handle rate limiting
	if result.RateLimited {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":             "rate_limited",
			"error_description": "too many reset requests, please try again later",
			"retry_after":       result.RetryAfterSecs,
		})
		return
	}

	// If existing code, just acknowledge (don't reveal this to prevent enumeration)
	if result.ExistingCodeExp != nil {
		c.JSON(http.StatusOK, ForgotPasswordResponse{
			Success: true,
			Message: "If an account exists with this email, a reset code has been sent.",
		})
		return
	}

	// Send email with code
	if s.emailSender != nil && result.Code != nil {
		emailData := email.PasswordResetEmailData{
			To:           emailAddr,
			Username:     username,
			Code:         result.Code.Code,
			ExpiresInMin: int(s.passwordResetStore.Config.CodeTTL.Minutes()),
			AppName:      "OAuth2 Service",
			SupportEmail: "",
		}
		if err := s.emailSender.SendPasswordReset(c.Request.Context(), emailData); err != nil {
			// Log error but don't expose to user
			// Consider retry queue for production
		}
	}

	c.JSON(http.StatusOK, ForgotPasswordResponse{
		Success:       true,
		Message:       "If an account exists with this email, a reset code has been sent.",
		ExpiresInSecs: int(s.passwordResetStore.Config.CodeTTL.Seconds()),
	})
}

// ValidateResetCodeResponse is the response for code validation
type ValidateResetCodeResponse struct {
	Valid             bool   `json:"valid"`
	Reason            string `json:"reason,omitempty"`
	RemainingAttempts int    `json:"remaining_attempts,omitempty"`
	LockedUntil       string `json:"locked_until,omitempty"` // RFC3339 format
}

// HandleValidateResetCodeGin handles GET /iam/v1/public/users/reset-password/validate
// Validates a reset code without consuming it
func (s *Server) HandleValidateResetCodeGin(c *gin.Context) {
	if s.passwordResetStore == nil {
		NotImplementedGin(c, "password reset not configured")
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

	// Validate code format (6 digits)
	if len(code) != 6 || !isNumeric(code) {
		c.JSON(http.StatusOK, ValidateResetCodeResponse{
			Valid:  false,
			Reason: "invalid_code_format",
		})
		return
	}

	result, err := s.passwordResetStore.ValidateCodeOnly(c.Request.Context(), emailAddr, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "validation failed",
		})
		return
	}

	resp := ValidateResetCodeResponse{
		Valid:             result.Valid,
		RemainingAttempts: result.RemainingAttempts,
	}

	if result.NotFound {
		resp.Reason = "code_not_found"
	} else if result.AlreadyUsed {
		resp.Reason = "code_already_used"
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

// ResetPasswordRequest is the request for password reset execution
type ResetPasswordRequest struct {
	Email       string `json:"email" binding:"required"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ResetPasswordResponse is the response for password reset
type ResetPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// HandleResetPasswordGin handles POST /iam/v1/public/users/reset-password
// Executes password reset after validating code
func (s *Server) HandleResetPasswordGin(c *gin.Context) {
	if s.passwordResetStore == nil {
		NotImplementedGin(c, "password reset not configured")
		return
	}

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		})
		return
	}

	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	code := strings.TrimSpace(req.Code)
	newPassword := req.NewPassword

	// Validate inputs
	if emailAddr == "" || code == "" || newPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "email, code, and new_password are required",
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

	// Validate password strength (minimum requirements)
	if len(newPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_password",
			"error_description": "password must be at least 8 characters",
		})
		return
	}

	// Validate the code (this increments failed attempts on wrong code)
	result, err := s.passwordResetStore.ValidateCode(c.Request.Context(), emailAddr, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "validation failed",
		})
		return
	}

	if !result.Valid {
		status := http.StatusBadRequest
		resp := gin.H{"error": "invalid_code"}

		if result.Locked {
			status = http.StatusTooManyRequests
			resp["error"] = "account_locked"
			resp["error_description"] = "too many failed attempts, account temporarily locked"
			if result.LockedUntil != nil {
				resp["locked_until"] = result.LockedUntil.Format(time.RFC3339)
			}
		} else if result.Expired {
			resp["error_description"] = "code has expired"
		} else if result.NotFound {
			resp["error_description"] = "no active reset code found"
		} else if result.AlreadyUsed {
			resp["error_description"] = "code has already been used"
		} else {
			resp["error_description"] = "invalid code"
			resp["remaining_attempts"] = result.RemainingAttempts
		}

		c.JSON(status, resp)
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to process password",
		})
		return
	}

	// Update password in database
	db, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "database unavailable",
		})
		return
	}

	updateResult := db.WithContext(c.Request.Context()).Exec(
		`UPDATE accounts SET password_hash = $1 WHERE id = $2`,
		string(hash), result.Code.AccountID,
	)
	if updateResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to update password",
		})
		return
	}

	// Consume the code
	if err := s.passwordResetStore.ConsumeCode(c.Request.Context(), result.Code.ID); err != nil {
		// Log but don't fail - password was already updated
	}

	// Invalidate any other pending codes for this account
	_ = s.passwordResetStore.InvalidateCodesForAccount(c.Request.Context(), result.Code.AccountID)

	c.JSON(http.StatusOK, ResetPasswordResponse{
		Success: true,
		Message: "Password has been reset successfully",
	})
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
