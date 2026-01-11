package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"gorm.io/gorm"
)

// PasswordResetConfig holds configuration for password reset operations
type PasswordResetConfig struct {
	CodeTTL           time.Duration // How long a reset code is valid (default: 1 hour)
	MaxFailedAttempts int           // Max wrong code entries before lockout (default: 5)
	LockoutDuration   time.Duration // How long to lock after max failures (default: 30 min)
	RateLimitWindow   time.Duration // Time window for rate limiting (default: 5 min)
	RateLimitMaxReqs  int           // Max requests per window (default: 3)
}

// DefaultPasswordResetConfig returns sensible defaults
func DefaultPasswordResetConfig() PasswordResetConfig {
	return PasswordResetConfig{
		CodeTTL:           1 * time.Hour,
		MaxFailedAttempts: 5,
		LockoutDuration:   30 * time.Minute,
		RateLimitWindow:   5 * time.Minute,
		RateLimitMaxReqs:  3,
	}
}

// PasswordResetCode represents a password reset verification code
type PasswordResetCode struct {
	ID             string     `gorm:"primaryKey" json:"id"`
	Code           string     `json:"code"`
	AccountID      string     `json:"account_id"`
	Email          string     `json:"email"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Used           bool       `json:"used"`
	UsedAt         *time.Time `json:"used_at,omitempty"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (PasswordResetCode) TableName() string {
	return "password_reset_codes"
}

// PasswordResetRateLimit tracks rate limiting per email
type PasswordResetRateLimit struct {
	Email         string    `gorm:"primaryKey"`
	RequestCount  int       `json:"request_count"`
	WindowStart   time.Time `json:"window_start"`
	LastRequestAt time.Time `json:"last_request_at"`
}

func (PasswordResetRateLimit) TableName() string {
	return "password_reset_rate_limits"
}

// PasswordResetStore provides operations for password reset codes
type PasswordResetStore struct {
	DB     *gorm.DB
	Config PasswordResetConfig
}

// NewPasswordResetStore creates a new PasswordResetStore with default configuration
func NewPasswordResetStore(db *gorm.DB) *PasswordResetStore {
	return &PasswordResetStore{
		DB:     db,
		Config: DefaultPasswordResetConfig(),
	}
}

// NewPasswordResetStoreWithConfig creates a store with custom configuration
func NewPasswordResetStoreWithConfig(db *gorm.DB, cfg PasswordResetConfig) *PasswordResetStore {
	return &PasswordResetStore{
		DB:     db,
		Config: cfg,
	}
}

// generateNumericCode creates a cryptographically secure 6-digit numeric code
func generateNumericCode() (string, error) {
	var code string
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %w", err)
		}
		code += fmt.Sprintf("%d", n.Int64())
	}
	return code, nil
}

// CreateResetCodeResult contains the result of code creation
type CreateResetCodeResult struct {
	Code            *PasswordResetCode
	RateLimited     bool
	RetryAfterSecs  int
	ExistingCodeExp *time.Time // If a valid code already exists
}

// CreateResetCode generates a new password reset code for an account
// Returns rate limit info if exceeded, or existing code expiration if one exists
func (s *PasswordResetStore) CreateResetCode(ctx context.Context, accountID, email string) (*CreateResetCodeResult, error) {
	now := time.Now().UTC()
	result := &CreateResetCodeResult{}

	// Check rate limit
	rateLimited, retryAfter, err := s.checkRateLimit(ctx, email, now)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if rateLimited {
		result.RateLimited = true
		result.RetryAfterSecs = retryAfter
		return result, nil
	}

	// Check for existing valid code
	var existing PasswordResetCode
	err = s.DB.WithContext(ctx).Where(
		"email = ? AND used = FALSE AND expires_at > ?",
		email, now,
	).First(&existing).Error
	if err == nil {
		// Valid code already exists - return its expiration
		result.ExistingCodeExp = &existing.ExpiresAt
		// Update rate limit counter even for existing code check
		_ = s.incrementRateLimit(ctx, email, now)
		return result, nil
	}

	// Generate new code
	code, err := generateNumericCode()
	if err != nil {
		return nil, err
	}

	resetCode := &PasswordResetCode{
		ID:             generateID(),
		Code:           code,
		AccountID:      accountID,
		Email:          email,
		ExpiresAt:      now.Add(s.Config.CodeTTL),
		Used:           false,
		FailedAttempts: 0,
		CreatedAt:      now,
	}

	if err := s.DB.WithContext(ctx).Create(resetCode).Error; err != nil {
		return nil, fmt.Errorf("failed to create reset code: %w", err)
	}

	// Update rate limit counter
	if err := s.incrementRateLimit(ctx, email, now); err != nil {
		// Log but don't fail - code was created successfully
	}

	result.Code = resetCode
	return result, nil
}

// checkRateLimit verifies if the email is within rate limits
// Returns (isLimited, retryAfterSeconds, error)
func (s *PasswordResetStore) checkRateLimit(ctx context.Context, email string, now time.Time) (bool, int, error) {
	var rateLimit PasswordResetRateLimit
	err := s.DB.WithContext(ctx).Where("email = ?", email).First(&rateLimit).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// No rate limit record - not limited
			return false, 0, nil
		}
		return false, 0, err
	}

	windowEnd := rateLimit.WindowStart.Add(s.Config.RateLimitWindow)

	if now.After(windowEnd) {
		// Window expired, reset counter (will be done on next increment)
		return false, 0, nil
	}

	if rateLimit.RequestCount >= s.Config.RateLimitMaxReqs {
		retryAfter := int(windowEnd.Sub(now).Seconds())
		if retryAfter < 0 {
			retryAfter = 0
		}
		return true, retryAfter, nil
	}

	return false, 0, nil
}

// incrementRateLimit updates the rate limit counter for an email
func (s *PasswordResetStore) incrementRateLimit(ctx context.Context, email string, now time.Time) error {
	windowMinutes := int(s.Config.RateLimitWindow.Minutes())
	return s.DB.WithContext(ctx).Exec(fmt.Sprintf(`
		INSERT INTO password_reset_rate_limits (email, request_count, window_start, last_request_at)
		VALUES ($1, 1, $2, $2)
		ON CONFLICT (email) DO UPDATE SET
			request_count = CASE
				WHEN password_reset_rate_limits.window_start + INTERVAL '%d minutes' < $2
				THEN 1
				ELSE password_reset_rate_limits.request_count + 1
			END,
			window_start = CASE
				WHEN password_reset_rate_limits.window_start + INTERVAL '%d minutes' < $2
				THEN $2
				ELSE password_reset_rate_limits.window_start
			END,
			last_request_at = $2
	`, windowMinutes, windowMinutes), email, now).Error
}

// ValidateCodeResult contains the result of code validation
type ValidateCodeResult struct {
	Valid             bool
	Code              *PasswordResetCode
	Expired           bool
	NotFound          bool
	AlreadyUsed       bool
	Locked            bool
	LockedUntil       *time.Time
	RemainingAttempts int
}

// ValidateCode checks if a reset code is valid
// This method increments failed attempts if the code doesn't match
func (s *PasswordResetStore) ValidateCode(ctx context.Context, email, code string) (*ValidateCodeResult, error) {
	now := time.Now().UTC()
	result := &ValidateCodeResult{}

	var resetCode PasswordResetCode
	err := s.DB.WithContext(ctx).Where("email = ?", email).
		Order("created_at DESC").
		First(&resetCode).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			result.NotFound = true
			return result, nil
		}
		return nil, err
	}

	// Check if already used
	if resetCode.Used {
		result.AlreadyUsed = true
		return result, nil
	}

	// Check if locked
	if resetCode.LockedUntil != nil && now.Before(*resetCode.LockedUntil) {
		result.Locked = true
		result.LockedUntil = resetCode.LockedUntil
		return result, nil
	}

	// Check if expired
	if now.After(resetCode.ExpiresAt) {
		result.Expired = true
		return result, nil
	}

	// Check code match
	if resetCode.Code != code {
		// Increment failed attempts
		newFailedAttempts := resetCode.FailedAttempts + 1
		updates := map[string]interface{}{
			"failed_attempts": newFailedAttempts,
		}

		// Lock if exceeded max attempts
		if newFailedAttempts >= s.Config.MaxFailedAttempts {
			lockUntil := now.Add(s.Config.LockoutDuration)
			updates["locked_until"] = lockUntil
			result.Locked = true
			result.LockedUntil = &lockUntil
		}

		s.DB.WithContext(ctx).Model(&PasswordResetCode{}).
			Where("id = ?", resetCode.ID).
			Updates(updates)

		result.RemainingAttempts = s.Config.MaxFailedAttempts - newFailedAttempts
		if result.RemainingAttempts < 0 {
			result.RemainingAttempts = 0
		}
		return result, nil
	}

	result.Valid = true
	result.Code = &resetCode
	result.RemainingAttempts = s.Config.MaxFailedAttempts - resetCode.FailedAttempts
	return result, nil
}

// ValidateCodeOnly checks if a reset code is valid without incrementing failed attempts
// Use this for the validate endpoint that checks without consuming
func (s *PasswordResetStore) ValidateCodeOnly(ctx context.Context, email, code string) (*ValidateCodeResult, error) {
	now := time.Now().UTC()
	result := &ValidateCodeResult{}

	var resetCode PasswordResetCode
	err := s.DB.WithContext(ctx).Where("email = ?", email).
		Order("created_at DESC").
		First(&resetCode).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			result.NotFound = true
			return result, nil
		}
		return nil, err
	}

	// Check if already used
	if resetCode.Used {
		result.AlreadyUsed = true
		return result, nil
	}

	// Check if locked
	if resetCode.LockedUntil != nil && now.Before(*resetCode.LockedUntil) {
		result.Locked = true
		result.LockedUntil = resetCode.LockedUntil
		return result, nil
	}

	// Check if expired
	if now.After(resetCode.ExpiresAt) {
		result.Expired = true
		return result, nil
	}

	// Check code match (without incrementing failed attempts)
	if resetCode.Code != code {
		result.RemainingAttempts = s.Config.MaxFailedAttempts - resetCode.FailedAttempts
		if result.RemainingAttempts < 0 {
			result.RemainingAttempts = 0
		}
		return result, nil
	}

	result.Valid = true
	result.Code = &resetCode
	result.RemainingAttempts = s.Config.MaxFailedAttempts - resetCode.FailedAttempts
	return result, nil
}

// ConsumeCode marks a reset code as used (after password has been reset)
func (s *PasswordResetStore) ConsumeCode(ctx context.Context, codeID string) error {
	now := time.Now().UTC()
	result := s.DB.WithContext(ctx).Model(&PasswordResetCode{}).
		Where("id = ? AND used = FALSE", codeID).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("code not found or already used")
	}
	return nil
}

// InvalidateCodesForAccount marks all pending codes for an account as used
// Called after successful password reset to invalidate any remaining codes
func (s *PasswordResetStore) InvalidateCodesForAccount(ctx context.Context, accountID string) error {
	now := time.Now().UTC()
	return s.DB.WithContext(ctx).Model(&PasswordResetCode{}).
		Where("account_id = ? AND used = FALSE", accountID).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

// DeleteExpiredCodes removes expired codes from the database (cleanup job)
func (s *PasswordResetStore) DeleteExpiredCodes(ctx context.Context) (int64, error) {
	result := s.DB.WithContext(ctx).Where(
		"expires_at < ? OR (used = TRUE AND used_at < ?)",
		time.Now().UTC(),
		time.Now().UTC().Add(-24*time.Hour), // Keep used codes for 24 hours for audit
	).Delete(&PasswordResetCode{})

	return result.RowsAffected, result.Error
}

// GetCodeByID retrieves a code by its ID (for internal use)
func (s *PasswordResetStore) GetCodeByID(ctx context.Context, id string) (*PasswordResetCode, error) {
	var code PasswordResetCode
	err := s.DB.WithContext(ctx).Where("id = ?", id).First(&code).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &code, nil
}
