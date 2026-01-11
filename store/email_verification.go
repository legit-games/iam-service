package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// EmailVerificationConfig holds configuration for email verification
type EmailVerificationConfig struct {
	CodeTTL           time.Duration // How long the code is valid (default: 24 hours)
	MaxFailedAttempts int           // Max wrong code attempts before lockout (default: 5)
	LockoutDuration   time.Duration // How long to lock after max failures (default: 30 min)
	RateLimitWindow   time.Duration // Time window for rate limiting (default: 5 min)
	RateLimitMaxReqs  int           // Max requests per window (default: 3)
}

// DefaultEmailVerificationConfig returns default configuration
func DefaultEmailVerificationConfig() EmailVerificationConfig {
	return EmailVerificationConfig{
		CodeTTL:           24 * time.Hour,
		MaxFailedAttempts: 5,
		LockoutDuration:   30 * time.Minute,
		RateLimitWindow:   5 * time.Minute,
		RateLimitMaxReqs:  3,
	}
}

// EmailVerificationCode represents a verification code in the database
type EmailVerificationCode struct {
	ID             string     `gorm:"column:id;primaryKey"`
	Code           string     `gorm:"column:code"`
	AccountID      string     `gorm:"column:account_id"`
	Email          string     `gorm:"column:email"`
	NamespaceID    string     `gorm:"column:namespace_id"`
	ExpiresAt      time.Time  `gorm:"column:expires_at"`
	Verified       bool       `gorm:"column:verified"`
	VerifiedAt     *time.Time `gorm:"column:verified_at"`
	FailedAttempts int        `gorm:"column:failed_attempts"`
	LockedUntil    *time.Time `gorm:"column:locked_until"`
	CreatedAt      time.Time  `gorm:"column:created_at"`
}

func (EmailVerificationCode) TableName() string {
	return "email_verification_codes"
}

// EmailVerificationRateLimit tracks rate limiting for verification requests
type EmailVerificationRateLimit struct {
	Email         string    `gorm:"column:email;primaryKey"`
	RequestCount  int       `gorm:"column:request_count"`
	WindowStart   time.Time `gorm:"column:window_start"`
	LastRequestAt time.Time `gorm:"column:last_request_at"`
}

func (EmailVerificationRateLimit) TableName() string {
	return "email_verification_rate_limits"
}

// EmailVerificationStore manages email verification codes
type EmailVerificationStore struct {
	DB     *gorm.DB
	Config EmailVerificationConfig
}

// NewEmailVerificationStore creates a new store with default config
func NewEmailVerificationStore(db *gorm.DB) *EmailVerificationStore {
	return &EmailVerificationStore{
		DB:     db,
		Config: DefaultEmailVerificationConfig(),
	}
}

// NewEmailVerificationStoreWithConfig creates a store with custom configuration
func NewEmailVerificationStoreWithConfig(db *gorm.DB, cfg EmailVerificationConfig) *EmailVerificationStore {
	return &EmailVerificationStore{
		DB:     db,
		Config: cfg,
	}
}

// generateVerificationCode creates a cryptographically secure 6-digit numeric code
func generateVerificationCode() (string, error) {
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

// CreateVerificationCodeResult contains the result of code creation
type CreateVerificationCodeResult struct {
	Code            *EmailVerificationCode
	RateLimited     bool
	RetryAfterSecs  int
	ExistingCodeExp *time.Time // If a valid code already exists
	AlreadyVerified bool       // If email is already verified
}

// CreateVerificationCode generates a new verification code for an account
func (s *EmailVerificationStore) CreateVerificationCode(ctx context.Context, accountID, email, namespaceID string) (*CreateVerificationCodeResult, error) {
	now := time.Now().UTC()
	result := &CreateVerificationCodeResult{}

	// Check if email is already verified for this account
	var existingVerified EmailVerificationCode
	err := s.DB.WithContext(ctx).Where(
		"account_id = ? AND email = ? AND namespace_id = ? AND verified = TRUE",
		accountID, email, namespaceID,
	).First(&existingVerified).Error
	if err == nil {
		result.AlreadyVerified = true
		return result, nil
	}

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
	var existing EmailVerificationCode
	err = s.DB.WithContext(ctx).Where(
		"email = ? AND namespace_id = ? AND verified = FALSE AND expires_at > ?",
		email, namespaceID, now,
	).First(&existing).Error
	if err == nil {
		// Valid code already exists - return its expiration
		result.ExistingCodeExp = &existing.ExpiresAt
		_ = s.incrementRateLimit(ctx, email, now)
		return result, nil
	}

	// Generate new code
	code, err := generateVerificationCode()
	if err != nil {
		return nil, err
	}

	verificationCode := &EmailVerificationCode{
		ID:             uuid.New().String(),
		Code:           code,
		AccountID:      accountID,
		Email:          email,
		NamespaceID:    namespaceID,
		ExpiresAt:      now.Add(s.Config.CodeTTL),
		Verified:       false,
		FailedAttempts: 0,
		CreatedAt:      now,
	}

	if err := s.DB.WithContext(ctx).Create(verificationCode).Error; err != nil {
		return nil, fmt.Errorf("failed to create verification code: %w", err)
	}

	if err := s.incrementRateLimit(ctx, email, now); err != nil {
		// Log but don't fail
	}

	result.Code = verificationCode
	return result, nil
}

// checkRateLimit verifies if the email is within rate limits
func (s *EmailVerificationStore) checkRateLimit(ctx context.Context, email string, now time.Time) (bool, int, error) {
	var rateLimit EmailVerificationRateLimit
	err := s.DB.WithContext(ctx).Where("email = ?", email).First(&rateLimit).Error

	if err != nil {
		// No rate limit record - not limited
		return false, 0, nil
	}

	// Check if window has expired
	windowEnd := rateLimit.WindowStart.Add(s.Config.RateLimitWindow)
	if now.After(windowEnd) {
		// Window expired - reset
		return false, 0, nil
	}

	// Check if over limit
	if rateLimit.RequestCount >= s.Config.RateLimitMaxReqs {
		retryAfter := int(windowEnd.Sub(now).Seconds())
		if retryAfter < 0 {
			retryAfter = 0
		}
		return true, retryAfter, nil
	}

	return false, 0, nil
}

// incrementRateLimit updates the rate limit counter
func (s *EmailVerificationStore) incrementRateLimit(ctx context.Context, email string, now time.Time) error {
	var rateLimit EmailVerificationRateLimit
	err := s.DB.WithContext(ctx).Where("email = ?", email).First(&rateLimit).Error

	if err != nil {
		// Create new rate limit record
		rateLimit = EmailVerificationRateLimit{
			Email:         email,
			RequestCount:  1,
			WindowStart:   now,
			LastRequestAt: now,
		}
		return s.DB.WithContext(ctx).Create(&rateLimit).Error
	}

	// Check if window has expired
	windowEnd := rateLimit.WindowStart.Add(s.Config.RateLimitWindow)
	if now.After(windowEnd) {
		// Reset window
		rateLimit.RequestCount = 1
		rateLimit.WindowStart = now
	} else {
		rateLimit.RequestCount++
	}
	rateLimit.LastRequestAt = now

	return s.DB.WithContext(ctx).Save(&rateLimit).Error
}

// VerifyCodeResult contains the result of code verification
type VerifyCodeResult struct {
	Valid             bool
	Verified          bool       // Successfully verified
	Code              *EmailVerificationCode
	NotFound          bool
	Expired           bool
	AlreadyVerified   bool
	Locked            bool
	LockedUntil       *time.Time
	RemainingAttempts int
}

// VerifyCode validates a verification code and marks email as verified if valid
func (s *EmailVerificationStore) VerifyCode(ctx context.Context, email, code, namespaceID string) (*VerifyCodeResult, error) {
	now := time.Now().UTC()
	result := &VerifyCodeResult{}

	// Find the code
	var verificationCode EmailVerificationCode
	err := s.DB.WithContext(ctx).Where(
		"email = ? AND namespace_id = ?",
		email, namespaceID,
	).Order("created_at DESC").First(&verificationCode).Error

	if err != nil {
		result.NotFound = true
		return result, nil
	}

	// Check if already verified
	if verificationCode.Verified {
		result.AlreadyVerified = true
		return result, nil
	}

	// Check if locked
	if verificationCode.LockedUntil != nil && now.Before(*verificationCode.LockedUntil) {
		result.Locked = true
		result.LockedUntil = verificationCode.LockedUntil
		return result, nil
	}

	// Check if expired
	if now.After(verificationCode.ExpiresAt) {
		result.Expired = true
		return result, nil
	}

	// Validate the code
	if verificationCode.Code != code {
		// Wrong code - increment failed attempts
		verificationCode.FailedAttempts++

		if verificationCode.FailedAttempts >= s.Config.MaxFailedAttempts {
			lockUntil := now.Add(s.Config.LockoutDuration)
			verificationCode.LockedUntil = &lockUntil
			result.Locked = true
			result.LockedUntil = &lockUntil
		}

		result.RemainingAttempts = s.Config.MaxFailedAttempts - verificationCode.FailedAttempts
		if result.RemainingAttempts < 0 {
			result.RemainingAttempts = 0
		}

		s.DB.WithContext(ctx).Save(&verificationCode)
		return result, nil
	}

	// Code is valid - mark as verified in transaction
	verificationCode.Verified = true
	verifiedAt := now
	verificationCode.VerifiedAt = &verifiedAt

	err = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Mark verification code as verified
		if err := tx.Save(&verificationCode).Error; err != nil {
			return fmt.Errorf("failed to mark code as verified: %w", err)
		}

		// Also mark the account's email as verified
		if err := tx.Exec(
			`UPDATE accounts SET email_verified = TRUE, email_verified_at = ? WHERE id = ?`,
			verifiedAt, verificationCode.AccountID,
		).Error; err != nil {
			return fmt.Errorf("failed to mark account email as verified: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	result.Valid = true
	result.Verified = true
	result.Code = &verificationCode
	return result, nil
}

// ValidateCodeOnly checks if a code is valid without consuming it or incrementing failed attempts
func (s *EmailVerificationStore) ValidateCodeOnly(ctx context.Context, email, code, namespaceID string) (*VerifyCodeResult, error) {
	now := time.Now().UTC()
	result := &VerifyCodeResult{}

	var verificationCode EmailVerificationCode
	err := s.DB.WithContext(ctx).Where(
		"email = ? AND namespace_id = ?",
		email, namespaceID,
	).Order("created_at DESC").First(&verificationCode).Error

	if err != nil {
		result.NotFound = true
		return result, nil
	}

	if verificationCode.Verified {
		result.AlreadyVerified = true
		return result, nil
	}

	if verificationCode.LockedUntil != nil && now.Before(*verificationCode.LockedUntil) {
		result.Locked = true
		result.LockedUntil = verificationCode.LockedUntil
		return result, nil
	}

	if now.After(verificationCode.ExpiresAt) {
		result.Expired = true
		return result, nil
	}

	if verificationCode.Code == code {
		result.Valid = true
		result.Code = &verificationCode
	}

	result.RemainingAttempts = s.Config.MaxFailedAttempts - verificationCode.FailedAttempts
	return result, nil
}

// ResendVerificationCode invalidates existing codes and creates a new one
func (s *EmailVerificationStore) ResendVerificationCode(ctx context.Context, accountID, email, namespaceID string) (*CreateVerificationCodeResult, error) {
	// Invalidate existing codes first
	s.DB.WithContext(ctx).Model(&EmailVerificationCode{}).
		Where("email = ? AND namespace_id = ? AND verified = FALSE", email, namespaceID).
		Update("expires_at", time.Now().UTC().Add(-1*time.Hour))

	// Create new code
	return s.CreateVerificationCode(ctx, accountID, email, namespaceID)
}

// IsEmailVerified checks if an email is verified for an account
func (s *EmailVerificationStore) IsEmailVerified(ctx context.Context, accountID, email, namespaceID string) (bool, error) {
	var code EmailVerificationCode
	err := s.DB.WithContext(ctx).Where(
		"account_id = ? AND email = ? AND namespace_id = ? AND verified = TRUE",
		accountID, email, namespaceID,
	).First(&code).Error

	if err != nil {
		return false, nil
	}
	return true, nil
}

// GetVerificationStatus returns the verification status for an email
func (s *EmailVerificationStore) GetVerificationStatus(ctx context.Context, email, namespaceID string) (*EmailVerificationCode, error) {
	var code EmailVerificationCode
	err := s.DB.WithContext(ctx).Where(
		"email = ? AND namespace_id = ?",
		email, namespaceID,
	).Order("created_at DESC").First(&code).Error

	if err != nil {
		return nil, err
	}
	return &code, nil
}

// DeleteExpiredCodes removes expired verification codes
func (s *EmailVerificationStore) DeleteExpiredCodes(ctx context.Context) (int64, error) {
	result := s.DB.WithContext(ctx).
		Where("expires_at < ? AND verified = FALSE", time.Now().UTC()).
		Delete(&EmailVerificationCode{})
	return result.RowsAffected, result.Error
}
