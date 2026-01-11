package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4/utils/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// MFAConfig holds configuration for MFA operations
type MFAConfig struct {
	TOTPIssuer        string        // Issuer name for TOTP (e.g., "MyApp")
	TOTPWindow        int           // TOTP validation window (default: 1 = +/- 30 seconds)
	BackupCodeCount   int           // Number of backup codes to generate (default: 10)
	BackupCodeLength  int           // Length of each backup code (default: 8)
	MFATokenTTL       time.Duration // MFA token expiry (default: 5 minutes)
	MaxFailedAttempts int           // Max failed attempts before lockout (default: 5)
	LockoutDuration   time.Duration // Lockout duration (default: 15 minutes)
	EncryptionKey     []byte        // AES-256 key for TOTP secret encryption (32 bytes)
}

// DefaultMFAConfig returns sensible defaults
func DefaultMFAConfig() MFAConfig {
	return MFAConfig{
		TOTPIssuer:        "OAuth2 Service",
		TOTPWindow:        1,
		BackupCodeCount:   10,
		BackupCodeLength:  8,
		MFATokenTTL:       5 * time.Minute,
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
		// EncryptionKey must be set via environment variable
	}
}

// ========== Data Models ==========

// UserMFASettings represents MFA settings for a user account
type UserMFASettings struct {
	ID                  string     `gorm:"primaryKey" json:"id"`
	AccountID           string     `gorm:"uniqueIndex" json:"account_id"`
	TOTPSecretEncrypted []byte     `gorm:"column:totp_secret_encrypted" json:"-"`
	TOTPSecretNonce     []byte     `gorm:"column:totp_secret_nonce" json:"-"`
	TOTPVerified        bool       `json:"totp_verified"`
	MFAEnabled          bool       `json:"mfa_enabled"`
	EnabledAt           *time.Time `json:"enabled_at,omitempty"`
	DisabledAt          *time.Time `json:"disabled_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func (UserMFASettings) TableName() string { return "user_mfa_settings" }

// UserMFABackupCode represents a hashed backup code
type UserMFABackupCode struct {
	ID        string     `gorm:"primaryKey" json:"id"`
	AccountID string     `json:"account_id"`
	CodeHash  string     `gorm:"column:code_hash" json:"-"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (UserMFABackupCode) TableName() string { return "user_mfa_backup_codes" }

// NamespaceMFASettings represents namespace-level MFA requirements
type NamespaceMFASettings struct {
	ID              string    `gorm:"primaryKey" json:"id"`
	Namespace       string    `gorm:"uniqueIndex" json:"namespace"`
	MFARequired     bool      `json:"mfa_required"`
	GracePeriodDays int       `json:"grace_period_days"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (NamespaceMFASettings) TableName() string { return "namespace_mfa_settings" }

// UserMFAAttempt represents an MFA attempt record for rate limiting
type UserMFAAttempt struct {
	ID          string     `gorm:"primaryKey" json:"id"`
	AccountID   string     `json:"account_id"`
	AttemptType string     `json:"attempt_type"` // 'totp', 'backup', 'setup'
	Success     bool       `json:"success"`
	IPAddress   string     `json:"ip_address,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	FailedCount int        `json:"failed_count"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (UserMFAAttempt) TableName() string { return "user_mfa_attempts" }

// MFAToken represents a short-lived token for MFA verification
type MFAToken struct {
	ID        string     `gorm:"primaryKey" json:"id"`
	TokenHash string     `gorm:"column:token_hash" json:"-"`
	AccountID string     `json:"account_id"`
	Namespace string     `json:"namespace"`
	ClientID  string     `json:"client_id,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (MFAToken) TableName() string { return "mfa_tokens" }

// ========== MFA Store ==========

// MFAStore provides operations for MFA management
type MFAStore struct {
	DB     *gorm.DB
	Config MFAConfig
}

// NewMFAStore creates a new MFAStore with default configuration
func NewMFAStore(db *gorm.DB) *MFAStore {
	return &MFAStore{
		DB:     db,
		Config: DefaultMFAConfig(),
	}
}

// NewMFAStoreWithConfig creates a store with custom configuration
func NewMFAStoreWithConfig(db *gorm.DB, cfg MFAConfig) *MFAStore {
	return &MFAStore{
		DB:     db,
		Config: cfg,
	}
}

// ========== Encryption Helpers ==========

// encryptTOTPSecret encrypts the TOTP secret using AES-256-GCM
func (s *MFAStore) encryptTOTPSecret(secret string) ([]byte, []byte, error) {
	if len(s.Config.EncryptionKey) != 32 {
		return nil, nil, fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(s.Config.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	return ciphertext, nonce, nil
}

// decryptTOTPSecret decrypts the TOTP secret using AES-256-GCM
func (s *MFAStore) decryptTOTPSecret(ciphertext, nonce []byte) (string, error) {
	if len(s.Config.EncryptionKey) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(s.Config.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// hashToken creates a SHA256 hash of a token
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ========== TOTP Secret Management ==========

// MFASetupResult contains the result of MFA setup initiation
type MFASetupResult struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	Issuer    string `json:"issuer"`
}

// InitiateTOTPSetup generates a new TOTP secret for an account
// Returns the secret and QR code URL for display to the user
func (s *MFAStore) InitiateTOTPSetup(ctx context.Context, accountID, accountName string) (*MFASetupResult, error) {
	now := time.Now().UTC()

	// Check if MFA is already enabled
	var existing UserMFASettings
	queryErr := s.DB.WithContext(ctx).Where("account_id = ?", accountID).First(&existing).Error
	if queryErr == nil && existing.MFAEnabled {
		return nil, fmt.Errorf("MFA is already enabled for this account")
	}
	isNewRecord := queryErr == gorm.ErrRecordNotFound

	// Generate TOTP secret
	cfg := totp.Config{
		Issuer:    s.Config.TOTPIssuer,
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Window:    s.Config.TOTPWindow,
	}
	secret, err := totp.GenerateSecret(accountName, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Encrypt the secret
	encrypted, nonce, err := s.encryptTOTPSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Store or update MFA settings
	if isNewRecord {
		// Create new settings
		settings := UserMFASettings{
			ID:                  generateID(),
			AccountID:           accountID,
			TOTPSecretEncrypted: encrypted,
			TOTPSecretNonce:     nonce,
			TOTPVerified:        false,
			MFAEnabled:          false,
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.DB.WithContext(ctx).Create(&settings).Error; err != nil {
			return nil, fmt.Errorf("failed to create MFA settings: %w", err)
		}
	} else {
		// Update existing settings (re-setup)
		if err := s.DB.WithContext(ctx).Model(&UserMFASettings{}).
			Where("account_id = ?", accountID).
			Updates(map[string]interface{}{
				"totp_secret_encrypted": encrypted,
				"totp_secret_nonce":     nonce,
				"totp_verified":         false,
				"updated_at":            now,
			}).Error; err != nil {
			return nil, fmt.Errorf("failed to update MFA settings: %w", err)
		}
	}

	// Generate QR code URL
	qrURL := totp.GenerateQRCodeURL(secret, accountName, cfg)

	return &MFASetupResult{
		Secret:    secret,
		QRCodeURL: qrURL,
		Issuer:    s.Config.TOTPIssuer,
	}, nil
}

// GetTOTPSecret retrieves and decrypts the TOTP secret for an account
func (s *MFAStore) GetTOTPSecret(ctx context.Context, accountID string) (string, error) {
	var settings UserMFASettings
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).First(&settings).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", fmt.Errorf("MFA not configured for this account")
		}
		return "", err
	}

	if settings.TOTPSecretEncrypted == nil || settings.TOTPSecretNonce == nil {
		return "", fmt.Errorf("TOTP secret not set")
	}

	return s.decryptTOTPSecret(settings.TOTPSecretEncrypted, settings.TOTPSecretNonce)
}

// MFAVerifyResult contains the result of MFA setup verification
type MFAVerifyResult struct {
	Success     bool     `json:"success"`
	BackupCodes []string `json:"backup_codes,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// VerifyAndEnableTOTP verifies a TOTP code and enables MFA if valid
// Returns backup codes on success (display once, then never shown again)
func (s *MFAStore) VerifyAndEnableTOTP(ctx context.Context, accountID, code string) (*MFAVerifyResult, error) {
	now := time.Now().UTC()

	// Get TOTP secret
	secret, err := s.GetTOTPSecret(ctx, accountID)
	if err != nil {
		return nil, err
	}

	// Validate TOTP code
	cfg := totp.Config{
		Issuer:    s.Config.TOTPIssuer,
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Window:    s.Config.TOTPWindow,
	}
	if !totp.ValidateCode(secret, code, cfg) {
		return &MFAVerifyResult{
			Success: false,
			Message: "Invalid TOTP code",
		}, nil
	}

	// Enable MFA
	if err := s.DB.WithContext(ctx).Model(&UserMFASettings{}).
		Where("account_id = ?", accountID).
		Updates(map[string]interface{}{
			"totp_verified": true,
			"mfa_enabled":   true,
			"enabled_at":    now,
			"updated_at":    now,
		}).Error; err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Generate backup codes
	backupCodes, err := s.GenerateBackupCodes(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	return &MFAVerifyResult{
		Success:     true,
		BackupCodes: backupCodes,
		Message:     "MFA enabled successfully",
	}, nil
}

// ValidateTOTPCode validates a TOTP code for an account (for login verification)
func (s *MFAStore) ValidateTOTPCode(ctx context.Context, accountID, code string) (bool, error) {
	secret, err := s.GetTOTPSecret(ctx, accountID)
	if err != nil {
		return false, err
	}

	cfg := totp.Config{
		Issuer:    s.Config.TOTPIssuer,
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Window:    s.Config.TOTPWindow,
	}
	return totp.ValidateCode(secret, code, cfg), nil
}

// ========== Backup Codes ==========

// GenerateBackupCodes creates new backup codes for an account
// Deletes existing codes and returns the plaintext codes (display once)
func (s *MFAStore) GenerateBackupCodes(ctx context.Context, accountID string) ([]string, error) {
	now := time.Now().UTC()

	// Delete existing backup codes
	if err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).
		Delete(&UserMFABackupCode{}).Error; err != nil {
		return nil, fmt.Errorf("failed to delete existing backup codes: %w", err)
	}

	// Generate new backup codes
	codes, err := totp.GenerateBackupCodes(s.Config.BackupCodeCount, s.Config.BackupCodeLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store hashed backup codes
	for _, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}

		backupCode := UserMFABackupCode{
			ID:        generateID(),
			AccountID: accountID,
			CodeHash:  string(hash),
			Used:      false,
			CreatedAt: now,
		}
		if err := s.DB.WithContext(ctx).Create(&backupCode).Error; err != nil {
			return nil, fmt.Errorf("failed to store backup code: %w", err)
		}
	}

	// Format codes for display
	formattedCodes := make([]string, len(codes))
	for i, code := range codes {
		formattedCodes[i] = totp.FormatBackupCode(code)
	}

	return formattedCodes, nil
}

// ValidateBackupCode validates a backup code and marks it as used
func (s *MFAStore) ValidateBackupCode(ctx context.Context, accountID, code string) (bool, error) {
	now := time.Now().UTC()

	// Normalize the code (remove dashes, uppercase)
	normalizedCode := totp.NormalizeBackupCode(code)

	// Get all unused backup codes for the account
	var backupCodes []UserMFABackupCode
	if err := s.DB.WithContext(ctx).Where("account_id = ? AND used = FALSE", accountID).
		Find(&backupCodes).Error; err != nil {
		return false, err
	}

	// Check each code against the provided code
	for _, bc := range backupCodes {
		if bcrypt.CompareHashAndPassword([]byte(bc.CodeHash), []byte(normalizedCode)) == nil {
			// Match found - mark as used
			if err := s.DB.WithContext(ctx).Model(&UserMFABackupCode{}).
				Where("id = ?", bc.ID).
				Updates(map[string]interface{}{
					"used":    true,
					"used_at": now,
				}).Error; err != nil {
				return false, fmt.Errorf("failed to mark backup code as used: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// GetBackupCodeCount returns the number of unused backup codes
func (s *MFAStore) GetBackupCodeCount(ctx context.Context, accountID string) (int, error) {
	var count int64
	if err := s.DB.WithContext(ctx).Model(&UserMFABackupCode{}).
		Where("account_id = ? AND used = FALSE", accountID).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return int(count), nil
}

// ========== MFA Token Management ==========

// CreateMFAToken creates a short-lived MFA token for two-phase login
// Returns the plaintext token (only shown once)
func (s *MFAStore) CreateMFAToken(ctx context.Context, accountID, namespace, clientID string) (string, error) {
	now := time.Now().UTC()

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash for storage
	tokenHash := hashToken(token)

	mfaToken := MFAToken{
		ID:        generateID(),
		TokenHash: tokenHash,
		AccountID: accountID,
		Namespace: namespace,
		ClientID:  clientID,
		ExpiresAt: now.Add(s.Config.MFATokenTTL),
		Used:      false,
		CreatedAt: now,
	}

	if err := s.DB.WithContext(ctx).Create(&mfaToken).Error; err != nil {
		return "", fmt.Errorf("failed to create MFA token: %w", err)
	}

	return token, nil
}

// MFATokenValidationResult contains the result of MFA token validation
type MFATokenValidationResult struct {
	Valid     bool
	AccountID string
	Namespace string
	ClientID  string
	Expired   bool
	NotFound  bool
	AlreadyUsed bool
}

// ValidateMFAToken validates an MFA token and marks it as used
func (s *MFAStore) ValidateMFAToken(ctx context.Context, token string) (*MFATokenValidationResult, error) {
	now := time.Now().UTC()
	result := &MFATokenValidationResult{}

	tokenHash := hashToken(token)

	var mfaToken MFAToken
	err := s.DB.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&mfaToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			result.NotFound = true
			return result, nil
		}
		return nil, err
	}

	// Check if already used
	if mfaToken.Used {
		result.AlreadyUsed = true
		return result, nil
	}

	// Check if expired
	if now.After(mfaToken.ExpiresAt) {
		result.Expired = true
		return result, nil
	}

	// Mark as used
	if err := s.DB.WithContext(ctx).Model(&MFAToken{}).
		Where("id = ?", mfaToken.ID).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error; err != nil {
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	result.Valid = true
	result.AccountID = mfaToken.AccountID
	result.Namespace = mfaToken.Namespace
	result.ClientID = mfaToken.ClientID
	return result, nil
}

// ========== Rate Limiting ==========

// RateLimitResult contains the result of rate limit check
type RateLimitResult struct {
	Allowed       bool
	LockedUntil   *time.Time
	FailedCount   int
	RetryAfterSec int
}

// CheckRateLimit checks if an account is rate limited for MFA attempts
func (s *MFAStore) CheckRateLimit(ctx context.Context, accountID, attemptType string) (*RateLimitResult, error) {
	now := time.Now().UTC()
	result := &RateLimitResult{Allowed: true}

	var attempt UserMFAAttempt
	err := s.DB.WithContext(ctx).Where("account_id = ? AND attempt_type = ?", accountID, attemptType).
		Order("created_at DESC").
		First(&attempt).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return result, nil
		}
		return nil, err
	}

	// Check if locked
	if attempt.LockedUntil != nil && now.Before(*attempt.LockedUntil) {
		result.Allowed = false
		result.LockedUntil = attempt.LockedUntil
		result.FailedCount = attempt.FailedCount
		result.RetryAfterSec = int(attempt.LockedUntil.Sub(now).Seconds())
		return result, nil
	}

	result.FailedCount = attempt.FailedCount
	return result, nil
}

// RecordAttempt records an MFA attempt and updates rate limiting
func (s *MFAStore) RecordAttempt(ctx context.Context, accountID, attemptType string, success bool, ip, userAgent string) error {
	now := time.Now().UTC()

	// Get or create attempt record
	var attempt UserMFAAttempt
	err := s.DB.WithContext(ctx).Where("account_id = ? AND attempt_type = ?", accountID, attemptType).
		First(&attempt).Error

	if err == gorm.ErrRecordNotFound {
		// Create new attempt record
		attempt = UserMFAAttempt{
			ID:          generateID(),
			AccountID:   accountID,
			AttemptType: attemptType,
			Success:     success,
			IPAddress:   ip,
			UserAgent:   userAgent,
			FailedCount: 0,
			CreatedAt:   now,
		}
		if !success {
			attempt.FailedCount = 1
		}
		return s.DB.WithContext(ctx).Create(&attempt).Error
	} else if err != nil {
		return err
	}

	// Update existing record
	updates := map[string]interface{}{
		"success":    success,
		"ip_address": ip,
		"user_agent": userAgent,
	}

	if success {
		// Reset on success
		updates["failed_count"] = 0
		updates["locked_until"] = nil
	} else {
		// Check if lock has expired
		if attempt.LockedUntil != nil && now.After(*attempt.LockedUntil) {
			// Lock expired, reset counter
			updates["failed_count"] = 1
			updates["locked_until"] = nil
		} else {
			// Increment failed count
			newFailedCount := attempt.FailedCount + 1
			updates["failed_count"] = newFailedCount

			// Lock if exceeded max attempts
			if newFailedCount >= s.Config.MaxFailedAttempts {
				lockUntil := now.Add(s.Config.LockoutDuration)
				updates["locked_until"] = lockUntil
			}
		}
	}

	return s.DB.WithContext(ctx).Model(&UserMFAAttempt{}).
		Where("id = ?", attempt.ID).
		Updates(updates).Error
}

// ========== Namespace Settings ==========

// GetNamespaceMFASettings retrieves MFA settings for a namespace
func (s *MFAStore) GetNamespaceMFASettings(ctx context.Context, namespace string) (*NamespaceMFASettings, error) {
	var settings NamespaceMFASettings
	err := s.DB.WithContext(ctx).Where("namespace = ?", namespace).First(&settings).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &settings, nil
}

// SetNamespaceMFASettings updates MFA settings for a namespace
func (s *MFAStore) SetNamespaceMFASettings(ctx context.Context, namespace string, mfaRequired bool, gracePeriodDays int) error {
	now := time.Now().UTC()

	var settings NamespaceMFASettings
	err := s.DB.WithContext(ctx).Where("namespace = ?", namespace).First(&settings).Error

	if err == gorm.ErrRecordNotFound {
		// Create new settings
		settings = NamespaceMFASettings{
			ID:              generateID(),
			Namespace:       namespace,
			MFARequired:     mfaRequired,
			GracePeriodDays: gracePeriodDays,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		return s.DB.WithContext(ctx).Create(&settings).Error
	} else if err != nil {
		return err
	}

	// Update existing settings
	return s.DB.WithContext(ctx).Model(&NamespaceMFASettings{}).
		Where("namespace = ?", namespace).
		Updates(map[string]interface{}{
			"mfa_required":      mfaRequired,
			"grace_period_days": gracePeriodDays,
			"updated_at":        now,
		}).Error
}

// IsMFARequiredForNamespace checks if MFA is required for a namespace
func (s *MFAStore) IsMFARequiredForNamespace(ctx context.Context, namespace string) bool {
	settings, err := s.GetNamespaceMFASettings(ctx, namespace)
	if err != nil || settings == nil {
		return false
	}
	return settings.MFARequired
}

// ========== User MFA Status ==========

// MFAStatus represents the MFA status for an account
type MFAStatus struct {
	Enabled          bool       `json:"mfa_enabled"`
	TOTPVerified     bool       `json:"totp_configured"`
	BackupCodesCount int        `json:"backup_codes_remaining"`
	EnabledAt        *time.Time `json:"enabled_at,omitempty"`
}

// GetMFAStatus returns the MFA status for an account
func (s *MFAStore) GetMFAStatus(ctx context.Context, accountID string) (*MFAStatus, error) {
	status := &MFAStatus{}

	var settings UserMFASettings
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).First(&settings).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return status, nil
		}
		return nil, err
	}

	status.Enabled = settings.MFAEnabled
	status.TOTPVerified = settings.TOTPVerified
	status.EnabledAt = settings.EnabledAt

	// Get backup codes count
	count, err := s.GetBackupCodeCount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	status.BackupCodesCount = count

	return status, nil
}

// IsMFAEnabled checks if MFA is enabled for an account
func (s *MFAStore) IsMFAEnabled(ctx context.Context, accountID string) (bool, error) {
	var settings UserMFASettings
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).First(&settings).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	return settings.MFAEnabled, nil
}

// DisableMFA disables MFA for an account
func (s *MFAStore) DisableMFA(ctx context.Context, accountID string) error {
	now := time.Now().UTC()

	// Update MFA settings
	if err := s.DB.WithContext(ctx).Model(&UserMFASettings{}).
		Where("account_id = ?", accountID).
		Updates(map[string]interface{}{
			"mfa_enabled":           false,
			"totp_verified":         false,
			"totp_secret_encrypted": nil,
			"totp_secret_nonce":     nil,
			"disabled_at":           now,
			"updated_at":            now,
		}).Error; err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Delete backup codes
	if err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).
		Delete(&UserMFABackupCode{}).Error; err != nil {
		return fmt.Errorf("failed to delete backup codes: %w", err)
	}

	return nil
}

// ========== Cleanup ==========

// DeleteExpiredMFATokens removes expired MFA tokens from the database
func (s *MFAStore) DeleteExpiredMFATokens(ctx context.Context) (int64, error) {
	result := s.DB.WithContext(ctx).Where(
		"expires_at < ? OR (used = TRUE AND used_at < ?)",
		time.Now().UTC(),
		time.Now().UTC().Add(-24*time.Hour), // Keep used tokens for 24 hours for audit
	).Delete(&MFAToken{})

	return result.RowsAffected, result.Error
}
