package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// LinkCode represents a one-time linking code for account linking.
type LinkCode struct {
	ID                string    `gorm:"primaryKey" json:"id"`
	Code              string    `gorm:"uniqueIndex" json:"code"`
	HeadlessAccountID string    `json:"headless_account_id"`
	Namespace         string    `json:"namespace"`
	ProviderType      string    `json:"provider_type"`
	ProviderAccountID string    `json:"provider_account_id"`
	ExpiresAt         time.Time `json:"expires_at"`
	Used              bool      `json:"used"`
	UsedBy            *string   `json:"used_by,omitempty"`
	UsedAt            *time.Time `json:"used_at,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

func (LinkCode) TableName() string {
	return "link_codes"
}

// LinkCodeStore provides operations for one-time link codes.
type LinkCodeStore struct {
	DB  *gorm.DB
	TTL time.Duration
}

// NewLinkCodeStore creates a new LinkCodeStore with default TTL of 10 minutes.
func NewLinkCodeStore(db *gorm.DB) *LinkCodeStore {
	return &LinkCodeStore{
		DB:  db,
		TTL: 10 * time.Minute,
	}
}

// NewLinkCodeStoreWithTTL creates a new LinkCodeStore with custom TTL.
func NewLinkCodeStoreWithTTL(db *gorm.DB, ttl time.Duration) *LinkCodeStore {
	return &LinkCodeStore{
		DB:  db,
		TTL: ttl,
	}
}

// GenerateCode creates a secure random 8-character link code.
func generateLinkCode() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateLinkCode generates a new one-time link code for a headless account.
// If a valid code already exists for this headless account, it returns that code.
func (s *LinkCodeStore) CreateLinkCode(ctx context.Context, headlessAccountID, namespace, providerType, providerAccountID string) (*LinkCode, error) {
	// Check if there's already a valid code for this headless account
	var existing LinkCode
	err := s.DB.WithContext(ctx).Where(
		"headless_account_id = ? AND namespace = ? AND used = FALSE AND expires_at > ?",
		headlessAccountID, namespace, time.Now().UTC(),
	).First(&existing).Error

	if err == nil {
		// Return existing valid code
		return &existing, nil
	}

	// Generate new code
	code, err := generateLinkCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate link code: %w", err)
	}

	// Create new link code
	linkCode := &LinkCode{
		ID:                generateID(),
		Code:              code,
		HeadlessAccountID: headlessAccountID,
		Namespace:         namespace,
		ProviderType:      providerType,
		ProviderAccountID: providerAccountID,
		ExpiresAt:         time.Now().UTC().Add(s.TTL),
		Used:              false,
		CreatedAt:         time.Now().UTC(),
	}

	if err := s.DB.WithContext(ctx).Create(linkCode).Error; err != nil {
		return nil, fmt.Errorf("failed to save link code: %w", err)
	}

	return linkCode, nil
}

// ValidateLinkCode checks if a link code is valid and not expired.
func (s *LinkCodeStore) ValidateLinkCode(ctx context.Context, code string) (*LinkCode, error) {
	var linkCode LinkCode
	err := s.DB.WithContext(ctx).Where(
		"code = ? AND used = FALSE AND expires_at > ?",
		code, time.Now().UTC(),
	).First(&linkCode).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // Code not found or expired
		}
		return nil, err
	}

	return &linkCode, nil
}

// UseLinkCode marks a link code as used by the specified account.
func (s *LinkCodeStore) UseLinkCode(ctx context.Context, code, usedByAccountID string) error {
	now := time.Now().UTC()
	result := s.DB.WithContext(ctx).Model(&LinkCode{}).
		Where("code = ? AND used = FALSE AND expires_at > ?", code, now).
		Updates(map[string]interface{}{
			"used":    true,
			"used_by": usedByAccountID,
			"used_at": now,
		})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("link code not found, already used, or expired")
	}
	return nil
}

// GetLinkCodeByHeadlessAccount returns the active link code for a headless account.
func (s *LinkCodeStore) GetLinkCodeByHeadlessAccount(ctx context.Context, headlessAccountID, namespace string) (*LinkCode, error) {
	var linkCode LinkCode
	err := s.DB.WithContext(ctx).Where(
		"headless_account_id = ? AND namespace = ? AND used = FALSE AND expires_at > ?",
		headlessAccountID, namespace, time.Now().UTC(),
	).First(&linkCode).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	return &linkCode, nil
}

// DeleteExpiredCodes removes expired link codes from the database.
func (s *LinkCodeStore) DeleteExpiredCodes(ctx context.Context) (int64, error) {
	result := s.DB.WithContext(ctx).Where(
		"expires_at < ? OR used = TRUE",
		time.Now().UTC().Add(-24*time.Hour), // Keep used codes for 24 hours for audit
	).Delete(&LinkCode{})

	return result.RowsAffected, result.Error
}

// generateID creates a unique ID (same format as LegitID from models).
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
