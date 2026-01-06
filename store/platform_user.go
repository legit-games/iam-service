package store

import (
	"context"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// PlatformUserStore provides operations for platform user links.
type PlatformUserStore struct {
	DB *gorm.DB
}

// NewPlatformUserStore creates a new platform user store.
func NewPlatformUserStore(db *gorm.DB) *PlatformUserStore {
	return &PlatformUserStore{DB: db}
}

// GetPlatformAccount returns a platform account for a user by platform ID.
func (s *PlatformUserStore) GetPlatformAccount(ctx context.Context, namespace, platformID, userID string) (*models.PlatformUser, error) {
	var pu models.PlatformUser
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND platform_id = ? AND user_id = ?", namespace, platformID, userID).
		First(&pu).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &pu, nil
}

// GetPlatformAccountsByPlatformID returns all platform accounts for a user by platform ID.
func (s *PlatformUserStore) GetPlatformAccountsByPlatformID(ctx context.Context, namespace, userID, platformID string) ([]models.PlatformUser, error) {
	var accounts []models.PlatformUser
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND user_id = ? AND platform_id = ?", namespace, userID, platformID).
		Find(&accounts).Error
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

// GetPlatformAccountByPlatformUserID returns platform account by platform user ID.
func (s *PlatformUserStore) GetPlatformAccountByPlatformUserID(ctx context.Context, namespace, platformID, platformUserID string) (*models.PlatformUser, error) {
	var pu models.PlatformUser
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND platform_id = ? AND platform_user_id = ?", namespace, platformID, platformUserID).
		First(&pu).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &pu, nil
}

// CreatePlatformAccount creates a new platform account link.
func (s *PlatformUserStore) CreatePlatformAccount(ctx context.Context, pu *models.PlatformUser) error {
	if pu.ID == "" {
		pu.ID = models.LegitID()
	}
	now := time.Now().UTC()
	pu.CreatedAt = now
	pu.UpdatedAt = now
	if pu.LinkedAt.IsZero() {
		pu.LinkedAt = now
	}
	return s.DB.WithContext(ctx).Create(pu).Error
}

// UpdatePlatformRefreshToken updates the refresh token for a platform account.
func (s *PlatformUserStore) UpdatePlatformRefreshToken(ctx context.Context, namespace, platformID, platformUserID, refreshToken string) error {
	return s.DB.WithContext(ctx).
		Model(&models.PlatformUser{}).
		Where("namespace = ? AND platform_id = ? AND platform_user_id = ?", namespace, platformID, platformUserID).
		Updates(map[string]interface{}{
			"refresh_token": refreshToken,
			"updated_at":    time.Now().UTC(),
		}).Error
}

// DeletePlatformAccount deletes a platform account link.
func (s *PlatformUserStore) DeletePlatformAccount(ctx context.Context, namespace, platformID, userID string) error {
	return s.DB.WithContext(ctx).
		Where("namespace = ? AND platform_id = ? AND user_id = ?", namespace, platformID, userID).
		Delete(&models.PlatformUser{}).Error
}

// ListPlatformAccountsByUser returns all platform accounts for a user in a namespace.
func (s *PlatformUserStore) ListPlatformAccountsByUser(ctx context.Context, namespace, userID string) ([]models.PlatformUser, error) {
	var accounts []models.PlatformUser
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND user_id = ?", namespace, userID).
		Find(&accounts).Error
	if err != nil {
		return nil, err
	}
	return accounts, nil
}