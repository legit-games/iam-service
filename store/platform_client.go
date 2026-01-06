package store

import (
	"context"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// PlatformClientStore provides operations for platform client configurations.
type PlatformClientStore struct {
	DB *gorm.DB
}

// NewPlatformClientStore creates a new platform client store.
func NewPlatformClientStore(db *gorm.DB) *PlatformClientStore {
	return &PlatformClientStore{DB: db}
}

// GetByNamespaceAndPlatform returns a platform client by namespace and platform ID.
func (s *PlatformClientStore) GetByNamespaceAndPlatform(ctx context.Context, namespace, platformID string) (*models.PlatformClient, error) {
	var pc models.PlatformClient
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND platform_id = ? AND active = ?", namespace, platformID, true).
		First(&pc).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &pc, nil
}

// GetByNamespace returns all platform clients for a namespace.
func (s *PlatformClientStore) GetByNamespace(ctx context.Context, namespace string) ([]models.PlatformClient, error) {
	var clients []models.PlatformClient
	err := s.DB.WithContext(ctx).
		Where("namespace = ? AND active = ?", namespace, true).
		Find(&clients).Error
	if err != nil {
		return nil, err
	}
	return clients, nil
}

// Create creates a new platform client configuration.
func (s *PlatformClientStore) Create(ctx context.Context, pc *models.PlatformClient) error {
	if pc.ID == "" {
		pc.ID = models.LegitID()
	}
	now := time.Now().UTC()
	pc.CreatedAt = now
	pc.UpdatedAt = now
	if pc.Environment == "" {
		pc.Environment = models.EnvProd
	}
	pc.Active = true
	return s.DB.WithContext(ctx).Create(pc).Error
}

// Update updates an existing platform client configuration.
func (s *PlatformClientStore) Update(ctx context.Context, pc *models.PlatformClient) error {
	pc.UpdatedAt = time.Now().UTC()
	return s.DB.WithContext(ctx).Save(pc).Error
}

// Delete soft-deletes a platform client by setting active to false.
func (s *PlatformClientStore) Delete(ctx context.Context, namespace, platformID string) error {
	return s.DB.WithContext(ctx).
		Model(&models.PlatformClient{}).
		Where("namespace = ? AND platform_id = ?", namespace, platformID).
		Update("active", false).Error
}

// HardDelete permanently removes a platform client.
func (s *PlatformClientStore) HardDelete(ctx context.Context, namespace, platformID string) error {
	return s.DB.WithContext(ctx).
		Where("namespace = ? AND platform_id = ?", namespace, platformID).
		Delete(&models.PlatformClient{}).Error
}

// ListAll returns all active platform clients.
func (s *PlatformClientStore) ListAll(ctx context.Context) ([]models.PlatformClient, error) {
	var clients []models.PlatformClient
	err := s.DB.WithContext(ctx).
		Where("active = ?", true).
		Find(&clients).Error
	if err != nil {
		return nil, err
	}
	return clients, nil
}

// Upsert creates or updates a platform client.
func (s *PlatformClientStore) Upsert(ctx context.Context, pc *models.PlatformClient) error {
	existing, err := s.GetByNamespaceAndPlatform(ctx, pc.Namespace, pc.PlatformID)
	if err != nil {
		return err
	}
	if existing != nil {
		pc.ID = existing.ID
		pc.CreatedAt = existing.CreatedAt
		return s.Update(ctx, pc)
	}
	return s.Create(ctx, pc)
}
