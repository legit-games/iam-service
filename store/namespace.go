package store

import (
	"context"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// NamespaceStore handles namespaces persistence.
type NamespaceStore struct{ DB *gorm.DB }

func NewNamespaceStore(db *gorm.DB) *NamespaceStore { return &NamespaceStore{DB: db} }

func (s *NamespaceStore) Create(ctx context.Context, name, ntype, description string) (string, error) {
	id := models.LegitID()
	if err := s.DB.WithContext(ctx).Exec(`INSERT INTO namespaces(id, name, type, description, active) VALUES(?,?,?,?,TRUE)`, id, name, ntype, description).Error; err != nil {
		return "", err
	}
	return id, nil
}

func (s *NamespaceStore) GetByName(ctx context.Context, name string) (*models.Namespace, error) {
	var ns models.Namespace
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, name, type, description, active, created_at, updated_at FROM namespaces WHERE name=?`, name).Scan(&ns).Error; err != nil {
		return nil, err
	}
	if ns.ID == "" {
		return nil, nil
	}
	return &ns, nil
}

func (s *NamespaceStore) List(ctx context.Context) ([]*models.Namespace, error) {
	var namespaces []*models.Namespace
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, name, type, description, active, created_at, updated_at FROM namespaces ORDER BY name`).Scan(&namespaces).Error; err != nil {
		return nil, err
	}
	return namespaces, nil
}

func (s *NamespaceStore) GetByID(ctx context.Context, id string) (*models.Namespace, error) {
	var ns models.Namespace
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, name, type, description, active, created_at, updated_at FROM namespaces WHERE id=?`, id).Scan(&ns).Error; err != nil {
		return nil, err
	}
	if ns.ID == "" {
		return nil, nil
	}
	return &ns, nil
}

func (s *NamespaceStore) Update(ctx context.Context, name, description string, active bool) error {
	return s.DB.WithContext(ctx).Exec(`UPDATE namespaces SET description=?, active=?, updated_at=NOW() WHERE name=?`, description, active, name).Error
}
