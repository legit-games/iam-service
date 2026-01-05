package store

import (
	"context"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// NamespaceStore handles namespaces persistence.
type NamespaceStore struct{ DB *gorm.DB }

func NewNamespaceStore(db *gorm.DB) *NamespaceStore { return &NamespaceStore{DB: db} }

func (s *NamespaceStore) Create(ctx context.Context, name, description string) (string, error) {
	id := models.LegitID()
	if err := s.DB.WithContext(ctx).Exec(`INSERT INTO namespaces(id, name, description) VALUES(?,?,?)`, id, name, description).Error; err != nil {
		return "", err
	}
	return id, nil
}

func (s *NamespaceStore) GetByName(ctx context.Context, name string) (*models.Namespace, error) {
	var ns models.Namespace
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, name, description, created_at, updated_at FROM namespaces WHERE name=?`, name).Scan(&ns).Error; err != nil {
		return nil, err
	}
	if ns.ID == "" {
		return nil, nil
	}
	return &ns, nil
}
