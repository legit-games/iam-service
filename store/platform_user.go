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

// PlatformUserSearchParams holds search parameters for platform accounts.
type PlatformUserSearchParams struct {
	PlatformID     string     // Filter by platform ID (exact match)
	PlatformUserID string     // Filter by platform user ID (partial match)
	CreatedFrom    *time.Time // Filter by created_at >= value
	CreatedTo      *time.Time // Filter by created_at <= value
	Offset         int        // Pagination offset
	Limit          int        // Pagination limit (default 20, max 100)
}

// PlatformUserWithUserID extends PlatformUser with the actual user_id from account_users table.
type PlatformUserWithUserID struct {
	models.PlatformUser
	AccountID  string `json:"account_id"`  // The account_id (stored in platform_users.user_id)
	ActualUserID string `json:"actual_user_id"` // The actual user_id from account_users table
}

// PlatformUserSearchResult holds search results with pagination info.
type PlatformUserSearchResult struct {
	Data   []PlatformUserWithUserID `json:"data"`
	Total  int64                    `json:"total"`
	Offset int                      `json:"offset"`
	Limit  int                      `json:"limit"`
}

// SearchPlatformAccounts searches platform accounts with filters and pagination.
func (s *PlatformUserStore) SearchPlatformAccounts(ctx context.Context, namespace string, params *PlatformUserSearchParams) (*PlatformUserSearchResult, error) {
	query := s.DB.WithContext(ctx).Model(&models.PlatformUser{}).Where("platform_users.namespace = ?", namespace)

	// Apply filters
	if params.PlatformID != "" {
		query = query.Where("platform_users.platform_id = ?", params.PlatformID)
	}
	if params.PlatformUserID != "" {
		query = query.Where("platform_users.platform_user_id ILIKE ?", "%"+params.PlatformUserID+"%")
	}
	if params.CreatedFrom != nil {
		query = query.Where("platform_users.created_at >= ?", *params.CreatedFrom)
	}
	if params.CreatedTo != nil {
		query = query.Where("platform_users.created_at <= ?", *params.CreatedTo)
	}

	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply pagination
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	// Fetch results with LEFT JOIN to get actual user_id from account_users
	type resultRow struct {
		models.PlatformUser
		ActualUserID *string `gorm:"column:actual_user_id"`
	}
	var rows []resultRow
	err := s.DB.WithContext(ctx).
		Table("platform_users").
		Select("platform_users.*, account_users.user_id as actual_user_id").
		Joins("LEFT JOIN account_users ON platform_users.user_id = account_users.account_id").
		Where("platform_users.namespace = ?", namespace).
		Scopes(func(db *gorm.DB) *gorm.DB {
			if params.PlatformID != "" {
				db = db.Where("platform_users.platform_id = ?", params.PlatformID)
			}
			if params.PlatformUserID != "" {
				db = db.Where("platform_users.platform_user_id ILIKE ?", "%"+params.PlatformUserID+"%")
			}
			if params.CreatedFrom != nil {
				db = db.Where("platform_users.created_at >= ?", *params.CreatedFrom)
			}
			if params.CreatedTo != nil {
				db = db.Where("platform_users.created_at <= ?", *params.CreatedTo)
			}
			return db
		}).
		Order("platform_users.created_at DESC").
		Offset(offset).
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	// Convert to result format
	data := make([]PlatformUserWithUserID, len(rows))
	for i, row := range rows {
		data[i] = PlatformUserWithUserID{
			PlatformUser: row.PlatformUser,
			AccountID:    row.PlatformUser.UserID, // platform_users.user_id is actually account_id
			ActualUserID: "",
		}
		if row.ActualUserID != nil {
			data[i].ActualUserID = *row.ActualUserID
		}
		// Clear the misleading user_id field and set it to actual user_id
		data[i].PlatformUser.UserID = data[i].ActualUserID
	}

	return &PlatformUserSearchResult{
		Data:   data,
		Total:  total,
		Offset: offset,
		Limit:  limit,
	}, nil
}