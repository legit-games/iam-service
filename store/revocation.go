package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/go-oauth2/oauth2/v4/utils/bloom"
	"gorm.io/gorm"
)

// RevocationConfig holds configuration for the revocation store.
type RevocationConfig struct {
	// TokenTTL is how long revoked tokens are kept (should match max token lifetime)
	TokenTTL time.Duration
	// UserRevocationTTL is how long user revocations are kept
	UserRevocationTTL time.Duration
	// BloomFilterSize is the size of the bloom filter bit array
	BloomFilterSize uint
	// BloomFilterHashCount is the number of hash functions for bloom filter
	BloomFilterHashCount uint
}

// DefaultRevocationConfig returns the default configuration.
func DefaultRevocationConfig() RevocationConfig {
	return RevocationConfig{
		TokenTTL:             24 * time.Hour * 7, // 7 days
		UserRevocationTTL:    24 * time.Hour * 7, // 7 days
		BloomFilterSize:      10000,
		BloomFilterHashCount: 7,
	}
}

// RevokedToken represents a revoked token record.
type RevokedToken struct {
	ID        string    `gorm:"column:id;primaryKey" json:"id"`
	TokenHash string    `gorm:"column:token_hash;not null" json:"token_hash"`
	UserID    *string   `gorm:"column:user_id" json:"user_id,omitempty"`
	ClientID  *string   `gorm:"column:client_id" json:"client_id,omitempty"`
	RevokedAt time.Time `gorm:"column:revoked_at;not null" json:"revoked_at"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null" json:"expires_at"`
	Reason    string    `gorm:"column:reason" json:"reason,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
}

func (RevokedToken) TableName() string {
	return "revoked_tokens"
}

// RevokedUser represents a user whose all tokens are revoked.
type RevokedUser struct {
	ID        string    `gorm:"column:id;primaryKey" json:"id"`
	UserID    string    `gorm:"column:user_id;not null" json:"user_id"`
	RevokedAt time.Time `gorm:"column:revoked_at;not null" json:"revoked_at"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null" json:"expires_at"`
	Reason    string    `gorm:"column:reason" json:"reason,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
}

func (RevokedUser) TableName() string {
	return "revoked_users"
}

// RevocationBloomFilter represents a stored bloom filter for a specific date.
type RevocationBloomFilter struct {
	ID         string    `gorm:"column:id;primaryKey" json:"id"`
	FilterDate time.Time `gorm:"column:filter_date;not null" json:"filter_date"`
	M          int       `gorm:"column:m;not null" json:"m"`
	K          int       `gorm:"column:k;not null" json:"k"`
	FilterData []byte    `gorm:"column:filter_data;not null" json:"filter_data"`
	TokenCount int       `gorm:"column:token_count" json:"token_count"`
	CreatedAt  time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (RevocationBloomFilter) TableName() string {
	return "revocation_bloom_filters"
}

// UserRevocationRecord is the response format for user revocation list.
type UserRevocationRecord struct {
	ID        string    `json:"id"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevocationList is the response format for the revocation list API.
type RevocationList struct {
	RevokedTokens bloom.FilterJSON       `json:"revoked_tokens"`
	RevokedUsers  []UserRevocationRecord `json:"revoked_users"`
}

// RevocationStore manages token and user revocation data.
type RevocationStore struct {
	db     *gorm.DB
	config RevocationConfig
}

// NewRevocationStore creates a new RevocationStore.
func NewRevocationStore(db *gorm.DB) *RevocationStore {
	return &RevocationStore{
		db:     db,
		config: DefaultRevocationConfig(),
	}
}

// NewRevocationStoreWithConfig creates a new RevocationStore with custom config.
func NewRevocationStoreWithConfig(db *gorm.DB, config RevocationConfig) *RevocationStore {
	return &RevocationStore{
		db:     db,
		config: config,
	}
}

// HashToken creates a SHA256 hash of the token for storage.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// RevokeToken revokes a single token.
func (s *RevocationStore) RevokeToken(ctx context.Context, token string, userID, clientID *string, reason string, expiresAt time.Time) error {
	tokenHash := HashToken(token)

	record := &RevokedToken{
		TokenHash: tokenHash,
		UserID:    userID,
		ClientID:  clientID,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	return s.db.WithContext(ctx).Create(record).Error
}

// RevokeTokenByHash revokes a token by its hash (useful when you only have the hash).
func (s *RevocationStore) RevokeTokenByHash(ctx context.Context, tokenHash string, userID, clientID *string, reason string, expiresAt time.Time) error {
	record := &RevokedToken{
		TokenHash: tokenHash,
		UserID:    userID,
		ClientID:  clientID,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	return s.db.WithContext(ctx).Create(record).Error
}

// IsTokenRevoked checks if a token is in the revocation list.
func (s *RevocationStore) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	tokenHash := HashToken(token)
	return s.IsTokenRevokedByHash(ctx, tokenHash)
}

// IsTokenRevokedByHash checks if a token hash is in the revocation list.
func (s *RevocationStore) IsTokenRevokedByHash(ctx context.Context, tokenHash string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&RevokedToken{}).
		Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now().UTC()).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// RevokeUser revokes all tokens for a user.
func (s *RevocationStore) RevokeUser(ctx context.Context, userID, reason string) error {
	expiresAt := time.Now().UTC().Add(s.config.UserRevocationTTL)

	// First, delete any existing active revocation for this user
	s.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Delete(&RevokedUser{})

	record := &RevokedUser{
		UserID:    userID,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	return s.db.WithContext(ctx).Create(record).Error
}

// RevokeUserWithExpiry revokes all tokens for a user with custom expiry.
func (s *RevocationStore) RevokeUserWithExpiry(ctx context.Context, userID, reason string, expiresAt time.Time) error {
	// First, delete any existing active revocation for this user
	s.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Delete(&RevokedUser{})

	record := &RevokedUser{
		UserID:    userID,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	return s.db.WithContext(ctx).Create(record).Error
}

// IsUserRevoked checks if a user's tokens are revoked.
// Returns the revocation time if revoked, nil otherwise.
func (s *RevocationStore) IsUserRevoked(ctx context.Context, userID string) (*time.Time, error) {
	var record RevokedUser
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Order("revoked_at DESC").
		First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record.RevokedAt, nil
}

// GetRevokedUsers returns all currently revoked users.
func (s *RevocationStore) GetRevokedUsers(ctx context.Context) ([]UserRevocationRecord, error) {
	var records []RevokedUser
	err := s.db.WithContext(ctx).
		Where("expires_at > ?", time.Now().UTC()).
		Order("revoked_at DESC").
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	result := make([]UserRevocationRecord, len(records))
	for i, r := range records {
		result[i] = UserRevocationRecord{
			ID:        r.UserID,
			RevokedAt: r.RevokedAt,
		}
	}
	return result, nil
}

// GetRevokedUsersSince returns users revoked since the given time.
func (s *RevocationStore) GetRevokedUsersSince(ctx context.Context, since time.Time) ([]UserRevocationRecord, error) {
	var records []RevokedUser
	err := s.db.WithContext(ctx).
		Where("revoked_at >= ? AND expires_at > ?", since, time.Now().UTC()).
		Order("revoked_at DESC").
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	result := make([]UserRevocationRecord, len(records))
	for i, r := range records {
		result[i] = UserRevocationRecord{
			ID:        r.UserID,
			RevokedAt: r.RevokedAt,
		}
	}
	return result, nil
}

// GetTodayRevokedTokens returns all tokens revoked today.
func (s *RevocationStore) GetTodayRevokedTokens(ctx context.Context) ([]RevokedToken, error) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	tomorrow := today.Add(24 * time.Hour)

	var records []RevokedToken
	err := s.db.WithContext(ctx).
		Where("revoked_at >= ? AND revoked_at < ? AND expires_at > ?", today, tomorrow, time.Now().UTC()).
		Find(&records).Error
	return records, err
}

// GetRevokedTokensSince returns tokens revoked since the given time.
func (s *RevocationStore) GetRevokedTokensSince(ctx context.Context, since time.Time) ([]RevokedToken, error) {
	var records []RevokedToken
	err := s.db.WithContext(ctx).
		Where("revoked_at >= ? AND expires_at > ?", since, time.Now().UTC()).
		Find(&records).Error
	return records, err
}

// BuildBloomFilter builds a bloom filter from today's revoked tokens.
func (s *RevocationStore) BuildBloomFilter(ctx context.Context) (*bloom.Filter, error) {
	tokens, err := s.GetTodayRevokedTokens(ctx)
	if err != nil {
		return nil, err
	}

	filter := bloom.NewWithParams(s.config.BloomFilterSize, s.config.BloomFilterHashCount)
	for _, t := range tokens {
		filter.Put([]byte(t.TokenHash))
	}

	return filter, nil
}

// BuildBloomFilterSince builds a bloom filter from tokens revoked since the given time.
func (s *RevocationStore) BuildBloomFilterSince(ctx context.Context, since time.Time) (*bloom.Filter, error) {
	tokens, err := s.GetRevokedTokensSince(ctx, since)
	if err != nil {
		return nil, err
	}

	filter := bloom.NewWithParams(s.config.BloomFilterSize, s.config.BloomFilterHashCount)
	for _, t := range tokens {
		filter.Put([]byte(t.TokenHash))
	}

	return filter, nil
}

// SaveBloomFilter saves a bloom filter to the database.
func (s *RevocationStore) SaveBloomFilter(ctx context.Context, date time.Time, filter *bloom.Filter, tokenCount int) error {
	filterDate := date.Truncate(24 * time.Hour)

	// Serialize the bloom filter data
	filterData, err := json.Marshal(filter.B())
	if err != nil {
		return err
	}

	// Upsert the bloom filter
	record := &RevocationBloomFilter{
		FilterDate: filterDate,
		M:          int(filter.M()),
		K:          int(filter.K()),
		FilterData: filterData,
		TokenCount: tokenCount,
		UpdatedAt:  time.Now().UTC(),
	}

	return s.db.WithContext(ctx).
		Where("filter_date = ?", filterDate).
		Assign(record).
		FirstOrCreate(record).Error
}

// GetBloomFilter retrieves a bloom filter for a specific date.
func (s *RevocationStore) GetBloomFilter(ctx context.Context, date time.Time) (*bloom.Filter, error) {
	filterDate := date.Truncate(24 * time.Hour)

	var record RevocationBloomFilter
	err := s.db.WithContext(ctx).
		Where("filter_date = ?", filterDate).
		First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	var data []uint64
	if err := json.Unmarshal(record.FilterData, &data); err != nil {
		return nil, err
	}

	return bloom.NewFromData(uint(record.M), uint(record.K), data), nil
}

// GetMergedBloomFilter returns a merged bloom filter for the TTL period.
func (s *RevocationStore) GetMergedBloomFilter(ctx context.Context) (*bloom.Filter, error) {
	since := time.Now().UTC().Add(-s.config.TokenTTL).Truncate(24 * time.Hour)

	var records []RevocationBloomFilter
	err := s.db.WithContext(ctx).
		Where("filter_date >= ?", since).
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		// Return an empty filter
		return bloom.NewWithParams(s.config.BloomFilterSize, s.config.BloomFilterHashCount), nil
	}

	// Start with the first filter
	var data []uint64
	if err := json.Unmarshal(records[0].FilterData, &data); err != nil {
		return nil, err
	}
	merged := bloom.NewFromData(uint(records[0].M), uint(records[0].K), data)

	// Merge remaining filters
	for i := 1; i < len(records); i++ {
		var filterData []uint64
		if err := json.Unmarshal(records[i].FilterData, &filterData); err != nil {
			return nil, err
		}
		filter := bloom.NewFromData(uint(records[i].M), uint(records[i].K), filterData)
		merged, err = bloom.Merge(merged, filter)
		if err != nil {
			// If incompatible, skip this filter
			continue
		}
	}

	return merged, nil
}

// GetRevocationList returns the complete revocation list for API response.
func (s *RevocationStore) GetRevocationList(ctx context.Context) (*RevocationList, error) {
	// Get merged bloom filter for revoked tokens
	filter, err := s.GetMergedBloomFilter(ctx)
	if err != nil {
		return nil, err
	}

	// Also include today's tokens in the bloom filter
	todayFilter, err := s.BuildBloomFilter(ctx)
	if err != nil {
		return nil, err
	}

	if todayFilter != nil && filter != nil {
		merged, mergeErr := bloom.Merge(filter, todayFilter)
		if mergeErr == nil {
			filter = merged
		}
	} else if todayFilter != nil {
		filter = todayFilter
	}

	// Get revoked users
	users, err := s.GetRevokedUsers(ctx)
	if err != nil {
		return nil, err
	}

	return &RevocationList{
		RevokedTokens: filter.ToJSON(),
		RevokedUsers:  users,
	}, nil
}

// CleanupExpired removes expired revocation records.
func (s *RevocationStore) CleanupExpired(ctx context.Context) error {
	now := time.Now().UTC()

	// Clean up expired tokens
	if err := s.db.WithContext(ctx).
		Where("expires_at < ?", now).
		Delete(&RevokedToken{}).Error; err != nil {
		return err
	}

	// Clean up expired user revocations
	if err := s.db.WithContext(ctx).
		Where("expires_at < ?", now).
		Delete(&RevokedUser{}).Error; err != nil {
		return err
	}

	// Clean up old bloom filters
	cutoff := now.Add(-s.config.TokenTTL * 2).Truncate(24 * time.Hour)
	if err := s.db.WithContext(ctx).
		Where("filter_date < ?", cutoff).
		Delete(&RevocationBloomFilter{}).Error; err != nil {
		return err
	}

	return nil
}

// RemoveUserRevocation removes user revocation (e.g., when ban is lifted).
func (s *RevocationStore) RemoveUserRevocation(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&RevokedUser{}).Error
}

// GetConfig returns the current configuration.
func (s *RevocationStore) GetConfig() RevocationConfig {
	return s.config
}
