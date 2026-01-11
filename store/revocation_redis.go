package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4/utils/bloom"
	valkey "github.com/valkey-io/valkey-go"
)

const (
	// Redis key prefixes for revocation data
	revocationKeyPrefix     = "revoke:"
	bloomFilterDataKey      = revocationKeyPrefix + "bloom:data"
	bloomFilterMetaKey      = revocationKeyPrefix + "bloom:meta"
	revokedUsersKey         = revocationKeyPrefix + "users"
	revokedTokensKeyPrefix  = revocationKeyPrefix + "tokens:"
)

// RevocationRedisCache provides Redis-based caching for token revocation.
// This enables immediate synchronization across all pods in a Kubernetes cluster.
type RevocationRedisCache struct {
	client valkey.Client
	prefix string
	config RevocationConfig
}

// BloomFilterMeta stores bloom filter metadata in Redis.
type BloomFilterMeta struct {
	M          uint      `json:"m"`
	K          uint      `json:"k"`
	TokenCount int       `json:"token_count"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// NewRevocationRedisCache creates a new Redis-based revocation cache.
func NewRevocationRedisCache(addr string, prefix string, config RevocationConfig) (*RevocationRedisCache, error) {
	if addr == "" {
		return nil, fmt.Errorf("redis address is required")
	}

	cli, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	if prefix == "" {
		prefix = "oauth2:"
	}

	return &RevocationRedisCache{
		client: cli,
		prefix: prefix,
		config: config,
	}, nil
}

// key returns the full Redis key with prefix.
func (c *RevocationRedisCache) key(k string) string {
	return c.prefix + k
}

// GetClient returns the underlying Valkey client.
func (c *RevocationRedisCache) GetClient() valkey.Client {
	return c.client
}

// GetPrefix returns the key prefix.
func (c *RevocationRedisCache) GetPrefix() string {
	return c.prefix
}

// Close closes the Redis connection.
func (c *RevocationRedisCache) Close() {
	c.client.Close()
}

// AddRevokedToken adds a revoked token hash to Redis.
func (c *RevocationRedisCache) AddRevokedToken(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // Already expired
	}

	// Store individual token with TTL
	key := c.key(revokedTokensKeyPrefix + tokenHash)
	err := c.client.Do(ctx, c.client.B().Set().Key(key).Value("1").Ex(ttl).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to add revoked token to redis: %w", err)
	}

	// Update bloom filter
	return c.addToBloomFilter(ctx, tokenHash)
}

// IsTokenRevoked checks if a token hash is revoked (using Redis).
func (c *RevocationRedisCache) IsTokenRevoked(ctx context.Context, tokenHash string) (bool, error) {
	// First check bloom filter for fast negative lookup
	inBloom, err := c.checkBloomFilter(ctx, tokenHash)
	if err != nil {
		// On error, fall through to direct check
	} else if !inBloom {
		// Bloom filter says definitely not revoked
		return false, nil
	}

	// Bloom filter says possibly revoked, check exact key
	key := c.key(revokedTokensKeyPrefix + tokenHash)
	res := c.client.Do(ctx, c.client.B().Exists().Key(key).Build())
	if res.Error() != nil {
		return false, res.Error()
	}

	count, err := res.ToInt64()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// AddRevokedUser adds a revoked user to Redis.
func (c *RevocationRedisCache) AddRevokedUser(ctx context.Context, userID string, revokedAt time.Time, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // Already expired
	}

	// Store in hash with revokedAt timestamp and expiry info
	data := fmt.Sprintf("%d:%d", revokedAt.Unix(), expiresAt.Unix())
	err := c.client.Do(ctx, c.client.B().Hset().Key(c.key(revokedUsersKey)).FieldValue().FieldValue(userID, data).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to add revoked user to redis: %w", err)
	}

	return nil
}

// RemoveRevokedUser removes a user from the revoked users list.
func (c *RevocationRedisCache) RemoveRevokedUser(ctx context.Context, userID string) error {
	err := c.client.Do(ctx, c.client.B().Hdel().Key(c.key(revokedUsersKey)).Field(userID).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to remove revoked user from redis: %w", err)
	}
	return nil
}

// IsUserRevoked checks if a user is revoked and returns the revocation time.
func (c *RevocationRedisCache) IsUserRevoked(ctx context.Context, userID string) (*time.Time, error) {
	res := c.client.Do(ctx, c.client.B().Hget().Key(c.key(revokedUsersKey)).Field(userID).Build())
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return nil, nil // Not revoked
		}
		return nil, res.Error()
	}

	data, err := res.ToString()
	if err != nil || data == "" {
		return nil, nil
	}

	// Parse "revokedAt:expiresAt" format
	var revokedAtUnix, expiresAtUnix int64
	_, err = fmt.Sscanf(data, "%d:%d", &revokedAtUnix, &expiresAtUnix)
	if err != nil {
		return nil, nil
	}

	// Check if expired
	if time.Now().Unix() > expiresAtUnix {
		// Cleanup expired entry
		_ = c.RemoveRevokedUser(ctx, userID)
		return nil, nil
	}

	revokedAt := time.Unix(revokedAtUnix, 0).UTC()
	return &revokedAt, nil
}

// GetAllRevokedUsers returns all currently revoked users.
func (c *RevocationRedisCache) GetAllRevokedUsers(ctx context.Context) ([]UserRevocationRecord, error) {
	res := c.client.Do(ctx, c.client.B().Hgetall().Key(c.key(revokedUsersKey)).Build())
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return nil, nil
		}
		return nil, res.Error()
	}

	data, err := res.AsStrMap()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	var users []UserRevocationRecord
	var expiredUsers []string

	for userID, value := range data {
		var revokedAtUnix, expiresAtUnix int64
		_, err := fmt.Sscanf(value, "%d:%d", &revokedAtUnix, &expiresAtUnix)
		if err != nil {
			continue
		}

		// Skip expired entries
		if now > expiresAtUnix {
			expiredUsers = append(expiredUsers, userID)
			continue
		}

		users = append(users, UserRevocationRecord{
			ID:        userID,
			RevokedAt: time.Unix(revokedAtUnix, 0).UTC(),
		})
	}

	// Cleanup expired entries asynchronously
	if len(expiredUsers) > 0 {
		go func() {
			for _, userID := range expiredUsers {
				_ = c.RemoveRevokedUser(context.Background(), userID)
			}
		}()
	}

	return users, nil
}

// SaveBloomFilter saves the bloom filter to Redis.
func (c *RevocationRedisCache) SaveBloomFilter(ctx context.Context, filter *bloom.Filter, tokenCount int) error {
	if filter == nil {
		return nil
	}

	// Save bloom filter data
	filterData, err := json.Marshal(filter.B())
	if err != nil {
		return fmt.Errorf("failed to serialize bloom filter: %w", err)
	}

	err = c.client.Do(ctx, c.client.B().Set().Key(c.key(bloomFilterDataKey)).Value(string(filterData)).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to save bloom filter data to redis: %w", err)
	}

	// Save metadata
	meta := BloomFilterMeta{
		M:          filter.M(),
		K:          filter.K(),
		TokenCount: tokenCount,
		UpdatedAt:  time.Now().UTC(),
	}
	metaData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to serialize bloom filter meta: %w", err)
	}

	err = c.client.Do(ctx, c.client.B().Set().Key(c.key(bloomFilterMetaKey)).Value(string(metaData)).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to save bloom filter meta to redis: %w", err)
	}

	return nil
}

// GetBloomFilter retrieves the bloom filter from Redis.
func (c *RevocationRedisCache) GetBloomFilter(ctx context.Context) (*bloom.Filter, error) {
	// Get metadata first
	metaRes := c.client.Do(ctx, c.client.B().Get().Key(c.key(bloomFilterMetaKey)).Build())
	if metaRes.Error() != nil {
		if valkey.IsValkeyNil(metaRes.Error()) {
			return nil, nil
		}
		return nil, metaRes.Error()
	}

	metaStr, err := metaRes.ToString()
	if err != nil || metaStr == "" {
		return nil, nil
	}

	var meta BloomFilterMeta
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		return nil, fmt.Errorf("failed to parse bloom filter meta: %w", err)
	}

	// Get bloom filter data
	dataRes := c.client.Do(ctx, c.client.B().Get().Key(c.key(bloomFilterDataKey)).Build())
	if dataRes.Error() != nil {
		if valkey.IsValkeyNil(dataRes.Error()) {
			return nil, nil
		}
		return nil, dataRes.Error()
	}

	dataStr, err := dataRes.ToString()
	if err != nil || dataStr == "" {
		return nil, nil
	}

	var data []uint64
	if err := json.Unmarshal([]byte(dataStr), &data); err != nil {
		return nil, fmt.Errorf("failed to parse bloom filter data: %w", err)
	}

	return bloom.NewFromData(meta.M, meta.K, data), nil
}

// addToBloomFilter adds a token hash to the bloom filter in Redis.
func (c *RevocationRedisCache) addToBloomFilter(ctx context.Context, tokenHash string) error {
	// Get current filter
	filter, err := c.GetBloomFilter(ctx)
	if err != nil {
		return err
	}

	if filter == nil {
		// Create new filter
		filter = bloom.NewWithParams(c.config.BloomFilterSize, c.config.BloomFilterHashCount)
	}

	// Add token hash
	filter.Put([]byte(tokenHash))

	// Save back
	return c.SaveBloomFilter(ctx, filter, 0)
}

// checkBloomFilter checks if a token hash might be in the bloom filter.
func (c *RevocationRedisCache) checkBloomFilter(ctx context.Context, tokenHash string) (bool, error) {
	filter, err := c.GetBloomFilter(ctx)
	if err != nil {
		return false, err
	}

	if filter == nil {
		return false, nil
	}

	return filter.Test([]byte(tokenHash)), nil
}

// GetRevocationList returns the complete revocation list for API response.
func (c *RevocationRedisCache) GetRevocationList(ctx context.Context) (*RevocationList, error) {
	filter, err := c.GetBloomFilter(ctx)
	if err != nil {
		return nil, err
	}

	if filter == nil {
		filter = bloom.NewWithParams(c.config.BloomFilterSize, c.config.BloomFilterHashCount)
	}

	users, err := c.GetAllRevokedUsers(ctx)
	if err != nil {
		return nil, err
	}

	return &RevocationList{
		RevokedTokens: filter.ToJSON(),
		RevokedUsers:  users,
	}, nil
}

// SyncFromDatabase syncs the Redis cache from the database.
// This should be called periodically by a background worker.
func (c *RevocationRedisCache) SyncFromDatabase(ctx context.Context, store *RevocationStore) error {
	// Get all active revoked tokens from DB
	var tokens []RevokedToken
	err := store.db.WithContext(ctx).
		Where("expires_at > ?", time.Now().UTC()).
		Find(&tokens).Error
	if err != nil {
		return fmt.Errorf("failed to fetch revoked tokens: %w", err)
	}

	// Build bloom filter
	filter := bloom.NewWithParams(c.config.BloomFilterSize, c.config.BloomFilterHashCount)
	for _, t := range tokens {
		filter.Put([]byte(t.TokenHash))

		// Also store individual token keys
		ttl := time.Until(t.ExpiresAt)
		if ttl > 0 {
			key := c.key(revokedTokensKeyPrefix + t.TokenHash)
			_ = c.client.Do(ctx, c.client.B().Set().Key(key).Value("1").Ex(ttl).Build())
		}
	}

	// Save bloom filter
	if err := c.SaveBloomFilter(ctx, filter, len(tokens)); err != nil {
		return fmt.Errorf("failed to save bloom filter: %w", err)
	}

	// Get all active revoked users from DB
	var users []RevokedUser
	err = store.db.WithContext(ctx).
		Where("expires_at > ?", time.Now().UTC()).
		Find(&users).Error
	if err != nil {
		return fmt.Errorf("failed to fetch revoked users: %w", err)
	}

	// Clear and rebuild revoked users hash
	_ = c.client.Do(ctx, c.client.B().Del().Key(c.key(revokedUsersKey)).Build())

	for _, u := range users {
		if err := c.AddRevokedUser(ctx, u.UserID, u.RevokedAt, u.ExpiresAt); err != nil {
			return fmt.Errorf("failed to add revoked user: %w", err)
		}
	}

	return nil
}

// Ping checks if Redis is reachable.
func (c *RevocationRedisCache) Ping(ctx context.Context) error {
	res := c.client.Do(ctx, c.client.B().Ping().Build())
	return res.Error()
}

// GetStats returns cache statistics.
func (c *RevocationRedisCache) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get bloom filter meta
	metaRes := c.client.Do(ctx, c.client.B().Get().Key(c.key(bloomFilterMetaKey)).Build())
	if metaRes.Error() == nil {
		metaStr, _ := metaRes.ToString()
		if metaStr != "" {
			var meta BloomFilterMeta
			if json.Unmarshal([]byte(metaStr), &meta) == nil {
				stats["bloom_filter_size"] = meta.M
				stats["bloom_filter_hash_count"] = meta.K
				stats["bloom_filter_token_count"] = meta.TokenCount
				stats["bloom_filter_updated_at"] = meta.UpdatedAt
			}
		}
	}

	// Get revoked users count
	usersCountRes := c.client.Do(ctx, c.client.B().Hlen().Key(c.key(revokedUsersKey)).Build())
	if usersCountRes.Error() == nil {
		count, _ := usersCountRes.ToInt64()
		stats["revoked_users_count"] = count
	}

	// Count revoked tokens (approximate via KEYS - use cautiously in production)
	stats["cache_type"] = "redis"

	return stats, nil
}

// BuildBloomFilterFromTokens builds a new bloom filter from the given tokens.
func (c *RevocationRedisCache) BuildBloomFilterFromTokens(tokens []RevokedToken) *bloom.Filter {
	filter := bloom.NewWithParams(c.config.BloomFilterSize, c.config.BloomFilterHashCount)
	for _, t := range tokens {
		filter.Put([]byte(t.TokenHash))
	}
	return filter
}

// SetBloomFilterSize updates the bloom filter size in config.
func (c *RevocationRedisCache) SetBloomFilterSize(size uint) {
	c.config.BloomFilterSize = size
}

// SetBloomFilterHashCount updates the bloom filter hash count in config.
func (c *RevocationRedisCache) SetBloomFilterHashCount(count uint) {
	c.config.BloomFilterHashCount = count
}

// IncrementTokenCount atomically increments the token count in bloom filter meta.
func (c *RevocationRedisCache) IncrementTokenCount(ctx context.Context) error {
	// Get current meta
	metaRes := c.client.Do(ctx, c.client.B().Get().Key(c.key(bloomFilterMetaKey)).Build())

	var meta BloomFilterMeta
	if metaRes.Error() == nil {
		metaStr, _ := metaRes.ToString()
		if metaStr != "" {
			_ = json.Unmarshal([]byte(metaStr), &meta)
		}
	}

	if meta.M == 0 {
		meta.M = c.config.BloomFilterSize
		meta.K = c.config.BloomFilterHashCount
	}

	meta.TokenCount++
	meta.UpdatedAt = time.Now().UTC()

	metaData, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return c.client.Do(ctx, c.client.B().Set().Key(c.key(bloomFilterMetaKey)).Value(string(metaData)).Build()).Error()
}

// Helper to convert int64 to string
func int64ToString(n int64) string {
	return strconv.FormatInt(n, 10)
}
