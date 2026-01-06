package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	valkey "github.com/valkey-io/valkey-go"
)

// ErrPlatformTokenNotFound indicates the platform token was not found in cache.
var ErrPlatformTokenNotFound = errors.New("platform token not found")

// PlatformTokenStore stores platform tokens in Valkey (Redis-compatible).
type PlatformTokenStore struct {
	client valkey.Client
	prefix string
}

// NewPlatformTokenStore creates a Valkey-backed platform token store.
func NewPlatformTokenStore(addr string, prefix string) (*PlatformTokenStore, error) {
	cli, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "iam:"
	}
	return &PlatformTokenStore{client: cli, prefix: prefix}, nil
}

// NewPlatformTokenStoreWithClient creates a platform token store with an existing Valkey client.
func NewPlatformTokenStoreWithClient(client valkey.Client, prefix string) *PlatformTokenStore {
	if prefix == "" {
		prefix = "iam:"
	}
	return &PlatformTokenStore{client: client, prefix: prefix}
}

// key builds the Redis key for a platform token.
// Format: <prefix>:<namespace>:<platformID>:<platformUserID>:token
func (s *PlatformTokenStore) key(namespace, platformID, platformUserID string) string {
	return fmt.Sprintf("%s%s:%s:%s:token", s.prefix, namespace, platformID, platformUserID)
}

// Save stores a platform token with TTL.
func (s *PlatformTokenStore) Save(ctx context.Context, namespace, platformID, platformUserID, token, sandboxID string, ttl time.Duration) error {
	platformToken := models.PlatformToken{
		ThirdPartyToken: token,
		SandboxID:       sandboxID,
	}

	data, err := json.Marshal(platformToken)
	if err != nil {
		return fmt.Errorf("failed to marshal platform token: %w", err)
	}

	key := s.key(namespace, platformID, platformUserID)
	return s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error()
}

// Load retrieves a platform token from cache.
func (s *PlatformTokenStore) Load(ctx context.Context, namespace, platformID, platformUserID string) (*models.PlatformToken, error) {
	key := s.key(namespace, platformID, platformUserID)

	res := s.client.Do(ctx, s.client.B().Get().Key(key).Build())
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return nil, ErrPlatformTokenNotFound
		}
		return nil, res.Error()
	}

	val, err := res.ToString()
	if err != nil || val == "" {
		return nil, ErrPlatformTokenNotFound
	}

	var platformToken models.PlatformToken
	if err := json.Unmarshal([]byte(val), &platformToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal platform token: %w", err)
	}

	return &platformToken, nil
}

// Delete removes a platform token from cache.
func (s *PlatformTokenStore) Delete(ctx context.Context, namespace, platformID, platformUserID string) error {
	key := s.key(namespace, platformID, platformUserID)
	return s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error()
}

// Exists checks if a platform token exists in cache.
func (s *PlatformTokenStore) Exists(ctx context.Context, namespace, platformID, platformUserID string) (bool, error) {
	key := s.key(namespace, platformID, platformUserID)
	res := s.client.Do(ctx, s.client.B().Exists().Key(key).Build())
	if res.Error() != nil {
		return false, res.Error()
	}
	count, err := res.AsInt64()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}