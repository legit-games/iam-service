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

// ErrAuthorizationRequestNotFound indicates the authorization request was not found.
var ErrAuthorizationRequestNotFound = errors.New("authorization request not found")

// DefaultAuthRequestTTL is the default TTL for authorization requests (10 minutes).
const DefaultAuthRequestTTL = 10 * time.Minute

// AuthorizationRequestStore stores authorization requests in Valkey (Redis-compatible).
type AuthorizationRequestStore struct {
	client valkey.Client
	prefix string
	ttl    time.Duration
}

// NewAuthorizationRequestStore creates a Valkey-backed authorization request store.
func NewAuthorizationRequestStore(addr string, prefix string) (*AuthorizationRequestStore, error) {
	cli, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "iam:"
	}
	return &AuthorizationRequestStore{
		client: cli,
		prefix: prefix,
		ttl:    DefaultAuthRequestTTL,
	}, nil
}

// NewAuthorizationRequestStoreWithClient creates a store with an existing Valkey client.
func NewAuthorizationRequestStoreWithClient(client valkey.Client, prefix string) *AuthorizationRequestStore {
	if prefix == "" {
		prefix = "iam:"
	}
	return &AuthorizationRequestStore{
		client: client,
		prefix: prefix,
		ttl:    DefaultAuthRequestTTL,
	}
}

// SetTTL sets the TTL for authorization requests.
func (s *AuthorizationRequestStore) SetTTL(ttl time.Duration) {
	s.ttl = ttl
}

// key builds the Redis key for an authorization request.
func (s *AuthorizationRequestStore) key(requestID string) string {
	return fmt.Sprintf("%sauth_request:%s", s.prefix, requestID)
}

// Save stores an authorization request with TTL.
func (s *AuthorizationRequestStore) Save(ctx context.Context, req *models.AuthorizationRequest) error {
	if req.RequestID == "" {
		return errors.New("request_id is required")
	}

	// Set expiration time
	req.CreatedAt = time.Now().UTC()
	req.ExpiresAt = req.CreatedAt.Add(s.ttl)

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization request: %w", err)
	}

	key := s.key(req.RequestID)
	return s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(s.ttl).Build()).Error()
}

// Load retrieves an authorization request by request ID.
func (s *AuthorizationRequestStore) Load(ctx context.Context, requestID string) (*models.AuthorizationRequest, error) {
	key := s.key(requestID)

	res := s.client.Do(ctx, s.client.B().Get().Key(key).Build())
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return nil, ErrAuthorizationRequestNotFound
		}
		return nil, res.Error()
	}

	val, err := res.ToString()
	if err != nil || val == "" {
		return nil, ErrAuthorizationRequestNotFound
	}

	var req models.AuthorizationRequest
	if err := json.Unmarshal([]byte(val), &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization request: %w", err)
	}

	// Check if expired
	if req.IsExpired() {
		// Delete expired request
		_ = s.Delete(ctx, requestID)
		return nil, ErrAuthorizationRequestNotFound
	}

	return &req, nil
}

// Delete removes an authorization request.
func (s *AuthorizationRequestStore) Delete(ctx context.Context, requestID string) error {
	key := s.key(requestID)
	return s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error()
}

// Exists checks if an authorization request exists.
func (s *AuthorizationRequestStore) Exists(ctx context.Context, requestID string) (bool, error) {
	key := s.key(requestID)
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
