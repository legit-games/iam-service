package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/google/uuid"
	valkey "github.com/valkey-io/valkey-go"
)

// ValkeyTokenStore stores tokens in Valkey (Redis-compatible).
type ValkeyTokenStore struct {
	client valkey.Client
	prefix string
}

// NewValkeyTokenStore creates a Valkey-backed token store.
// addr example: "127.0.0.1:6379"; prefix helps namespace keys.
func NewValkeyTokenStore(addr string, prefix string) (oauth2.TokenStore, error) {
	cli, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "oauth2:"
	}
	return &ValkeyTokenStore{client: cli, prefix: prefix}, nil
}

func (ts *ValkeyTokenStore) key(k string) string { return ts.prefix + k }

// Create stores token info; mirrors buntdb behavior with basicID indirection.
func (ts *ValkeyTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// Authorization code: store JSON under code:<code>
	if code := info.GetCode(); code != "" {
		ttl := info.GetCodeExpiresIn()
		return ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("code:"+code)).Value(string(jv)).Ex(ttl).Build()).Error()
	}

	basicID := uuid.Must(uuid.NewRandom()).String()
	// store JSON under data:<basicID>
	// TTL will align to rexp computed below
	aexp := info.GetAccessExpiresIn()
	rexp := aexp
	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
		if aexp > rexp {
			aexp = rexp
		}
		// map refresh -> basicID under refresh:<refresh>
		if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("refresh:"+refresh)).Value(basicID).Ex(rexp).Build()).Error(); err != nil {
			return err
		}
		// literal refresh token key
		_ = ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("refreshToken:"+refresh)).Value(refresh).Ex(rexp).Build()).Error()
	}
	// store JSON under data:<basicID>
	if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("data:"+basicID)).Value(string(jv)).Ex(rexp).Build()).Error(); err != nil {
		return err
	}
	// map access -> basicID under access:<access>
	if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("access:"+info.GetAccess())).Value(basicID).Ex(aexp).Build()).Error(); err != nil {
		return err
	}
	// literal access token key
	_ = ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("accessToken:"+info.GetAccess())).Value(info.GetAccess()).Ex(aexp).Build()).Error()
	return nil
}

// remove deletes key; missing is not an error
func (ts *ValkeyTokenStore) remove(ctx context.Context, key string) error {
	res := ts.client.Do(ctx, ts.client.B().Del().Key(ts.key(key)).Build())
	if res.Error() != nil {
		return res.Error()
	}
	return nil
}

func (ts *ValkeyTokenStore) RemoveByCode(ctx context.Context, code string) error {
	return ts.remove(ctx, "code:"+code)
}
func (ts *ValkeyTokenStore) RemoveByAccess(ctx context.Context, access string) error {
	// remove mapping and token-specific accessToken key
	_ = ts.client.Do(ctx, ts.client.B().Del().Key(ts.key("accessToken:"+access)).Build()).Error()
	return ts.remove(ctx, "access:"+access)
}
func (ts *ValkeyTokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	// remove mapping and token-specific refreshToken key
	_ = ts.client.Do(ctx, ts.client.B().Del().Key(ts.key("refreshToken:"+refresh)).Build()).Error()
	return ts.remove(ctx, "refresh:"+refresh)
}

func (ts *ValkeyTokenStore) getData(ctx context.Context, basicID string) (oauth2.TokenInfo, error) {
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("data:"+basicID)).Build())
	if res.Error() != nil {
		return nil, nil
	}
	val, err := res.ToString()
	if err != nil || val == "" {
		return nil, nil
	}
	var tm models.Token
	if err := json.Unmarshal([]byte(val), &tm); err != nil {
		return nil, err
	}
	return &tm, nil
}

func (ts *ValkeyTokenStore) getBasicID(ctx context.Context, purposeKey string) (string, error) {
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key(purposeKey)).Build())
	if res.Error() != nil {
		return "", nil
	}
	v, err := res.ToString()
	if err != nil || v == "" {
		return "", nil
	}
	return v, nil
}

func (ts *ValkeyTokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	// code stores JSON directly under code:<code>
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("code:"+code)).Build())
	if res.Error() != nil {
		return nil, nil
	}
	val, err := res.ToString()
	if err != nil || val == "" {
		return nil, nil
	}
	var tm models.Token
	if err := json.Unmarshal([]byte(val), &tm); err != nil {
		return nil, err
	}
	return &tm, nil
}

func (ts *ValkeyTokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(ctx, "access:"+access)
	if err != nil {
		return nil, err
	}
	if basicID == "" {
		return nil, nil
	}
	return ts.getData(ctx, basicID)
}

func (ts *ValkeyTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(ctx, "refresh:"+refresh)
	if err != nil {
		return nil, err
	}
	if basicID == "" {
		return nil, nil
	}
	return ts.getData(ctx, basicID)
}
