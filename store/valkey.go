package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// tokenHash returns a stable hex sha256 for a token string.
func tokenHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

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
	clientID := info.GetClientID()
	// store JSON under data:<basicID>
	// TTL will align to rexp computed below
	aexp := info.GetAccessExpiresIn()
	rexp := aexp
	refresh := info.GetRefresh()
	access := info.GetAccess()

	if refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
		if aexp > rexp {
			aexp = rexp
		}
		// map by clientId and hashed refresh token
		refreshH := tokenHash(refresh)
		if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("client:"+clientID+":refresh:"+refreshH)).Value(basicID).Ex(rexp).Build()).Error(); err != nil {
			return err
		}
		// index refresh hash -> clientId for reverse lookup
		if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("idx:refresh:"+refreshH)).Value(clientID).Ex(rexp).Build()).Error(); err != nil {
			return err
		}
	}
	// store JSON under data:<basicID>
	if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("data:"+basicID)).Value(string(jv)).Ex(rexp).Build()).Error(); err != nil {
		return err
	}
	// map access by clientId and hashed access token
	if access != "" {
		accessH := tokenHash(access)
		if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("client:"+clientID+":access:"+accessH)).Value(basicID).Ex(aexp).Build()).Error(); err != nil {
			return err
		}
		// index access hash -> clientId for reverse lookup
		if err := ts.client.Do(ctx, ts.client.B().Set().Key(ts.key("idx:access:"+accessH)).Value(clientID).Ex(aexp).Build()).Error(); err != nil {
			return err
		}
	}
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
	if access == "" {
		return nil
	}
	h := tokenHash(access)
	// resolve clientId
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("idx:access:"+h)).Build())
	if res.Error() != nil {
		return nil
	}
	clientID, _ := res.ToString()
	if clientID == "" {
		return nil
	}
	// delete mapping and index
	_ = ts.remove(ctx, "client:"+clientID+":access:"+h)
	_ = ts.remove(ctx, "idx:access:"+h)
	return nil
}
func (ts *ValkeyTokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	if refresh == "" {
		return nil
	}
	h := tokenHash(refresh)
	// resolve clientId
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("idx:refresh:"+h)).Build())
	if res.Error() != nil {
		return nil
	}
	clientID, _ := res.ToString()
	if clientID == "" {
		return nil
	}
	// delete mapping and index
	_ = ts.remove(ctx, "client:"+clientID+":refresh:"+h)
	_ = ts.remove(ctx, "idx:refresh:"+h)
	return nil
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

func (ts *ValkeyTokenStore) getBasicIDByClientAndHash(ctx context.Context, typ string, clientID string, h string) (string, error) {
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("client:"+clientID+":"+typ+":"+h)).Build())
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
	if access == "" {
		return nil, nil
	}
	h := tokenHash(access)
	// find clientId via index
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("idx:access:"+h)).Build())
	if res.Error() != nil {
		return nil, nil
	}
	clientID, _ := res.ToString()
	if clientID == "" {
		return nil, nil
	}
	basicID, err := ts.getBasicIDByClientAndHash(ctx, "access", clientID, h)
	if err != nil {
		return nil, err
	}
	if basicID == "" {
		return nil, nil
	}
	return ts.getData(ctx, basicID)
}

func (ts *ValkeyTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}
	h := tokenHash(refresh)
	// find clientId via index
	res := ts.client.Do(ctx, ts.client.B().Get().Key(ts.key("idx:refresh:"+h)).Build())
	if res.Error() != nil {
		return nil, nil
	}
	clientID, _ := res.ToString()
	if clientID == "" {
		return nil, nil
	}
	basicID, err := ts.getBasicIDByClientAndHash(ctx, "refresh", clientID, h)
	if err != nil {
		return nil, err
	}
	if basicID == "" {
		return nil, nil
	}
	return ts.getData(ctx, basicID)
}
