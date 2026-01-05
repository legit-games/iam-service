package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// NewClientStore create client store (memory)
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]oauth2.ClientInfo),
	}
}

// ClientStore client information store (in-memory)
type ClientStore struct {
	sync.RWMutex
	data map[string]oauth2.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

// Set set client information
func (cs *ClientStore) Set(id string, cli oauth2.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return
}

// --- Persistent client store ---

type DBClientStore struct{ DB *gorm.DB }

func NewDBClientStore(db *gorm.DB) *DBClientStore { return &DBClientStore{DB: db} }

// Upsert creates or updates a client, including permissions and public flag.
func (s *DBClientStore) Upsert(ctx context.Context, c *models.Client) error {
	b, _ := json.Marshal(c.Permissions)
	return s.DB.WithContext(ctx).Exec(
		`INSERT INTO oauth2_clients(id, secret, domain, user_id, public, permissions)
		 VALUES(?,?,?,?,?,?::jsonb)
		 ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, domain=excluded.domain, user_id=excluded.user_id, public=excluded.public, permissions=excluded.permissions, updated_at=CURRENT_TIMESTAMP`,
		c.ID, c.Secret, c.Domain, c.UserID, c.Public, string(b),
	).Error
}

// UpdatePermissions replaces client's permissions.
func (s *DBClientStore) UpdatePermissions(ctx context.Context, clientID string, perms []string) error {
	b, _ := json.Marshal(perms)
	return s.DB.WithContext(ctx).Exec(`UPDATE oauth2_clients SET permissions=?::jsonb, updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(b), clientID).Error
}

// GetByID implements oauth2.ClientStore backed by DB (reads permissions/public as well).
func (s *DBClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var row struct {
		ID          string
		Secret      string
		Domain      string
		UserID      string
		Public      bool
		Permissions string
	}
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, secret, domain, user_id, public, permissions::text AS permissions FROM oauth2_clients WHERE id=?`, id).Scan(&row).Error; err != nil {
		return nil, err
	}
	if row.ID == "" {
		return nil, errors.New("not found")
	}
	var perms []string
	_ = json.Unmarshal([]byte(row.Permissions), &perms)
	return &models.Client{ID: row.ID, Secret: row.Secret, Domain: row.Domain, UserID: row.UserID, Public: row.Public, Permissions: perms}, nil
}

// List returns a page of clients ordered by id.
func (s *DBClientStore) List(ctx context.Context, offset, limit int) ([]models.Client, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	var rows []struct {
		ID          string
		Secret      string
		Domain      string
		UserID      string
		Public      bool
		Permissions string
	}
	if err := s.DB.WithContext(ctx).Raw(`SELECT id, secret, domain, user_id, public, permissions::text AS permissions FROM oauth2_clients ORDER BY id LIMIT ? OFFSET ?`, limit, offset).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]models.Client, 0, len(rows))
	for _, r := range rows {
		var perms []string
		_ = json.Unmarshal([]byte(r.Permissions), &perms)
		out = append(out, models.Client{ID: r.ID, Secret: r.Secret, Domain: r.Domain, UserID: r.UserID, Public: r.Public, Permissions: perms})
	}
	return out, nil
}

// Delete removes a client by id.
func (s *DBClientStore) Delete(ctx context.Context, id string) error {
	return s.DB.WithContext(ctx).Exec(`DELETE FROM oauth2_clients WHERE id=?`, id).Error
}
