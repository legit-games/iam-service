package store

import (
	"context"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// UserStore provides operations for users.
type UserStore struct {
	DB *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore { return &UserStore{DB: db} }

// CreateHeadAccount creates a HEAD account with a HEAD user (namespace=nil).
func (s *UserStore) CreateHeadAccount(ctx context.Context, accountID, username, passwordHash string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`INSERT INTO accounts(id, username, password_hash, account_type) VALUES(?,?,?,?)`, accountID, username, passwordHash, string(models.AccountHead)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO users(id, account_id, namespace, user_type, orphaned) VALUES(?,?,?,?,FALSE)`, models.LegitID(), accountID, nil, string(models.UserHead)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_transactions(id, account_id, action, created_at) VALUES(?,?,?,?)`, models.LegitID(), accountID, "CREATE_HEAD", time.Now()).Error; err != nil {
			return err
		}
		return nil
	})
}

// CreateHeadlessAccount creates a HEADLESS account and an initial BODY user for a namespace/provider.
func (s *UserStore) CreateHeadlessAccount(ctx context.Context, accountID, namespace, providerType, providerAccountID string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`INSERT INTO accounts(id, username, password_hash, account_type) VALUES(?,?,?,?)`, accountID, accountID, "", string(models.AccountHeadless)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO users(id, account_id, namespace, user_type, provider_type, provider_account_id, orphaned) VALUES(?,?,?,?,?,?,FALSE)`, models.LegitID(), accountID, namespace, string(models.UserBody), providerType, providerAccountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_transactions(id, account_id, action, namespace, created_at) VALUES(?,?,?,?,?)`, models.LegitID(), accountID, "CREATE_HEADLESS", namespace, time.Now()).Error; err != nil {
			return err
		}
		return nil
	})
}

// Link transfers BODY users from headless to head account within a namespace.
func (s *UserStore) Link(ctx context.Context, namespace string, headAccountID, headlessAccountID string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE users SET account_id=? WHERE account_id=? AND namespace=? AND user_type='BODY'`, headAccountID, headlessAccountID, namespace).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE accounts SET account_type='ORPHAN' WHERE id=?`, headlessAccountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE accounts SET account_type='FULL' WHERE id=?`, headAccountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_transactions(id, account_id, action, namespace, created_at) VALUES(?,?,?,?,?)`, models.LegitID(), headAccountID, "LINK", namespace, time.Now()).Error; err != nil {
			return err
		}
		return nil
	})
}

// Unlink removes provider from user; if orphaned, mark/remove according to policy, then reevaluate account type.
func (s *UserStore) Unlink(ctx context.Context, accountID, namespace, providerType, providerAccountID string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE users SET provider_type=NULL, provider_account_id=NULL, orphaned=TRUE WHERE account_id=? AND namespace=? AND provider_type=? AND provider_account_id=?`, accountID, namespace, providerType, providerAccountID).Error; err != nil {
			return err
		}
		type row struct {
			UserType string
			Orphaned bool
		}
		var rows []row
		if err := tx.Raw(`SELECT user_type, orphaned FROM users WHERE account_id=?`, accountID).Scan(&rows).Error; err != nil {
			return err
		}
		var users []models.User
		for _, r := range rows {
			users = append(users, models.User{UserType: models.UserType(r.UserType), Orphaned: r.Orphaned})
		}
		newType := models.ReevaluateAccountType(users)
		if err := tx.Exec(`UPDATE accounts SET account_type=? WHERE id=?`, string(newType), accountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_transactions(id, account_id, action, namespace, created_at) VALUES(?,?,?,?,?)`, models.LegitID(), accountID, "UNLINK", namespace, time.Now()).Error; err != nil {
			return err
		}
		return nil
	})
}

// GetUser returns HEAD user if namespace is empty, otherwise namespace-scoped user.
func (s *UserStore) GetUser(ctx context.Context, accountID string, namespace *string) (*models.User, error) {
	var u models.User
	q := `SELECT id, account_id, namespace, user_type, provider_type, provider_account_id, orphaned, created_at, updated_at FROM users WHERE account_id=? AND user_type='HEAD'`
	var args []interface{}
	args = append(args, accountID)
	if namespace != nil {
		q = `SELECT id, account_id, namespace, user_type, provider_type, provider_account_id, orphaned, created_at, updated_at FROM users WHERE account_id=? AND namespace=? AND user_type='BODY'`
		args = []interface{}{accountID, *namespace}
	}
	if err := s.DB.WithContext(ctx).Raw(q, args...).Scan(&u).Error; err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, nil
	}
	return &u, nil
}
