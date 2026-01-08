package store

import (
	"context"
	"strings"
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
		userID := models.LegitID()
		if err := tx.Exec(`INSERT INTO users(id, namespace, user_type, orphaned) VALUES(?,?,?,FALSE)`, userID, nil, string(models.UserHead)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_users(account_id, user_id) VALUES(?,?)`, accountID, userID).Error; err != nil {
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
		userID := models.LegitID()
		if err := tx.Exec(`INSERT INTO users(id, namespace, user_type, provider_type, provider_account_id, orphaned) VALUES(?,?,?,?,?,FALSE)`, userID, namespace, string(models.UserBody), providerType, providerAccountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_users(account_id, user_id) VALUES(?,?)`, accountID, userID).Error; err != nil {
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
		// Update account_users: move BODY users from headless to head account
		if err := tx.Exec(`
			UPDATE account_users SET account_id=?
			WHERE account_id=? AND user_id IN (
				SELECT u.id FROM users u
				JOIN account_users au ON au.user_id = u.id
				WHERE au.account_id=? AND u.namespace=? AND u.user_type='BODY'
			)`, headAccountID, headlessAccountID, headlessAccountID, namespace).Error; err != nil {
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
		// Update user through join with account_users
		if err := tx.Exec(`
			UPDATE users SET provider_type=NULL, provider_account_id=NULL, orphaned=TRUE
			WHERE id IN (
				SELECT u.id FROM users u
				JOIN account_users au ON au.user_id = u.id
				WHERE au.account_id=? AND u.namespace=? AND u.provider_type=? AND u.provider_account_id=?
			)`, accountID, namespace, providerType, providerAccountID).Error; err != nil {
			return err
		}
		type row struct {
			UserType string
			Orphaned bool
		}
		var rows []row
		if err := tx.Raw(`
			SELECT u.user_type, u.orphaned FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id=?`, accountID).Scan(&rows).Error; err != nil {
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
	q := `SELECT u.id, u.namespace, u.user_type, u.display_name, u.provider_type, u.provider_account_id, u.orphaned, u.created_at, u.updated_at
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id=? AND u.user_type='HEAD'`
	var args []interface{}
	args = append(args, accountID)
	if namespace != nil {
		q = `SELECT u.id, u.namespace, u.user_type, u.display_name, u.provider_type, u.provider_account_id, u.orphaned, u.created_at, u.updated_at
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id=? AND u.namespace=? AND u.user_type='BODY'`
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

// BanUser applies a ban to a user within a namespace with type and reason. For TIMED, until must be set.
func (s *UserStore) BanUser(ctx context.Context, userID, namespace string, btype models.BanType, reason string, until *time.Time, actorID string) error {
	ns := strings.ToUpper(strings.TrimSpace(namespace))
	if ns == "" {
		return gorm.ErrInvalidData
	}
	// Normalize type to uppercase to match query filters
	banTypeStr := strings.ToUpper(string(btype))
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		id := models.LegitID()
		var untilVal interface{}
		if until != nil {
			uv := until.UTC()
			untilVal = uv
		} else {
			untilVal = nil
		}
		// Use UTC for created_at
		createdAt := time.Now().UTC()
		if err := tx.Exec(`INSERT INTO user_bans(id, user_id, namespace, type, reason, until, created_at) VALUES(?,?,?,?,?,?,?)`, id, userID, ns, banTypeStr, reason, untilVal, createdAt).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO user_ban_history(id, user_id, namespace, action, type, reason, until, actor_id, created_at) VALUES(?,?,?,?,?,?,?,?,?)`, models.LegitID(), userID, ns, "BAN", banTypeStr, reason, untilVal, actorID, createdAt).Error; err != nil {
			return err
		}
		return nil
	})
}

// UnbanUser removes ban entries for a user within a namespace and logs history.
func (s *UserStore) UnbanUser(ctx context.Context, userID, namespace string, reason string, actorID string) error {
	ns := strings.ToUpper(strings.TrimSpace(namespace))
	if ns == "" {
		return gorm.ErrInvalidData
	}
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		createdAt := time.Now().UTC()
		if err := tx.Exec(`DELETE FROM user_bans WHERE user_id=? AND namespace=?`, userID, ns).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO user_ban_history(id, user_id, namespace, action, reason, actor_id, created_at) VALUES(?,?,?,?,?,?,?)`, models.LegitID(), userID, ns, "UNBAN", reason, actorID, createdAt).Error; err != nil {
			return err
		}
		return nil
	})
}

// IsUserBanned returns true if the user is currently banned in the given namespace.
func (s *UserStore) IsUserBanned(ctx context.Context, userID, namespace string) (bool, error) {
	ns := strings.ToUpper(strings.TrimSpace(namespace))
	if ns == "" {
		return false, nil
	}
	var count int64
	err := s.DB.WithContext(ctx).Raw(`SELECT COUNT(1) FROM user_bans WHERE user_id=$1 AND namespace=$2 AND (type='PERMANENT' OR (type='TIMED' AND (until IS NULL OR until AT TIME ZONE 'UTC' >= NOW() AT TIME ZONE 'UTC')))`, userID, ns).Scan(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// BanAccount applies a ban to an entire account, affecting all users under that account.
func (s *UserStore) BanAccount(ctx context.Context, accountID string, btype models.BanType, reason string, until *time.Time, actorID string) error {
	// Normalize type to uppercase to match query filters
	banTypeStr := strings.ToUpper(string(btype))
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		id := models.LegitID()
		var untilVal interface{}
		if until != nil {
			uv := until.UTC()
			untilVal = uv
		} else {
			untilVal = nil
		}
		createdAt := time.Now().UTC()
		if err := tx.Exec(`INSERT INTO account_bans(id, account_id, type, reason, until, created_at) VALUES(?,?,?,?,?,?)`, id, accountID, banTypeStr, reason, untilVal, createdAt).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_ban_history(id, account_id, action, type, reason, until, actor_id, created_at) VALUES(?,?,?,?,?,?,?,?)`, models.LegitID(), accountID, "BAN", banTypeStr, reason, untilVal, actorID, createdAt).Error; err != nil {
			return err
		}
		return nil
	})
}

// UnbanAccount removes ban entries for an account and logs history.
func (s *UserStore) UnbanAccount(ctx context.Context, accountID string, reason string, actorID string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		createdAt := time.Now().UTC()
		if err := tx.Exec(`DELETE FROM account_bans WHERE account_id=?`, accountID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO account_ban_history(id, account_id, action, reason, actor_id, created_at) VALUES(?,?,?,?,?,?)`, models.LegitID(), accountID, "UNBAN", reason, actorID, createdAt).Error; err != nil {
			return err
		}
		return nil
	})
}

// IsAccountBanned returns true if the account is currently banned.
func (s *UserStore) IsAccountBanned(ctx context.Context, accountID string) (bool, error) {
	var count int64
	err := s.DB.WithContext(ctx).Raw(`SELECT COUNT(1) FROM account_bans WHERE account_id=$1 AND (type='PERMANENT' OR (type='TIMED' AND (until IS NULL OR until AT TIME ZONE 'UTC' >= NOW() AT TIME ZONE 'UTC')))`, accountID).Scan(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// IsUserBannedByAccount returns true if the user is banned either directly or through account ban.
func (s *UserStore) IsUserBannedByAccount(ctx context.Context, userID, namespace string) (bool, error) {
	ns := strings.ToUpper(strings.TrimSpace(namespace))
	if ns == "" {
		return false, nil
	}

	// Check direct user ban first
	directBan, err := s.IsUserBanned(ctx, userID, namespace)
	if err != nil || directBan {
		return directBan, err
	}

	// Check account ban via account_users bridge table
	var accountID string
	row := s.DB.WithContext(ctx).Raw(`SELECT account_id FROM account_users WHERE user_id=?`, userID).Row()
	if err := row.Scan(&accountID); err != nil {
		return false, err
	}

	return s.IsAccountBanned(ctx, accountID)
}

// ListUserBans returns all bans for a user in a namespace
func (s *UserStore) ListUserBans(ctx context.Context, userID, namespace string) ([]models.UserBan, error) {
	ns := strings.ToUpper(strings.TrimSpace(namespace))
	var bans []models.UserBan
	err := s.DB.WithContext(ctx).Where("user_id = ? AND namespace = ?", userID, ns).Order("created_at DESC").Find(&bans).Error
	return bans, err
}

// ListAccountBans returns all bans for an account
func (s *UserStore) ListAccountBans(ctx context.Context, accountID string) ([]models.AccountBan, error) {
	var bans []models.AccountBan
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).Order("created_at DESC").Find(&bans).Error
	return bans, err
}
