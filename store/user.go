package store

import (
	"context"
	"fmt"
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
// Returns the created userID.
func (s *UserStore) CreateHeadAccount(ctx context.Context, accountID, username, passwordHash string, email, country *string) (string, error) {
	userID := models.LegitID()
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`INSERT INTO accounts(id, username, password_hash, account_type, email, country) VALUES(?,?,?,?,?,?)`, accountID, username, passwordHash, string(models.AccountHead), email, country).Error; err != nil {
			return err
		}
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
	if err != nil {
		return "", err
	}
	return userID, nil
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
		// Get BODY user info before moving
		var bodyUser struct {
			ID                string
			ProviderType      *string
			ProviderAccountID *string
		}
		if err := tx.Raw(`
			SELECT u.id, u.provider_type, u.provider_account_id FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.namespace = ? AND u.user_type = 'BODY' LIMIT 1
		`, headlessAccountID, namespace).Scan(&bodyUser).Error; err != nil {
			return fmt.Errorf("failed to get body user: %w", err)
		}

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

		now := time.Now()
		transactionID := models.LegitID()
		description := fmt.Sprintf("linking headless account %s to head account %s", headlessAccountID, headAccountID)

		// Record in account_transactions
		if err := tx.Exec(`
			INSERT INTO account_transactions(id, account_id, action, namespace, description, created_at)
			VALUES(?, ?, ?, ?, ?, ?)
		`, transactionID, headAccountID, "LINK", namespace, description, now).Error; err != nil {
			return fmt.Errorf("failed to record transaction: %w", err)
		}

		// Record in account_transaction_histories
		if err := tx.Exec(`
			INSERT INTO account_transaction_histories(id, transaction_id, user_id, account_id, from_account_id, to_account_id, provider_type, provider_account_id, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, models.LegitID(), transactionID, bodyUser.ID, headAccountID, headlessAccountID, headAccountID, bodyUser.ProviderType, bodyUser.ProviderAccountID, now).Error; err != nil {
			return fmt.Errorf("failed to record transaction history: %w", err)
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

// UnlinkNamespace separates BODY users from a FULL account back to the original HEADLESS account.
// This reverses the Link operation for a specific namespace.
// The original HEADLESS account is found from account_transaction_histories.
func (s *UserStore) UnlinkNamespace(ctx context.Context, fullAccountID, namespace string) (restoredHeadlessAccountID string, err error) {
	err = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Verify the account is FULL type
		var accountType string
		if err := tx.Raw(`SELECT account_type FROM accounts WHERE id = ?`, fullAccountID).Row().Scan(&accountType); err != nil {
			return fmt.Errorf("account not found: %w", err)
		}
		if accountType != string(models.AccountFull) {
			return fmt.Errorf("account is not FULL type, cannot unlink")
		}

		// 2. Find the original HEADLESS account from account_transaction_histories
		// Get the most recent LINK transaction for this account and namespace
		var originalHeadlessID string
		var providerType, providerAccountID *string
		err := tx.Raw(`
			SELECT ath.from_account_id, ath.provider_type, ath.provider_account_id
			FROM account_transaction_histories ath
			JOIN account_transactions at ON at.id = ath.transaction_id
			WHERE at.account_id = ? AND at.namespace = ? AND at.action = 'LINK'
			ORDER BY ath.created_at DESC LIMIT 1
		`, fullAccountID, namespace).Row().Scan(&originalHeadlessID, &providerType, &providerAccountID)
		if err != nil || originalHeadlessID == "" {
			return fmt.Errorf("could not find original headless account for namespace %s in transaction history", namespace)
		}

		// 3. Verify the original account exists and is ORPHAN
		var originalAccountType string
		if err := tx.Raw(`SELECT account_type FROM accounts WHERE id = ?`, originalHeadlessID).Row().Scan(&originalAccountType); err != nil {
			return fmt.Errorf("original headless account not found: %w", err)
		}
		if originalAccountType != string(models.AccountOrphan) {
			return fmt.Errorf("original account is not ORPHAN type (current: %s), cannot restore", originalAccountType)
		}

		restoredHeadlessAccountID = originalHeadlessID
		now := time.Now()

		// 4. Find BODY users in the specified namespace
		var bodyUsers []struct {
			ID                string
			ProviderType      *string
			ProviderAccountID *string
		}
		if err := tx.Raw(`
			SELECT u.id, u.provider_type, u.provider_account_id
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.namespace = ? AND u.user_type = 'BODY'
		`, fullAccountID, namespace).Scan(&bodyUsers).Error; err != nil {
			return err
		}
		if len(bodyUsers) == 0 {
			return fmt.Errorf("no BODY users found in namespace %s", namespace)
		}

		// 5. Create UNLINK transaction record
		transactionID := models.LegitID()
		description := fmt.Sprintf("unlinking namespace %s from account %s, restoring to %s", namespace, fullAccountID, originalHeadlessID)
		if err := tx.Exec(`
			INSERT INTO account_transactions(id, account_id, action, namespace, description, created_at)
			VALUES(?, ?, ?, ?, ?, ?)
		`, transactionID, fullAccountID, "UNLINK", namespace, description, now).Error; err != nil {
			return fmt.Errorf("failed to record transaction: %w", err)
		}

		// 6. Move BODY users back to original HEADLESS account and record history
		for _, user := range bodyUsers {
			// Update account_users to point back to original account
			if err := tx.Exec(`
				UPDATE account_users SET account_id = ? WHERE user_id = ?
			`, originalHeadlessID, user.ID).Error; err != nil {
				return fmt.Errorf("failed to move user: %w", err)
			}

			// Record history for each user movement
			if err := tx.Exec(`
				INSERT INTO account_transaction_histories(id, transaction_id, user_id, account_id, from_account_id, to_account_id, provider_type, provider_account_id, created_at)
				VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, models.LegitID(), transactionID, user.ID, originalHeadlessID, fullAccountID, originalHeadlessID, user.ProviderType, user.ProviderAccountID, now).Error; err != nil {
				return fmt.Errorf("failed to record transaction history: %w", err)
			}
		}

		// 7. Restore original account to HEADLESS
		if err := tx.Exec(`UPDATE accounts SET account_type = ? WHERE id = ?`,
			string(models.AccountHeadless), originalHeadlessID).Error; err != nil {
			return fmt.Errorf("failed to restore headless account: %w", err)
		}

		// 8. Re-evaluate FULL account type
		var countResult struct {
			Count int64
		}
		if err := tx.Raw(`
			SELECT COUNT(*) as count FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
		`, fullAccountID).Scan(&countResult).Error; err != nil {
			return fmt.Errorf("failed to count remaining body users: %w", err)
		}

		newAccountType := models.AccountFull
		if countResult.Count == 0 {
			newAccountType = models.AccountHead
		}
		if err := tx.Exec(`UPDATE accounts SET account_type = ? WHERE id = ?`,
			string(newAccountType), fullAccountID).Error; err != nil {
			return fmt.Errorf("failed to update account type: %w", err)
		}

		// 9. Mark the link_code as unused (optional: allow re-linking)
		_ = tx.Exec(`
			UPDATE link_codes SET used = FALSE, used_by = NULL, used_at = NULL
			WHERE headless_account_id = ? AND namespace = ? AND used_by = ?
		`, originalHeadlessID, namespace, fullAccountID)

		return nil
	})
	return restoredHeadlessAccountID, err
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

// GetSignupStats returns signup statistics for the dashboard.
// If namespace is provided, counts unique accounts with users in that namespace.
// If namespace is empty, counts all accounts.
// HEAD and BODY users linked to the same account are counted as 1.
func (s *UserStore) GetSignupStats(ctx context.Context, namespace string) (*models.SignupStats, error) {
	stats := &models.SignupStats{}
	ns := strings.ToUpper(strings.TrimSpace(namespace))

	// Base query parts for namespace filtering
	// When namespace is specified, we count distinct accounts that have users in that namespace
	// The signup time is when the user was first linked to that namespace (MIN of account_users.created_at)
	var baseQuery, countQuery string
	var args []interface{}

	if ns != "" {
		// Namespace-specific: count distinct accounts with users in this namespace
		baseQuery = `
			SELECT COUNT(DISTINCT au.account_id) FROM account_users au
			INNER JOIN users u ON u.id = au.user_id
			WHERE u.namespace = $1`
		args = []interface{}{ns}
	} else {
		// Global: count all accounts
		baseQuery = `SELECT COUNT(*) FROM accounts`
		args = []interface{}{}
	}

	// Today's signups
	if ns != "" {
		countQuery = baseQuery + ` AND DATE(au.created_at AT TIME ZONE 'UTC') = DATE(NOW() AT TIME ZONE 'UTC')`
	} else {
		countQuery = baseQuery + ` WHERE DATE(created_at AT TIME ZONE 'UTC') = DATE(NOW() AT TIME ZONE 'UTC')`
	}
	err := s.DB.WithContext(ctx).Raw(countQuery, args...).Scan(&stats.Today).Error
	if err != nil {
		return nil, err
	}

	// This week's signups (last 7 days)
	if ns != "" {
		countQuery = baseQuery + ` AND au.created_at AT TIME ZONE 'UTC' >= (NOW() AT TIME ZONE 'UTC' - INTERVAL '7 days')`
	} else {
		countQuery = baseQuery + ` WHERE created_at AT TIME ZONE 'UTC' >= (NOW() AT TIME ZONE 'UTC' - INTERVAL '7 days')`
	}
	err = s.DB.WithContext(ctx).Raw(countQuery, args...).Scan(&stats.ThisWeek).Error
	if err != nil {
		return nil, err
	}

	// This month's signups
	if ns != "" {
		countQuery = baseQuery + ` AND DATE_TRUNC('month', au.created_at AT TIME ZONE 'UTC') = DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')`
	} else {
		countQuery = baseQuery + ` WHERE DATE_TRUNC('month', created_at AT TIME ZONE 'UTC') = DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')`
	}
	err = s.DB.WithContext(ctx).Raw(countQuery, args...).Scan(&stats.ThisMonth).Error
	if err != nil {
		return nil, err
	}

	// Monthly breakdown for the last 12 months
	type monthRow struct {
		Month string
		Count int64
	}
	var months []monthRow

	if ns != "" {
		// For namespace: group by month when user was linked to that namespace
		err = s.DB.WithContext(ctx).Raw(`
			SELECT TO_CHAR(DATE_TRUNC('month', au.created_at AT TIME ZONE 'UTC'), 'YYYY-MM') as month,
			       COUNT(DISTINCT au.account_id) as count
			FROM account_users au
			INNER JOIN users u ON u.id = au.user_id
			WHERE u.namespace = $1
			  AND au.created_at AT TIME ZONE 'UTC' >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '11 months'
			GROUP BY DATE_TRUNC('month', au.created_at AT TIME ZONE 'UTC')
			ORDER BY month ASC
		`, ns).Scan(&months).Error
	} else {
		// Global: group by account creation date
		err = s.DB.WithContext(ctx).Raw(`
			SELECT TO_CHAR(DATE_TRUNC('month', created_at AT TIME ZONE 'UTC'), 'YYYY-MM') as month,
			       COUNT(*) as count
			FROM accounts
			WHERE created_at AT TIME ZONE 'UTC' >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '11 months'
			GROUP BY DATE_TRUNC('month', created_at AT TIME ZONE 'UTC')
			ORDER BY month ASC
		`).Scan(&months).Error
	}
	if err != nil {
		return nil, err
	}

	stats.Monthly = make([]models.MonthCount, len(months))
	for i, m := range months {
		stats.Monthly[i] = models.MonthCount{Month: m.Month, Count: m.Count}
	}

	return stats, nil
}

// UpdateAccountEmailIfEmpty updates the account's email only if it's currently NULL.
// This is used to populate email from platform providers (e.g., Google) during login.
func (s *UserStore) UpdateAccountEmailIfEmpty(ctx context.Context, accountID string, email string) error {
	if accountID == "" || email == "" {
		return nil
	}
	return s.DB.WithContext(ctx).Exec(
		`UPDATE accounts SET email = ? WHERE id = ? AND email IS NULL`,
		email, accountID,
	).Error
}

// UpdateAccountCountryIfEmpty updates the account's country only if it's currently NULL.
// This is used to populate country from IP geolocation during login.
func (s *UserStore) UpdateAccountCountryIfEmpty(ctx context.Context, accountID string, country string) error {
	if accountID == "" || country == "" {
		return nil
	}
	return s.DB.WithContext(ctx).Exec(
		`UPDATE accounts SET country = ? WHERE id = ? AND country IS NULL`,
		country, accountID,
	).Error
}

// LinkConflictInfo contains information about conflicting platforms for merge.
type LinkConflictInfo struct {
	Namespace               string `json:"namespace"`
	SourceAccountID         string `json:"source_account_id"`
	SourceProviderType      string `json:"source_provider_type"`
	SourceProviderAccountID string `json:"source_provider_account_id"`
	TargetAccountID         string `json:"target_account_id"`
	TargetProviderType      string `json:"target_provider_type"`
	TargetProviderAccountID string `json:"target_provider_account_id"`
}

// LinkEligibility contains the result of link eligibility check.
type LinkEligibility struct {
	Eligible       bool              `json:"eligible"`
	Reason         string            `json:"reason,omitempty"`
	ConflictUserID string            `json:"conflict_user_id,omitempty"`
	Conflict       *LinkConflictInfo `json:"conflict,omitempty"`
}

// LinkedPlatform represents a platform account linked to a user.
type LinkedPlatform struct {
	UserID            string `json:"user_id"`
	Namespace         string `json:"namespace"`
	ProviderType      string `json:"provider_type"`
	ProviderAccountID string `json:"provider_account_id"`
	AccountID         string `json:"account_id"`
}

// GetAccountInfo returns account information by account ID.
func (s *UserStore) GetAccountInfo(ctx context.Context, accountID string) (*models.Account, error) {
	var account models.Account
	err := s.DB.WithContext(ctx).Raw(`
		SELECT id, username, email, country, account_type, created_at
		FROM accounts WHERE id = ?
	`, accountID).Scan(&account).Error
	if err != nil {
		return nil, err
	}
	if account.ID == "" {
		return nil, nil
	}
	return &account, nil
}

// GetAccountByUserID returns account information by user ID.
func (s *UserStore) GetAccountByUserID(ctx context.Context, userID string) (*models.Account, error) {
	var account models.Account
	err := s.DB.WithContext(ctx).Raw(`
		SELECT a.id, a.username, a.email, a.country, a.account_type, a.created_at
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		WHERE au.user_id = ?
	`, userID).Scan(&account).Error
	if err != nil {
		return nil, err
	}
	if account.ID == "" {
		return nil, nil
	}
	return &account, nil
}

// GetLinkedPlatforms returns all platform accounts linked to an account.
func (s *UserStore) GetLinkedPlatforms(ctx context.Context, accountID string) ([]LinkedPlatform, error) {
	var platforms []LinkedPlatform
	err := s.DB.WithContext(ctx).Raw(`
		SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id, au.account_id
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.provider_type IS NOT NULL
	`, accountID).Scan(&platforms).Error
	return platforms, err
}

// GetLinkedPlatformsByNamespace returns all platform accounts linked in a specific namespace.
func (s *UserStore) GetLinkedPlatformsByNamespace(ctx context.Context, accountID, namespace string) ([]LinkedPlatform, error) {
	var platforms []LinkedPlatform
	err := s.DB.WithContext(ctx).Raw(`
		SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id, au.account_id
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id = ? AND u.namespace = ? AND u.user_type = 'BODY' AND u.provider_type IS NOT NULL
	`, accountID, namespace).Scan(&platforms).Error
	return platforms, err
}

// CheckPlatformConflict checks if a platform account is already linked to another user.
// Returns the conflicting user ID if found.
func (s *UserStore) CheckPlatformConflict(ctx context.Context, namespace, providerType, providerAccountID string) (*LinkedPlatform, error) {
	var platform LinkedPlatform
	err := s.DB.WithContext(ctx).Raw(`
		SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id, au.account_id
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE u.namespace = ? AND u.provider_type = ? AND u.provider_account_id = ? AND u.orphaned = FALSE
	`, namespace, providerType, providerAccountID).Scan(&platform).Error
	if err != nil {
		return nil, err
	}
	if platform.UserID == "" {
		return nil, nil
	}
	return &platform, nil
}

// CheckLinkEligibility validates if a head account can link a headless account.
// Rules:
// 1. Head account must have email (full account requirement)
// 2. Headless account must exist and be of type HEADLESS
// 3. Head account must not already have a linked platform in the same namespace with different provider account
// 4. The platform from headless must not be linked to another account
func (s *UserStore) CheckLinkEligibility(ctx context.Context, namespace, headAccountID, headlessAccountID string) (*LinkEligibility, error) {
	// Check head account exists and has email
	headAccount, err := s.GetAccountInfo(ctx, headAccountID)
	if err != nil {
		return nil, err
	}
	if headAccount == nil {
		return &LinkEligibility{Eligible: false, Reason: "head_account_not_found"}, nil
	}
	if headAccount.Email == nil || *headAccount.Email == "" {
		return &LinkEligibility{Eligible: false, Reason: "head_account_requires_email"}, nil
	}

	// Check headless account exists and is HEADLESS type
	headlessAccount, err := s.GetAccountInfo(ctx, headlessAccountID)
	if err != nil {
		return nil, err
	}
	if headlessAccount == nil {
		return &LinkEligibility{Eligible: false, Reason: "headless_account_not_found"}, nil
	}
	if headlessAccount.AccountType != models.AccountHeadless {
		return &LinkEligibility{Eligible: false, Reason: "account_is_not_headless"}, nil
	}

	// Get headless account's platform info
	headlessPlatforms, err := s.GetLinkedPlatformsByNamespace(ctx, headlessAccountID, namespace)
	if err != nil {
		return nil, err
	}
	if len(headlessPlatforms) == 0 {
		return &LinkEligibility{Eligible: false, Reason: "headless_has_no_platform_in_namespace"}, nil
	}

	// Check if head account already has platform linked in same namespace
	headPlatforms, err := s.GetLinkedPlatformsByNamespace(ctx, headAccountID, namespace)
	if err != nil {
		return nil, err
	}

	// If head account already has ANY platform in this namespace, check for conflicts
	if len(headPlatforms) > 0 {
		headPlatform := headPlatforms[0]
		headlessPlatform := headlessPlatforms[0]

		// Build conflict info for merge API
		conflictInfo := &LinkConflictInfo{
			Namespace:               namespace,
			SourceAccountID:         headlessAccountID,
			SourceProviderType:      headlessPlatform.ProviderType,
			SourceProviderAccountID: headlessPlatform.ProviderAccountID,
			TargetAccountID:         headAccountID,
			TargetProviderType:      headPlatform.ProviderType,
			TargetProviderAccountID: headPlatform.ProviderAccountID,
		}

		// Same provider type and same account ID = already linked (exact same platform)
		if headPlatform.ProviderType == headlessPlatform.ProviderType &&
			headPlatform.ProviderAccountID == headlessPlatform.ProviderAccountID {
			return &LinkEligibility{
				Eligible: false,
				Reason:   "platform_already_linked",
			}, nil
		}

		// Same provider type but different account ID = not allowed (cannot have two different users on same platform)
		// This is NOT mergeable - just an error
		if headPlatform.ProviderType == headlessPlatform.ProviderType &&
			headPlatform.ProviderAccountID != headlessPlatform.ProviderAccountID {
			return &LinkEligibility{
				Eligible: false,
				Reason:   fmt.Sprintf("same_platform_already_linked: %s is already linked with different account", headPlatform.ProviderType),
			}, nil
		}

		// Different provider type in same namespace = conflict (e.g., Xbox vs PlayStation in TESTGAME)
		return &LinkEligibility{
			Eligible: false,
			Reason:   "conflict_different_platform_same_namespace",
			Conflict: conflictInfo,
		}, nil
	}

	return &LinkEligibility{Eligible: true}, nil
}

// GetHeadlessAccountByPlatform finds a headless account by platform credentials.
func (s *UserStore) GetHeadlessAccountByPlatform(ctx context.Context, namespace, providerType, providerAccountID string) (*models.Account, error) {
	var account models.Account
	err := s.DB.WithContext(ctx).Raw(`
		SELECT a.id, a.username, a.email, a.country, a.account_type, a.created_at
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		JOIN users u ON u.id = au.user_id
		WHERE u.namespace = ? AND u.provider_type = ? AND u.provider_account_id = ?
		  AND a.account_type = 'HEADLESS'
	`, namespace, providerType, providerAccountID).Scan(&account).Error
	if err != nil {
		return nil, err
	}
	if account.ID == "" {
		return nil, nil
	}
	return &account, nil
}

// ============================================================================
// Account Merge Types and Functions
// ============================================================================

// MergeConflict represents a conflict between source and target accounts in a namespace.
type MergeConflict struct {
	Namespace             string `json:"namespace"`
	SourceUserID          string `json:"source_user_id"`
	SourceProviderType    string `json:"source_provider_type"`
	SourceProviderAccount string `json:"source_provider_account"`
	TargetUserID          string `json:"target_user_id"`
	TargetProviderType    string `json:"target_provider_type"`
	TargetProviderAccount string `json:"target_provider_account"`
}

// ConflictResolution represents user's choice for resolving a merge conflict.
type ConflictResolution struct {
	Namespace string `json:"namespace"` // Conflicting namespace
	Keep      string `json:"keep"`      // "SOURCE" or "TARGET"
}

// MergeEligibility contains the result of merge eligibility check.
type MergeEligibility struct {
	Eligible   bool            `json:"eligible"`
	Reason     string          `json:"reason,omitempty"`
	Conflicts  []MergeConflict `json:"conflicts,omitempty"`
	Namespaces []string        `json:"namespaces"` // Namespaces that can be merged
}

// MergeResult contains the result of a merge operation.
type MergeResult struct {
	MergedNamespaces []string `json:"merged_namespaces"`
	OrphanedUsers    []string `json:"orphaned_users"`
}

// CheckMergeEligibility checks if two accounts can be merged and returns any conflicts.
func (s *UserStore) CheckMergeEligibility(ctx context.Context, sourceAccountID, targetAccountID string) (*MergeEligibility, error) {
	// 1. Validate source account exists
	sourceAccount, err := s.GetAccountInfo(ctx, sourceAccountID)
	if err != nil {
		return nil, err
	}
	if sourceAccount == nil {
		return &MergeEligibility{Eligible: false, Reason: "source_account_not_found"}, nil
	}

	// 2. Validate target account exists and is HEAD or FULL
	targetAccount, err := s.GetAccountInfo(ctx, targetAccountID)
	if err != nil {
		return nil, err
	}
	if targetAccount == nil {
		return &MergeEligibility{Eligible: false, Reason: "target_account_not_found"}, nil
	}
	if targetAccount.AccountType != models.AccountHead && targetAccount.AccountType != models.AccountFull {
		return &MergeEligibility{Eligible: false, Reason: "target_must_be_head_or_full"}, nil
	}

	// 3. Cannot merge same account
	if sourceAccountID == targetAccountID {
		return &MergeEligibility{Eligible: false, Reason: "cannot_merge_same_account"}, nil
	}

	// 4. Get all BODY users from source account
	var sourceBodyUsers []struct {
		UserID            string
		Namespace         string
		ProviderType      *string
		ProviderAccountID *string
	}
	if err := s.DB.WithContext(ctx).Raw(`
		SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
	`, sourceAccountID).Scan(&sourceBodyUsers).Error; err != nil {
		return nil, err
	}

	if len(sourceBodyUsers) == 0 {
		return &MergeEligibility{Eligible: false, Reason: "source_has_no_body_users"}, nil
	}

	// 5. Get all BODY users from target account
	var targetBodyUsers []struct {
		UserID            string
		Namespace         string
		ProviderType      *string
		ProviderAccountID *string
	}
	if err := s.DB.WithContext(ctx).Raw(`
		SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id
		FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
	`, targetAccountID).Scan(&targetBodyUsers).Error; err != nil {
		return nil, err
	}

	// 6. Build target namespace map for conflict detection
	targetNamespaceMap := make(map[string]struct {
		UserID            string
		ProviderType      *string
		ProviderAccountID *string
	})
	for _, u := range targetBodyUsers {
		targetNamespaceMap[u.Namespace] = struct {
			UserID            string
			ProviderType      *string
			ProviderAccountID *string
		}{u.UserID, u.ProviderType, u.ProviderAccountID}
	}

	// 7. Check for conflicts
	var conflicts []MergeConflict
	var namespacesToMerge []string

	for _, sourceUser := range sourceBodyUsers {
		if targetUser, exists := targetNamespaceMap[sourceUser.Namespace]; exists {
			// Check if same platform type - this is NOT mergeable
			if sourceUser.ProviderType != nil && targetUser.ProviderType != nil &&
				*sourceUser.ProviderType == *targetUser.ProviderType {
				return &MergeEligibility{
					Eligible: false,
					Reason:   fmt.Sprintf("same_platform_not_mergeable: both accounts have %s in namespace %s", *sourceUser.ProviderType, sourceUser.Namespace),
				}, nil
			}

			// Different platform type - this is a mergeable conflict
			conflict := MergeConflict{
				Namespace:    sourceUser.Namespace,
				SourceUserID: sourceUser.UserID,
				TargetUserID: targetUser.UserID,
			}
			if sourceUser.ProviderType != nil {
				conflict.SourceProviderType = *sourceUser.ProviderType
			}
			if sourceUser.ProviderAccountID != nil {
				conflict.SourceProviderAccount = *sourceUser.ProviderAccountID
			}
			if targetUser.ProviderType != nil {
				conflict.TargetProviderType = *targetUser.ProviderType
			}
			if targetUser.ProviderAccountID != nil {
				conflict.TargetProviderAccount = *targetUser.ProviderAccountID
			}
			conflicts = append(conflicts, conflict)
		} else {
			namespacesToMerge = append(namespacesToMerge, sourceUser.Namespace)
		}
	}

	if len(conflicts) > 0 {
		return &MergeEligibility{
			Eligible:   false,
			Reason:     "conflict_detected",
			Conflicts:  conflicts,
			Namespaces: namespacesToMerge,
		}, nil
	}

	return &MergeEligibility{
		Eligible:   true,
		Namespaces: namespacesToMerge,
	}, nil
}

// Merge moves all BODY users from source account to target account.
// If there are conflicts, resolutions must be provided for each conflicting namespace.
func (s *UserStore) Merge(ctx context.Context, sourceAccountID, targetAccountID string, resolutions []ConflictResolution) (*MergeResult, error) {
	// Build resolution map
	resolutionMap := make(map[string]string)
	for _, r := range resolutions {
		resolutionMap[r.Namespace] = r.Keep
	}

	var result MergeResult
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()

		// 1. Get all BODY users from source account
		var sourceBodyUsers []struct {
			UserID            string
			Namespace         string
			ProviderType      *string
			ProviderAccountID *string
		}
		if err := tx.Raw(`
			SELECT u.id as user_id, u.namespace, u.provider_type, u.provider_account_id
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
		`, sourceAccountID).Scan(&sourceBodyUsers).Error; err != nil {
			return err
		}

		// 2. Get all BODY users from target account for conflict detection
		var targetBodyUsers []struct {
			UserID    string
			Namespace string
		}
		if err := tx.Raw(`
			SELECT u.id as user_id, u.namespace
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
		`, targetAccountID).Scan(&targetBodyUsers).Error; err != nil {
			return err
		}

		targetNamespaceUserMap := make(map[string]string)
		for _, u := range targetBodyUsers {
			targetNamespaceUserMap[u.Namespace] = u.UserID
		}

		// 3. Create MERGE transaction
		transactionID := models.LegitID()
		description := fmt.Sprintf("merged account %s into %s", sourceAccountID, targetAccountID)
		if err := tx.Exec(`
			INSERT INTO account_transactions(id, account_id, action, description, created_at)
			VALUES(?, ?, ?, ?, ?)
		`, transactionID, targetAccountID, "MERGE", description, now).Error; err != nil {
			return fmt.Errorf("failed to record merge transaction: %w", err)
		}

		// 4. Process each source BODY user
		for _, sourceUser := range sourceBodyUsers {
			targetUserID, hasConflict := targetNamespaceUserMap[sourceUser.Namespace]

			if hasConflict {
				// Check if resolution is provided
				resolution, hasResolution := resolutionMap[sourceUser.Namespace]
				if !hasResolution {
					return fmt.Errorf("conflict in namespace %s requires resolution", sourceUser.Namespace)
				}

				var winningUserID, losingUserID string
				var losingProviderType, losingProviderAccountID *string

				if resolution == "SOURCE" {
					// Keep source as primary
					winningUserID = sourceUser.UserID
					losingUserID = targetUserID

					// Get target's platform info for transfer
					var targetPlatform struct {
						ProviderType      *string
						ProviderAccountID *string
					}
					tx.Raw(`SELECT provider_type, provider_account_id FROM users WHERE id = ?`, targetUserID).Scan(&targetPlatform)
					losingProviderType = targetPlatform.ProviderType
					losingProviderAccountID = targetPlatform.ProviderAccountID

					// Move source BODY to target account
					if err := tx.Exec(`UPDATE account_users SET account_id = ? WHERE user_id = ?`,
						targetAccountID, sourceUser.UserID).Error; err != nil {
						return fmt.Errorf("failed to move user: %w", err)
					}
				} else { // TARGET
					// Keep target as primary
					winningUserID = targetUserID
					losingUserID = sourceUser.UserID
					losingProviderType = sourceUser.ProviderType
					losingProviderAccountID = sourceUser.ProviderAccountID
				}

				// Transfer platform_users record from losing user to winning user (AccelByte approach)
				// This allows both platforms to login and get the winning user ID
				if losingProviderType != nil && losingProviderAccountID != nil {
					if err := tx.Exec(`
						UPDATE platform_users SET user_id = ?
						WHERE user_id = ? AND namespace = ? AND platform_id = ?
					`, winningUserID, losingUserID, sourceUser.Namespace, *losingProviderType).Error; err != nil {
						// Non-fatal: platform_users record might not exist
					}
				}

				// Orphan the losing user (no longer needed for platform login)
				if err := tx.Exec(`UPDATE users SET orphaned = TRUE WHERE id = ?`, losingUserID).Error; err != nil {
					return fmt.Errorf("failed to orphan losing user: %w", err)
				}
				result.OrphanedUsers = append(result.OrphanedUsers, losingUserID)

				result.MergedNamespaces = append(result.MergedNamespaces, sourceUser.Namespace)

				// Record history
				if err := tx.Exec(`
					INSERT INTO account_transaction_histories(id, transaction_id, user_id, account_id, from_account_id, to_account_id, provider_type, provider_account_id, created_at)
					VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
				`, models.LegitID(), transactionID, winningUserID, targetAccountID, sourceAccountID, targetAccountID, sourceUser.ProviderType, sourceUser.ProviderAccountID, now).Error; err != nil {
					return fmt.Errorf("failed to record history: %w", err)
				}
			} else {
				// No conflict: move source BODY to target account
				if err := tx.Exec(`UPDATE account_users SET account_id = ? WHERE user_id = ?`,
					targetAccountID, sourceUser.UserID).Error; err != nil {
					return fmt.Errorf("failed to move user: %w", err)
				}
				result.MergedNamespaces = append(result.MergedNamespaces, sourceUser.Namespace)

				// Record history
				if err := tx.Exec(`
					INSERT INTO account_transaction_histories(id, transaction_id, user_id, account_id, from_account_id, to_account_id, provider_type, provider_account_id, created_at)
					VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
				`, models.LegitID(), transactionID, sourceUser.UserID, targetAccountID, sourceAccountID, targetAccountID, sourceUser.ProviderType, sourceUser.ProviderAccountID, now).Error; err != nil {
					return fmt.Errorf("failed to record history: %w", err)
				}
			}
		}

		// 5. Re-evaluate source account type (should become ORPHAN if no BODY users left)
		var sourceUserCount struct{ Count int64 }
		if err := tx.Raw(`
			SELECT COUNT(*) as count FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
		`, sourceAccountID).Scan(&sourceUserCount).Error; err != nil {
			return err
		}

		newSourceType := models.AccountOrphan
		if sourceUserCount.Count > 0 {
			// Still has some BODY users (possibly HEAD too)
			var hasHead int64
			tx.Raw(`SELECT COUNT(*) FROM users u JOIN account_users au ON au.user_id = u.id WHERE au.account_id = ? AND u.user_type = 'HEAD'`, sourceAccountID).Scan(&hasHead)
			if hasHead > 0 {
				newSourceType = models.AccountFull
				if sourceUserCount.Count == 0 {
					newSourceType = models.AccountHead
				}
			} else {
				newSourceType = models.AccountHeadless
			}
		}
		if err := tx.Exec(`UPDATE accounts SET account_type = ? WHERE id = ?`, string(newSourceType), sourceAccountID).Error; err != nil {
			return fmt.Errorf("failed to update source account type: %w", err)
		}

		// 6. Re-evaluate target account type (should be FULL if has BODY users)
		var targetBodyCount struct{ Count int64 }
		if err := tx.Raw(`
			SELECT COUNT(*) as count FROM users u
			JOIN account_users au ON au.user_id = u.id
			WHERE au.account_id = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
		`, targetAccountID).Scan(&targetBodyCount).Error; err != nil {
			return err
		}

		if targetBodyCount.Count > 0 {
			if err := tx.Exec(`UPDATE accounts SET account_type = ? WHERE id = ?`, string(models.AccountFull), targetAccountID).Error; err != nil {
				return fmt.Errorf("failed to update target account type: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return &result, nil
}
