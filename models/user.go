package models

import "time"

// AccountType represents the state of an account relative to its users.
type AccountType string

const (
	AccountHead     AccountType = "HEAD"
	AccountHeadless AccountType = "HEADLESS"
	AccountFull     AccountType = "FULL"
	AccountOrphan   AccountType = "ORPHAN"
)

// Account represents an account in the IAM system.
type Account struct {
	ID           string      `json:"id" db:"id"`
	Username     string      `json:"username" db:"username"`
	PasswordHash string      `json:"-" db:"password_hash"` // Never expose in JSON
	AccountType  AccountType `json:"account_type" db:"account_type"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
}

// AccountUser represents the bridge table linking accounts and users.
type AccountUser struct {
	AccountID string    `json:"account_id" db:"account_id"`
	UserID    string    `json:"user_id" db:"user_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// UserType indicates how a user was created.
type UserType string

const (
	UserHead UserType = "HEAD"
	UserBody UserType = "BODY"
)

// BanType represents the type of ban.
type BanType string

const (
	BanPermanent BanType = "PERMANENT"
	BanTimed     BanType = "TIMED"
)

// User represents a user belonging to an account, optionally scoped to a namespace and provider.
// The relationship to account is managed through the account_users bridge table.
type User struct {
	ID                string    `json:"id" db:"id"`
	Namespace         *string   `json:"namespace,omitempty" db:"namespace"`
	UserType          UserType  `json:"user_type" db:"user_type"`
	DisplayName       *string   `json:"display_name,omitempty" db:"display_name"`
	ProviderType      *string   `json:"provider_type,omitempty" db:"provider_type"`
	ProviderAccountID *string   `json:"provider_account_id,omitempty" db:"provider_account_id"`
	Orphaned          bool      `json:"orphaned" db:"orphaned"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// UserBan represents a ban entry for a user in a specific namespace.
type UserBan struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Namespace string    `json:"namespace" db:"namespace"`
	Type      BanType   `json:"type" db:"type"`
	Reason    string    `json:"reason" db:"reason"`
	Until     time.Time `json:"until" db:"until"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// UserBanHistory stores ban/unban audit history.
type UserBanHistory struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Namespace string    `json:"namespace" db:"namespace"`
	Action    string    `json:"action" db:"action"` // BAN or UNBAN
	Type      BanType   `json:"type" db:"type"`
	Reason    string    `json:"reason" db:"reason"`
	Until     time.Time `json:"until" db:"until"`
	ActorID   string    `json:"actor_id" db:"actor_id"` // who performed the ban
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// AccountBan represents a ban entry for an account (affects all users under the account).
type AccountBan struct {
	ID        string    `json:"id" db:"id"`
	AccountID string    `json:"account_id" db:"account_id"`
	Type      BanType   `json:"type" db:"type"`
	Reason    string    `json:"reason" db:"reason"`
	Until     time.Time `json:"until" db:"until"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// AccountBanHistory stores account ban/unban audit history.
type AccountBanHistory struct {
	ID        string    `json:"id" db:"id"`
	AccountID string    `json:"account_id" db:"account_id"`
	Action    string    `json:"action" db:"action"` // BAN or UNBAN
	Type      BanType   `json:"type" db:"type"`
	Reason    string    `json:"reason" db:"reason"`
	Until     time.Time `json:"until" db:"until"`
	ActorID   string    `json:"actor_id" db:"actor_id"` // who performed the ban
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ReevaluateAccountType determines the account type from a set of users.
func ReevaluateAccountType(users []User) AccountType {
	hasHead := false
	hasBody := false
	for _, u := range users {
		if u.UserType == UserHead && !u.Orphaned {
			hasHead = true
		}
		if u.UserType == UserBody && !u.Orphaned {
			hasBody = true
		}
	}
	switch {
	case !hasHead && !hasBody:
		return AccountOrphan
	case hasHead && !hasBody:
		return AccountHead
	case !hasHead && hasBody:
		return AccountHeadless
	default:
		return AccountFull
	}
}

// HeadNamespace returns nil to indicate the HEAD user has no namespace.
func HeadNamespace() *string { return nil }
