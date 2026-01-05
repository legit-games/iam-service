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

// UserType indicates how a user was created.
type UserType string

const (
	UserHead UserType = "HEAD"
	UserBody UserType = "BODY"
)

// User represents a user belonging to an account, optionally scoped to a namespace and provider.
type User struct {
	ID                string    `json:"id" db:"id"`
	AccountID         string    `json:"account_id" db:"account_id"`
	Namespace         *string   `json:"namespace,omitempty" db:"namespace"`
	UserType          UserType  `json:"user_type" db:"user_type"`
	ProviderType      *string   `json:"provider_type,omitempty" db:"provider_type"`
	ProviderAccountID *string   `json:"provider_account_id,omitempty" db:"provider_account_id"`
	Orphaned          bool      `json:"orphaned" db:"orphaned"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
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
