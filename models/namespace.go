package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NamespaceType is an enum-like string type representing namespace kind.
type NamespaceType string

const (
	NamespaceTypePublisher NamespaceType = "publisher"
	NamespaceTypeGame      NamespaceType = "game"
)

// IsValid returns true if t is one of the allowed constants.
func (t NamespaceType) IsValid() bool {
	s := strings.ToLower(string(t))
	return s == string(NamespaceTypePublisher) || s == string(NamespaceTypeGame)
}

// Normalize returns the canonical lowercase form if valid; otherwise returns original.
func (t NamespaceType) Normalize() NamespaceType {
	s := strings.ToLower(string(t))
	switch s {
	case string(NamespaceTypePublisher):
		return NamespaceTypePublisher
	case string(NamespaceTypeGame):
		return NamespaceTypeGame
	default:
		return t
	}
}

// UnmarshalJSON implements strict validation for NamespaceType.
func (t *NamespaceType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	nt := NamespaceType(s)
	if !nt.IsValid() {
		return fmt.Errorf("invalid namespace type: %q (allowed: 'publisher','game')", s)
	}
	*t = nt.Normalize()
	return nil
}

// Namespace represents a tenant/game/service scope.
type Namespace struct {
	ID          string        `json:"id" db:"id"`
	Name        string        `json:"name" db:"name"`
	Type        NamespaceType `json:"type" db:"type"` // 'publisher' or 'game'
	Description string        `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
}
