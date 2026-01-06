package models

import (
	"encoding/json"
	"time"
)

// RoleType distinguishes user and client scoped roles
const (
	RoleTypeUser   = "USER"
	RoleTypeClient = "CLIENT"
)

// Role represents a namespace-scoped role with JSON permissions
// Permissions is stored as raw JSON bytes to avoid ORM map parsing issues.
type Role struct {
	ID          string          `gorm:"column:id;primaryKey"`
	Namespace   string          `gorm:"column:namespace;index"`
	Name        string          `gorm:"column:name"`
	RoleType    string          `gorm:"column:role_type"`
	Permissions json.RawMessage `gorm:"column:permissions"`
	Description string          `gorm:"column:description"`
	CreatedAt   time.Time       `gorm:"column:created_at"`
}

func (Role) TableName() string { return "roles" }

// UserRole links user to roles within a namespace
type UserRole struct {
	ID         string    `gorm:"column:id;primaryKey"`
	UserID     string    `gorm:"column:user_id;index"`
	RoleID     string    `gorm:"column:role_id;index"`
	Namespace  string    `gorm:"column:namespace;index"`
	AssignedAt time.Time `gorm:"column:assigned_at"`
}

func (UserRole) TableName() string { return "user_roles" }

// ClientRole links client to roles within a namespace
type ClientRole struct {
	ID         string    `gorm:"column:id;primaryKey"`
	ClientID   string    `gorm:"column:client_id;index"`
	RoleID     string    `gorm:"column:role_id;index"`
	Namespace  string    `gorm:"column:namespace;index"`
	AssignedAt time.Time `gorm:"column:assigned_at"`
}

func (ClientRole) TableName() string { return "client_roles" }
