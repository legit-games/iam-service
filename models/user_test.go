package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUserDisplayName(t *testing.T) {
	displayName := "John Doe"
	user := User{
		ID:          "user-123",
		AccountID:   "account-456",
		UserType:    UserHead,
		DisplayName: &displayName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if user.DisplayName == nil {
		t.Fatal("DisplayName should not be nil")
	}
	if *user.DisplayName != "John Doe" {
		t.Errorf("Expected DisplayName to be 'John Doe', got '%s'", *user.DisplayName)
	}
}

func TestUserDisplayNameNil(t *testing.T) {
	user := User{
		ID:          "user-123",
		AccountID:   "account-456",
		UserType:    UserHead,
		DisplayName: nil,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if user.DisplayName != nil {
		t.Errorf("DisplayName should be nil, got '%s'", *user.DisplayName)
	}
}

func TestUserDisplayNameJSONSerialization(t *testing.T) {
	displayName := "Test User"
	user := User{
		ID:          "user-123",
		AccountID:   "account-456",
		UserType:    UserHead,
		DisplayName: &displayName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["display_name"] != "Test User" {
		t.Errorf("Expected display_name to be 'Test User', got '%v'", result["display_name"])
	}
}

func TestUserDisplayNameJSONOmitEmpty(t *testing.T) {
	user := User{
		ID:          "user-123",
		AccountID:   "account-456",
		UserType:    UserHead,
		DisplayName: nil,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if _, exists := result["display_name"]; exists {
		t.Error("display_name should be omitted when nil")
	}
}

// ...existing code...

func TestBanType(t *testing.T) {
	tests := []struct {
		name     string
		banType  BanType
		expected string
	}{
		{"permanent ban", BanPermanent, "PERMANENT"},
		{"timed ban", BanTimed, "TIMED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.banType) != tt.expected {
				t.Errorf("Expected ban type %s, got %s", tt.expected, string(tt.banType))
			}
		})
	}
}

func TestUserBanValidation(t *testing.T) {
	testTime := time.Now().Add(24 * time.Hour)
	ban := UserBan{
		ID:        "test-ban-123",
		UserID:    "user-456",
		Namespace: "TESTNS",
		Type:      BanPermanent,
		Reason:    "Test ban",
		Until:     testTime,
		CreatedAt: time.Now(),
	}

	if ban.UserID != "user-456" {
		t.Errorf("Expected UserID to be user-456, got %s", ban.UserID)
	}

	if ban.Type != BanPermanent {
		t.Errorf("Expected Type to be PERMANENT, got %s", ban.Type)
	}

	if ban.Namespace != "TESTNS" {
		t.Errorf("Expected Namespace to be TESTNS, got %s", ban.Namespace)
	}
}

func TestAccountBanValidation(t *testing.T) {
	testTime := time.Now().Add(48 * time.Hour)
	ban := AccountBan{
		ID:        "test-account-ban-123",
		AccountID: "account-456",
		Type:      BanTimed,
		Reason:    "Account violation",
		Until:     testTime,
		CreatedAt: time.Now(),
	}

	if ban.AccountID != "account-456" {
		t.Errorf("Expected AccountID to be account-456, got %s", ban.AccountID)
	}

	if ban.Type != BanTimed {
		t.Errorf("Expected Type to be TIMED, got %s", ban.Type)
	}
}

func TestBanHistoryValidation(t *testing.T) {
	testTime := time.Now().Add(12 * time.Hour)
	history := UserBanHistory{
		ID:        "test-history-123",
		UserID:    "user-789",
		Namespace: "GAMENS",
		Action:    "BAN",
		Type:      BanTimed,
		Reason:    "Harassment",
		Until:     testTime,
		ActorID:   "admin-account-111",
		CreatedAt: time.Now(),
	}

	if history.Action != "BAN" {
		t.Errorf("Expected Action to be BAN, got %s", history.Action)
	}

	if history.ActorID != "admin-account-111" {
		t.Errorf("Expected ActorID to be admin-account-111, got %s", history.ActorID)
	}
}

func TestAccountBanHistoryValidation(t *testing.T) {
	history := AccountBanHistory{
		ID:        "test-account-history-123",
		AccountID: "account-999",
		Action:    "UNBAN",
		Reason:    "Appeal successful",
		ActorID:   "admin-account-222",
		CreatedAt: time.Now(),
	}

	if history.Action != "UNBAN" {
		t.Errorf("Expected Action to be UNBAN, got %s", history.Action)
	}

	if history.AccountID != "account-999" {
		t.Errorf("Expected AccountID to be account-999, got %s", history.AccountID)
	}
}
