package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var userTestCounter int64 = time.Now().UnixNano()

func uniqueUserTestID(prefix string) string {
	userTestCounter++
	return fmt.Sprintf("%s-%d", prefix, userTestCounter)
}

func TestUserStore_GetUser_WithDisplayName(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create test data
	accountID := uniqueUserTestID("test-account")
	userID := uniqueUserTestID("test-user")
	displayName := "Test Display Name"

	// Insert test account
	err = gormDB.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, ?, '', 'HEAD')`, accountID, accountID).Error
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM accounts WHERE id = ?`, accountID)

	// Insert test user with display_name
	err = gormDB.Exec(`INSERT INTO users (id, user_type, display_name) VALUES (?, 'HEAD', ?)`, userID, displayName).Error
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM users WHERE id = ?`, userID)
	err = gormDB.Exec(`INSERT INTO account_users (account_id, user_id) VALUES (?, ?)`, accountID, userID).Error
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM account_users WHERE user_id = ?`, userID)

	// Get user and verify display_name
	user, err := store.GetUser(ctx, accountID, nil)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		t.Fatal("User should not be nil")
	}
	if user.DisplayName == nil {
		t.Fatal("DisplayName should not be nil")
	}
	if *user.DisplayName != displayName {
		t.Errorf("Expected DisplayName to be '%s', got '%s'", displayName, *user.DisplayName)
	}
}

func TestUserStore_GetUser_WithoutDisplayName(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create test data
	accountID := uniqueUserTestID("test-account-no-display")
	userID := uniqueUserTestID("test-user-no-display")

	// Insert test account
	err = gormDB.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, ?, '', 'HEAD')`, accountID, accountID).Error
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM accounts WHERE id = ?`, accountID)

	// Insert test user without display_name
	err = gormDB.Exec(`INSERT INTO users (id, user_type) VALUES (?, 'HEAD')`, userID).Error
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM users WHERE id = ?`, userID)
	err = gormDB.Exec(`INSERT INTO account_users (account_id, user_id) VALUES (?, ?)`, accountID, userID).Error
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM account_users WHERE user_id = ?`, userID)

	// Get user and verify display_name is nil
	user, err := store.GetUser(ctx, accountID, nil)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		t.Fatal("User should not be nil")
	}
	if user.DisplayName != nil {
		t.Errorf("DisplayName should be nil, got '%s'", *user.DisplayName)
	}
}

func TestUserStore_GetUser_BodyWithDisplayName(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create test data
	accountID := uniqueUserTestID("test-account-body")
	userID := uniqueUserTestID("test-user-body")
	namespace := "TESTNS"
	displayName := "Body User Display"

	// Insert test account
	err = gormDB.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, ?, '', 'HEADLESS')`, accountID, accountID).Error
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM accounts WHERE id = ?`, accountID)

	// Insert test BODY user with display_name
	err = gormDB.Exec(`INSERT INTO users (id, namespace, user_type, display_name) VALUES (?, ?, 'BODY', ?)`, userID, namespace, displayName).Error
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM users WHERE id = ?`, userID)
	err = gormDB.Exec(`INSERT INTO account_users (account_id, user_id) VALUES (?, ?)`, accountID, userID).Error
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer gormDB.Exec(`DELETE FROM account_users WHERE user_id = ?`, userID)

	// Get user by namespace and verify display_name
	user, err := store.GetUser(ctx, accountID, &namespace)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		t.Fatal("User should not be nil")
	}
	if user.DisplayName == nil {
		t.Fatal("DisplayName should not be nil")
	}
	if *user.DisplayName != displayName {
		t.Errorf("Expected DisplayName to be '%s', got '%s'", displayName, *user.DisplayName)
	}
	if user.UserType != "BODY" {
		t.Errorf("Expected UserType to be 'BODY', got '%s'", user.UserType)
	}
}
