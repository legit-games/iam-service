package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupUserStoreTest(t *testing.T) *UserStore {
	// Use test database
	db, err := getTestGormDB()
	if err != nil {
		t.Fatal("Failed to setup test database:", err)
	}

	// Seed minimal required test data: accounts and users
	testAccountID := "test-account-123"
	testUserID := "test-user-456"
	actorAccountID := "actor-account-789"

	// Ensure accounts exist (password_hash required)
	if err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, 'testuser', 'x', 'HEAD') ON CONFLICT (id) DO NOTHING`, testAccountID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, 'actor', 'x', 'HEAD') ON CONFLICT (id) DO NOTHING`, actorAccountID).Error; err != nil {
		t.Fatal(err)
	}
	// Ensure users exist (one BODY under TESTNS for test user; one HEAD for actor)
	if err = db.Exec(`INSERT INTO users (id, account_id, namespace, user_type) VALUES (?, ?, 'TESTNS', 'BODY') ON CONFLICT (id) DO NOTHING`, testUserID, testAccountID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO users (id, account_id, user_type) VALUES ('actor-user-101', ?, 'HEAD') ON CONFLICT (id) DO NOTHING`, actorAccountID).Error; err != nil {
		t.Fatal(err)
	}

	return NewUserStore(db)
}

func getTestGormDB() (*gorm.DB, error) {
	// Get DSN from config (same as server tests)
	dsn := getTestDSN()
	if dsn == "" {
		return nil, fmt.Errorf("no test DSN available")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func getTestDSN() string {
	// This should use the same config as server tests
	// For now, use environment variable or default
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		// Default test database
		dsn = "postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable"
	}
	return dsn
}

func TestUserStore_BanUser(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name      string
		banType   models.BanType
		reason    string
		until     *time.Time
		expectErr bool
	}{
		{
			name:      "permanent ban success",
			banType:   models.BanPermanent,
			reason:    "Cheating detected",
			until:     nil,
			expectErr: false,
		},
		{
			name:      "timed ban success",
			banType:   models.BanTimed,
			reason:    "Harassment",
			until:     &[]time.Time{time.Now().Add(24 * time.Hour)}[0],
			expectErr: false,
		},
		{
			name:      "empty namespace should fail",
			banType:   models.BanPermanent,
			reason:    "Test",
			until:     nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans
			store.DB.Exec("DELETE FROM user_bans")
			store.DB.Exec("DELETE FROM user_ban_history")

			namespace := testNamespace
			if tt.name == "empty namespace should fail" {
				namespace = ""
			}

			err := store.BanUser(ctx, testUserID, namespace, tt.banType, tt.reason, tt.until, actorAccountID)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectErr {
				// Verify ban was created
				banned, err := store.IsUserBanned(ctx, testUserID, namespace)
				if err != nil {
					t.Errorf("Error checking ban status: %v", err)
				}
				if !banned {
					t.Errorf("Expected user to be banned")
				}

				// Verify history was created
				var historyCount int64
				store.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, namespace, "BAN").Count(&historyCount)
				if historyCount != 1 {
					t.Errorf("Expected 1 history entry, got %d", historyCount)
				}
			}
		})
	}
}

func TestUserStore_UnbanUser(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	// First, ban the user
	err := store.BanUser(ctx, testUserID, testNamespace, models.BanPermanent, "Test ban", nil, actorAccountID)
	if err != nil {
		t.Fatal(err)
	}

	// Now unban the user
	err = store.UnbanUser(ctx, testUserID, testNamespace, "Ban lifted", actorAccountID)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify user is no longer banned
	banned, err := store.IsUserBanned(ctx, testUserID, testNamespace)
	if err != nil {
		t.Errorf("Error checking ban status: %v", err)
	}
	if banned {
		t.Errorf("Expected user to be unbanned")
	}

	// Verify unban history was created
	var historyCount int64
	store.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, testNamespace, "UNBAN").Count(&historyCount)
	if historyCount != 1 {
		t.Errorf("Expected 1 unban history entry, got %d", historyCount)
	}
}

func TestUserStore_IsUserBanned(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name         string
		setupBan     func()
		expectBanned bool
	}{
		{
			name:         "no ban",
			setupBan:     func() {},
			expectBanned: false,
		},
		{
			name: "permanent ban",
			setupBan: func() {
				store.BanUser(ctx, testUserID, testNamespace, models.BanPermanent, "Permanent ban", nil, actorAccountID)
			},
			expectBanned: true,
		},
		{
			name: "active timed ban",
			setupBan: func() {
				futureTime := time.Now().Add(1 * time.Hour)
				store.BanUser(ctx, testUserID, testNamespace, models.BanTimed, "Active timed ban", &futureTime, actorAccountID)
			},
			expectBanned: true,
		},
		{
			name: "expired timed ban",
			setupBan: func() {
				pastTime := time.Now().Add(-1 * time.Hour)
				store.BanUser(ctx, testUserID, testNamespace, models.BanTimed, "Expired timed ban", &pastTime, actorAccountID)
			},
			expectBanned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans and history
			store.DB.Exec("DELETE FROM user_bans")
			store.DB.Exec("DELETE FROM user_ban_history")

			// Setup test scenario
			tt.setupBan()

			// Check ban status
			banned, err := store.IsUserBanned(ctx, testUserID, testNamespace)
			if err != nil {
				t.Errorf("Error checking ban status: %v", err)
			}

			if banned != tt.expectBanned {
				t.Errorf("Expected banned=%v, got %v", tt.expectBanned, banned)
			}
		})
	}
}

func TestUserStore_BanAccount(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testAccountID := "test-account-123"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name      string
		banType   models.BanType
		reason    string
		until     *time.Time
		expectErr bool
	}{
		{
			name:      "permanent account ban success",
			banType:   models.BanPermanent,
			reason:    "Account violation",
			until:     nil,
			expectErr: false,
		},
		{
			name:      "timed account ban success",
			banType:   models.BanTimed,
			reason:    "Temporary suspension",
			until:     &[]time.Time{time.Now().Add(48 * time.Hour)}[0],
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans
			store.DB.Exec("DELETE FROM account_bans")
			store.DB.Exec("DELETE FROM account_ban_history")

			err := store.BanAccount(ctx, testAccountID, tt.banType, tt.reason, tt.until, actorAccountID)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectErr {
				// Verify account ban was created
				banned, err := store.IsAccountBanned(ctx, testAccountID)
				if err != nil {
					t.Errorf("Error checking account ban status: %v", err)
				}
				if !banned {
					t.Errorf("Expected account to be banned")
				}

				// Verify history was created
				var historyCount int64
				store.DB.Model(&models.AccountBanHistory{}).Table("account_ban_history").Where("account_id = ? AND action = ?", testAccountID, "BAN").Count(&historyCount)
				if historyCount != 1 {
					t.Errorf("Expected 1 history entry, got %d", historyCount)
				}
			}
		})
	}
}

func TestUserStore_UnbanAccount(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testAccountID := "test-account-123"
	actorAccountID := "actor-account-789"

	// First, ban the account
	err := store.BanAccount(ctx, testAccountID, models.BanPermanent, "Test account ban", nil, actorAccountID)
	if err != nil {
		t.Fatal(err)
	}

	// Now unban the account
	err = store.UnbanAccount(ctx, testAccountID, "Account ban lifted", actorAccountID)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify account is no longer banned
	banned, err := store.IsAccountBanned(ctx, testAccountID)
	if err != nil {
		t.Errorf("Error checking account ban status: %v", err)
	}
	if banned {
		t.Errorf("Expected account to be unbanned")
	}

	// Verify unban history was created
	var historyCount int64
	store.DB.Model(&models.AccountBanHistory{}).Table("account_ban_history").Where("account_id = ? AND action = ?", testAccountID, "UNBAN").Count(&historyCount)
	if historyCount != 1 {
		t.Errorf("Expected 1 unban history entry, got %d", historyCount)
	}
}

func TestUserStore_IsAccountBanned(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testAccountID := "test-account-123"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name         string
		setupBan     func()
		expectBanned bool
	}{
		{
			name:         "no account ban",
			setupBan:     func() {},
			expectBanned: false,
		},
		{
			name: "permanent account ban",
			setupBan: func() {
				store.BanAccount(ctx, testAccountID, models.BanPermanent, "Permanent account ban", nil, actorAccountID)
			},
			expectBanned: true,
		},
		{
			name: "active timed account ban",
			setupBan: func() {
				futureTime := time.Now().Add(2 * time.Hour)
				store.BanAccount(ctx, testAccountID, models.BanTimed, "Active timed account ban", &futureTime, actorAccountID)
			},
			expectBanned: true,
		},
		{
			name: "expired timed account ban",
			setupBan: func() {
				pastTime := time.Now().Add(-2 * time.Hour)
				store.BanAccount(ctx, testAccountID, models.BanTimed, "Expired timed account ban", &pastTime, actorAccountID)
			},
			expectBanned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans and history
			store.DB.Exec("DELETE FROM account_bans")
			store.DB.Exec("DELETE FROM account_ban_history")

			// Setup test scenario
			tt.setupBan()

			// Check account ban status
			banned, err := store.IsAccountBanned(ctx, testAccountID)
			if err != nil {
				t.Errorf("Error checking account ban status: %v", err)
			}

			if banned != tt.expectBanned {
				t.Errorf("Expected banned=%v, got %v", tt.expectBanned, banned)
			}
		})
	}
}

func TestUserStore_IsUserBannedByAccount(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	testAccountID := "test-account-123"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name         string
		setupBan     func()
		expectBanned bool
		description  string
	}{
		{
			name:         "no ban",
			setupBan:     func() {},
			expectBanned: false,
			description:  "No ban should allow access",
		},
		{
			name: "user level ban",
			setupBan: func() {
				store.BanUser(ctx, testUserID, testNamespace, models.BanPermanent, "User level ban", nil, actorAccountID)
			},
			expectBanned: true,
			description:  "Direct user ban should block access",
		},
		{
			name: "account level ban",
			setupBan: func() {
				store.BanAccount(ctx, testAccountID, models.BanPermanent, "Account level ban", nil, actorAccountID)
			},
			expectBanned: true,
			description:  "Account ban should block all users under that account",
		},
		{
			name: "both user and account ban",
			setupBan: func() {
				store.BanUser(ctx, testUserID, testNamespace, models.BanPermanent, "User ban", nil, actorAccountID)
				store.BanAccount(ctx, testAccountID, models.BanPermanent, "Account ban", nil, actorAccountID)
			},
			expectBanned: true,
			description:  "Multiple bans should still block access",
		},
		{
			name: "expired user ban, active account ban",
			setupBan: func() {
				pastTime := time.Now().UTC().Add(-1 * time.Hour)
				futureTime := time.Now().UTC().Add(1 * time.Hour)
				store.BanUser(ctx, testUserID, testNamespace, models.BanTimed, "Expired user ban", &pastTime, actorAccountID)
				store.BanAccount(ctx, testAccountID, models.BanTimed, "Active account ban", &futureTime, actorAccountID)
			},
			expectBanned: true,
			description:  "Active account ban should block access even if user ban expired",
		},
		{
			name: "active user ban, expired account ban",
			setupBan: func() {
				futureTime := time.Now().UTC().Add(1 * time.Hour)
				pastTime := time.Now().UTC().Add(-1 * time.Hour)
				store.BanUser(ctx, testUserID, testNamespace, models.BanTimed, "Active user ban", &futureTime, actorAccountID)
				store.BanAccount(ctx, testAccountID, models.BanTimed, "Expired account ban", &pastTime, actorAccountID)
			},
			expectBanned: true,
			description:  "Active user ban should block access even if account ban expired",
		},
		{
			name: "both bans expired",
			setupBan: func() {
				pastTime1 := time.Now().UTC().Add(-2 * time.Hour)
				pastTime2 := time.Now().UTC().Add(-1 * time.Hour)
				store.BanUser(ctx, testUserID, testNamespace, models.BanTimed, "Expired user ban", &pastTime1, actorAccountID)
				store.BanAccount(ctx, testAccountID, models.BanTimed, "Expired account ban", &pastTime2, actorAccountID)
			},
			expectBanned: false,
			description:  "Expired bans should allow access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans and history
			store.DB.Exec("DELETE FROM user_bans")
			store.DB.Exec("DELETE FROM account_bans")
			store.DB.Exec("DELETE FROM user_ban_history")
			store.DB.Exec("DELETE FROM account_ban_history")

			// Setup test scenario
			tt.setupBan()

			// Check combined ban status
			banned, err := store.IsUserBannedByAccount(ctx, testUserID, testNamespace)
			if err != nil {
				t.Errorf("Error checking combined ban status: %v", err)
			}

			if banned != tt.expectBanned {
				t.Errorf("%s: Expected banned=%v, got %v", tt.description, tt.expectBanned, banned)
			}
		})
	}
}

func TestNamespaceNormalization(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	actorAccountID := "actor-account-789"

	// Test with different namespace cases
	namespaces := []string{"testns", "TESTNS", "TestNs", "tEsTnS"}

	for i, ns := range namespaces {
		t.Run("namespace_case_"+ns, func(t *testing.T) {
			// Clear bans and history
			store.DB.Exec("DELETE FROM user_bans")
			store.DB.Exec("DELETE FROM user_ban_history")

			// Ban with this namespace
			err := store.BanUser(ctx, testUserID, ns, models.BanPermanent, "Test ban", nil, actorAccountID)
			if err != nil {
				t.Errorf("Error banning user with namespace %s: %v", ns, err)
			}

			// Check if banned with normalized (uppercase) namespace
			banned, err := store.IsUserBanned(ctx, testUserID, "TESTNS")
			if err != nil {
				t.Errorf("Error checking ban status: %v", err)
			}

			if !banned {
				t.Errorf("Expected user to be banned with normalized namespace, case %d", i)
			}

			// Verify the namespace was stored in uppercase
			var storedNamespace string
			store.DB.Raw("SELECT namespace FROM user_bans WHERE user_id = ?", testUserID).Scan(&storedNamespace)
			if storedNamespace != "TESTNS" {
				t.Errorf("Expected namespace to be stored as 'TESTNS', got '%s'", storedNamespace)
			}
		})
	}
}

func TestConcurrentBanOperations(t *testing.T) {
	store := setupUserStoreTest(t)
	ctx := context.Background()

	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	// Clear all tables before test
	store.DB.Exec("DELETE FROM user_bans")
	store.DB.Exec("DELETE FROM user_ban_history")

	// Test concurrent ban operations
	done := make(chan bool, 2)

	// Concurrent ban
	go func() {
		err := store.BanUser(ctx, testUserID, testNamespace, models.BanPermanent, "Concurrent ban 1", nil, actorAccountID)
		if err != nil {
			t.Errorf("Error in concurrent ban 1: %v", err)
		}
		done <- true
	}()

	// Concurrent unban
	go func() {
		time.Sleep(10 * time.Millisecond) // Small delay to let first ban execute
		err := store.UnbanUser(ctx, testUserID, testNamespace, "Concurrent unban", actorAccountID)
		if err != nil {
			t.Errorf("Error in concurrent unban: %v", err)
		}
		done <- true
	}()

	// Wait for both operations to complete
	<-done
	<-done

	// Verify final state (should be unbanned due to unban operation)
	banned, err := store.IsUserBanned(ctx, testUserID, testNamespace)
	if err != nil {
		t.Errorf("Error checking final ban status: %v", err)
	}

	if banned {
		t.Errorf("Expected user to be unbanned after concurrent operations")
	}

	// Verify history entries were created for both operations
	var banHistoryCount, unbanHistoryCount int64
	store.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, testNamespace, "BAN").Count(&banHistoryCount)
	store.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, testNamespace, "UNBAN").Count(&unbanHistoryCount)

	if banHistoryCount != 1 {
		t.Errorf("Expected 1 ban history entry, got %d", banHistoryCount)
	}
	if unbanHistoryCount != 1 {
		t.Errorf("Expected 1 unban history entry, got %d", unbanHistoryCount)
	}
}
