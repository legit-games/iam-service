package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

var linkTestCounter int64 = time.Now().UnixNano()

func uniqueLinkTestID(prefix string) string {
	linkTestCounter++
	return fmt.Sprintf("%s-%d", prefix, linkTestCounter)
}

// Helper to create a HEAD account for testing
func createTestHeadAccount(t *testing.T, store *UserStore, accountID string) string {
	ctx := context.Background()
	email := accountID + "@test.com"
	userID, err := store.CreateHeadAccount(ctx, accountID, accountID, "password", &email, nil)
	if err != nil {
		t.Fatalf("Failed to create HEAD account: %v", err)
	}
	return userID
}

// Helper to create a HEADLESS account for testing
func createTestHeadlessAccount(t *testing.T, store *UserStore, accountID, namespace, providerType, providerAccountID string) {
	ctx := context.Background()
	err := store.CreateHeadlessAccount(ctx, accountID, namespace, providerType, providerAccountID)
	if err != nil {
		t.Fatalf("Failed to create HEADLESS account: %v", err)
	}
}

// Helper to create platform_users record
func createTestPlatformUser(t *testing.T, db *gorm.DB, userID, namespace, platformID, platformUserID string) {
	id := models.LegitID()
	result := db.Exec(`INSERT INTO platform_users (id, user_id, namespace, platform_id, platform_user_id, linked_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NOW(), NOW(), NOW())`,
		id, userID, namespace, platformID, platformUserID)
	if result.Error != nil {
		t.Fatalf("Failed to create platform_users record: %v", result.Error)
	}
}

// Helper to get account type
func getAccountType(t *testing.T, store *UserStore, accountID string) string {
	var accountType string
	err := store.DB.Raw(`SELECT account_type FROM accounts WHERE id = ?`, accountID).Row().Scan(&accountType)
	if err != nil {
		t.Fatalf("Failed to get account type: %v", err)
	}
	return accountType
}

// Helper to check if platform_users record exists
func platformUserExists(store *UserStore, userID, namespace, platformID string) bool {
	var count int64
	store.DB.Raw(`SELECT COUNT(*) FROM platform_users WHERE user_id = ? AND namespace = ? AND platform_id = ?`, userID, namespace, platformID).Row().Scan(&count)
	return count > 0
}

// Helper to get BODY user ID for an account/namespace
func getBodyUserID(store *UserStore, accountID, namespace string) string {
	var userID string
	store.DB.Raw(`
		SELECT u.id FROM users u
		JOIN account_users au ON au.user_id = u.id
		WHERE au.account_id = ? AND u.namespace = ? AND u.user_type = 'BODY' AND u.orphaned = FALSE
	`, accountID, namespace).Row().Scan(&userID)
	return userID
}

// cleanupTestData cleans up test data created during tests
func cleanupLinkTestData(store *UserStore, accountIDs ...string) {
	for _, id := range accountIDs {
		store.DB.Exec(`DELETE FROM account_transaction_histories WHERE transaction_id IN (SELECT id FROM account_transactions WHERE account_id = ?)`, id)
		store.DB.Exec(`DELETE FROM account_transactions WHERE account_id = ?`, id)
		store.DB.Exec(`DELETE FROM link_codes WHERE head_account_id = ? OR headless_account_id = ?`, id, id)
		store.DB.Exec(`DELETE FROM platform_users WHERE user_id IN (SELECT user_id FROM account_users WHERE account_id = ?)`, id)
		store.DB.Exec(`DELETE FROM account_users WHERE account_id = ?`, id)
		store.DB.Exec(`DELETE FROM users WHERE id IN (SELECT user_id FROM account_users WHERE account_id = ?)`, id)
		store.DB.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	}
}

func TestUserStore_Link(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create test accounts
	headAccountID := uniqueLinkTestID("head")
	headlessAccountID := uniqueLinkTestID("headless")
	namespace := "TESTGAME"
	providerType := "steam"
	providerAccountID := "steam123"

	createTestHeadAccount(t, store, headAccountID)
	createTestHeadlessAccount(t, store, headlessAccountID, namespace, providerType, providerAccountID)
	defer cleanupLinkTestData(store, headAccountID, headlessAccountID)

	// Get BODY user ID before link
	bodyUserID := getBodyUserID(store, headlessAccountID, namespace)
	if bodyUserID == "" {
		t.Fatal("BODY user should exist in HEADLESS account")
	}

	// Create platform_users record for the BODY user
	createTestPlatformUser(t, gormDB, bodyUserID, namespace, providerType, providerAccountID)

	// Verify initial state
	if getAccountType(t, store, headAccountID) != "HEAD" {
		t.Fatal("HEAD account should be HEAD type")
	}
	if getAccountType(t, store, headlessAccountID) != "HEADLESS" {
		t.Fatal("HEADLESS account should be HEADLESS type")
	}

	// Execute Link
	err = store.Link(ctx, namespace, headAccountID, headlessAccountID)
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	// Verify post-link state
	if getAccountType(t, store, headAccountID) != "FULL" {
		t.Errorf("HEAD account should become FULL after link, got %s", getAccountType(t, store, headAccountID))
	}
	if getAccountType(t, store, headlessAccountID) != "ORPHAN" {
		t.Errorf("HEADLESS account should become ORPHAN after link, got %s", getAccountType(t, store, headlessAccountID))
	}

	// Verify BODY user is now in HEAD account
	movedUserID := getBodyUserID(store, headAccountID, namespace)
	if movedUserID != bodyUserID {
		t.Errorf("BODY user should be moved to HEAD account")
	}

	// Verify platform_users still exists (pointing to same user)
	if !platformUserExists(store, bodyUserID, namespace, providerType) {
		t.Error("platform_users record should still exist after Link")
	}
}

func TestUserStore_UnlinkNamespace(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create and link accounts first
	headAccountID := uniqueLinkTestID("head-unlink")
	headlessAccountID := uniqueLinkTestID("headless-unlink")
	namespace := "TESTGAME"
	providerType := "xbox"
	providerAccountID := "xbox456"

	createTestHeadAccount(t, store, headAccountID)
	createTestHeadlessAccount(t, store, headlessAccountID, namespace, providerType, providerAccountID)
	defer cleanupLinkTestData(store, headAccountID, headlessAccountID)

	// Get BODY user ID
	bodyUserID := getBodyUserID(store, headlessAccountID, namespace)
	createTestPlatformUser(t, gormDB, bodyUserID, namespace, providerType, providerAccountID)

	// Link first
	err = store.Link(ctx, namespace, headAccountID, headlessAccountID)
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	// Verify link succeeded
	if getAccountType(t, store, headAccountID) != "FULL" {
		t.Fatal("Account should be FULL after link")
	}

	// Execute UnlinkNamespace
	restoredID, err := store.UnlinkNamespace(ctx, headAccountID, namespace)
	if err != nil {
		t.Fatalf("UnlinkNamespace failed: %v", err)
	}

	// Verify restored account ID
	if restoredID != headlessAccountID {
		t.Errorf("Expected restored account ID %s, got %s", headlessAccountID, restoredID)
	}

	// Verify post-unlink state
	if getAccountType(t, store, headAccountID) != "HEAD" {
		t.Errorf("Account should be HEAD after unlink, got %s", getAccountType(t, store, headAccountID))
	}
	if getAccountType(t, store, headlessAccountID) != "HEADLESS" {
		t.Errorf("Restored account should be HEADLESS, got %s", getAccountType(t, store, headlessAccountID))
	}

	// Verify BODY user is back in HEADLESS account
	restoredBodyUserID := getBodyUserID(store, headlessAccountID, namespace)
	if restoredBodyUserID != bodyUserID {
		t.Error("BODY user should be back in HEADLESS account")
	}

	// Verify platform_users still exists (for UnlinkNamespace, we don't delete platform_users)
	if !platformUserExists(store, bodyUserID, namespace, providerType) {
		t.Error("platform_users record should still exist after UnlinkNamespace")
	}
}

func TestUserStore_Unlink(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create HEADLESS account
	headlessAccountID := uniqueLinkTestID("headless-unlink-platform")
	namespace := "TESTGAME"
	providerType := "ps5"
	providerAccountID := "ps5789"

	createTestHeadlessAccount(t, store, headlessAccountID, namespace, providerType, providerAccountID)
	defer cleanupLinkTestData(store, headlessAccountID)

	// Get BODY user ID
	bodyUserID := getBodyUserID(store, headlessAccountID, namespace)
	createTestPlatformUser(t, gormDB, bodyUserID, namespace, providerType, providerAccountID)

	// Verify platform_users exists
	if !platformUserExists(store, bodyUserID, namespace, providerType) {
		t.Fatal("platform_users should exist before Unlink")
	}

	// Execute Unlink (remove specific platform)
	err = store.Unlink(ctx, headlessAccountID, namespace, providerType, providerAccountID)
	if err != nil {
		t.Fatalf("Unlink failed: %v", err)
	}

	// Verify platform_users is deleted (AccelByte approach)
	if platformUserExists(store, bodyUserID, namespace, providerType) {
		t.Error("platform_users record should be deleted after Unlink")
	}

	// Verify user is orphaned
	var orphaned bool
	gormDB.Raw(`SELECT orphaned FROM users WHERE id = ?`, bodyUserID).Row().Scan(&orphaned)
	if !orphaned {
		t.Error("User should be orphaned after Unlink")
	}

	// Verify account type changed to ORPHAN
	if getAccountType(t, store, headlessAccountID) != "ORPHAN" {
		t.Errorf("Account should be ORPHAN after unlink, got %s", getAccountType(t, store, headlessAccountID))
	}
}

func TestUserStore_UnlinkNamespace_FailsForNonFullAccount(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create HEAD account (not FULL)
	headAccountID := uniqueLinkTestID("head-not-full")
	createTestHeadAccount(t, store, headAccountID)
	defer cleanupLinkTestData(store, headAccountID)

	// Try to UnlinkNamespace on non-FULL account
	_, err = store.UnlinkNamespace(ctx, headAccountID, "TESTGAME")
	if err == nil {
		t.Error("UnlinkNamespace should fail for non-FULL account")
	}
}

func TestUserStore_CheckLinkEligibility(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create accounts
	headAccountID := uniqueLinkTestID("head-elig")
	headlessAccountID := uniqueLinkTestID("headless-elig")
	namespace := "TESTGAME"

	createTestHeadAccount(t, store, headAccountID)
	createTestHeadlessAccount(t, store, headlessAccountID, namespace, "steam", "steam123")
	defer cleanupLinkTestData(store, headAccountID, headlessAccountID)

	// Check eligibility (params: namespace, headAccountID, headlessAccountID)
	eligibility, err := store.CheckLinkEligibility(ctx, namespace, headAccountID, headlessAccountID)
	if err != nil {
		t.Fatalf("CheckLinkEligibility failed: %v", err)
	}

	if !eligibility.Eligible {
		t.Errorf("Link should be eligible, reason: %s", eligibility.Reason)
	}
}

func TestUserStore_CheckLinkEligibility_Conflict(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create accounts - HEAD already has a linked HEADLESS for same namespace
	headAccountID := uniqueLinkTestID("head-conflict")
	headless1AccountID := uniqueLinkTestID("headless1-conflict")
	headless2AccountID := uniqueLinkTestID("headless2-conflict")
	namespace := "TESTGAME"

	createTestHeadAccount(t, store, headAccountID)
	createTestHeadlessAccount(t, store, headless1AccountID, namespace, "steam", "steam123")
	createTestHeadlessAccount(t, store, headless2AccountID, namespace, "xbox", "xbox456")
	defer cleanupLinkTestData(store, headAccountID, headless1AccountID, headless2AccountID)

	// Link first HEADLESS
	err = store.Link(ctx, namespace, headAccountID, headless1AccountID)
	if err != nil {
		t.Fatalf("First link failed: %v", err)
	}

	// Check eligibility for second HEADLESS (should have conflict)
	// params: namespace, headAccountID, headlessAccountID
	eligibility, err := store.CheckLinkEligibility(ctx, namespace, headAccountID, headless2AccountID)
	if err != nil {
		t.Fatalf("CheckLinkEligibility failed: %v", err)
	}

	if eligibility.Eligible {
		t.Error("Link should not be eligible due to conflict")
	}

	// Should have conflict info for different platform
	if eligibility.Conflict == nil {
		t.Errorf("Should have conflict info, got reason: %s", eligibility.Reason)
	}
}

func TestUserStore_Merge(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create two FULL accounts
	targetHeadID := uniqueLinkTestID("target-head")
	targetHeadlessID := uniqueLinkTestID("target-headless")
	sourceHeadID := uniqueLinkTestID("source-head")
	sourceHeadlessID := uniqueLinkTestID("source-headless")
	namespace1 := "GAME1"
	namespace2 := "GAME2"

	// Target account with GAME1
	createTestHeadAccount(t, store, targetHeadID)
	createTestHeadlessAccount(t, store, targetHeadlessID, namespace1, "steam", "steam-target")
	bodyUserTarget := getBodyUserID(store, targetHeadlessID, namespace1)
	createTestPlatformUser(t, gormDB, bodyUserTarget, namespace1, "steam", "steam-target")
	store.Link(ctx, namespace1, targetHeadID, targetHeadlessID)

	// Source account with GAME2
	createTestHeadAccount(t, store, sourceHeadID)
	createTestHeadlessAccount(t, store, sourceHeadlessID, namespace2, "xbox", "xbox-source")
	bodyUserSource := getBodyUserID(store, sourceHeadlessID, namespace2)
	createTestPlatformUser(t, gormDB, bodyUserSource, namespace2, "xbox", "xbox-source")
	store.Link(ctx, namespace2, sourceHeadID, sourceHeadlessID)

	defer cleanupLinkTestData(store, targetHeadID, targetHeadlessID, sourceHeadID, sourceHeadlessID)

	// Execute Merge (no conflict since different namespaces)
	result, err := store.Merge(ctx, sourceHeadID, targetHeadID, nil)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify merge result
	if len(result.MergedNamespaces) != 1 || result.MergedNamespaces[0] != namespace2 {
		t.Errorf("Expected merged namespace %s, got %v", namespace2, result.MergedNamespaces)
	}

	// Verify target account is still FULL
	if getAccountType(t, store, targetHeadID) != "FULL" {
		t.Errorf("Target account should still be FULL, got %s", getAccountType(t, store, targetHeadID))
	}

	// Verify source account is ORPHAN or HEAD (no more BODY users)
	sourceType := getAccountType(t, store, sourceHeadID)
	if sourceType != "HEAD" && sourceType != "ORPHAN" {
		t.Errorf("Source account should be HEAD or ORPHAN after merge, got %s", sourceType)
	}

	// Verify BODY user from source is now in target
	movedUserID := getBodyUserID(store, targetHeadID, namespace2)
	if movedUserID != bodyUserSource {
		t.Error("Source BODY user should be moved to target account")
	}
}

func TestUserStore_Merge_WithConflict(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create two FULL accounts with same namespace (conflict)
	targetHeadID := uniqueLinkTestID("target-head-conflict")
	targetHeadlessID := uniqueLinkTestID("target-headless-conflict")
	sourceHeadID := uniqueLinkTestID("source-head-conflict")
	sourceHeadlessID := uniqueLinkTestID("source-headless-conflict")
	namespace := "CONFLICTGAME"

	// Target account
	createTestHeadAccount(t, store, targetHeadID)
	createTestHeadlessAccount(t, store, targetHeadlessID, namespace, "steam", "steam-target")
	bodyUserTarget := getBodyUserID(store, targetHeadlessID, namespace)
	createTestPlatformUser(t, gormDB, bodyUserTarget, namespace, "steam", "steam-target")
	store.Link(ctx, namespace, targetHeadID, targetHeadlessID)

	// Source account (different platform, same namespace)
	createTestHeadAccount(t, store, sourceHeadID)
	createTestHeadlessAccount(t, store, sourceHeadlessID, namespace, "xbox", "xbox-source")
	bodyUserSource := getBodyUserID(store, sourceHeadlessID, namespace)
	createTestPlatformUser(t, gormDB, bodyUserSource, namespace, "xbox", "xbox-source")
	store.Link(ctx, namespace, sourceHeadID, sourceHeadlessID)

	defer cleanupLinkTestData(store, targetHeadID, targetHeadlessID, sourceHeadID, sourceHeadlessID)

	// Try Merge without resolution - should fail
	_, err = store.Merge(ctx, sourceHeadID, targetHeadID, nil)
	if err == nil {
		t.Error("Merge should fail without conflict resolution")
	}

	// Merge with resolution - keep SOURCE
	resolutions := []ConflictResolution{
		{Namespace: namespace, Keep: "SOURCE"},
	}
	_, err = store.Merge(ctx, sourceHeadID, targetHeadID, resolutions)
	if err != nil {
		t.Fatalf("Merge with resolution failed: %v", err)
	}

	// Verify winning user (SOURCE) is now in target account
	winningUserID := getBodyUserID(store, targetHeadID, namespace)
	if winningUserID != bodyUserSource {
		t.Error("Source user should be the winner and be in target account")
	}

	// Verify losing user (TARGET) is orphaned
	var targetOrphaned bool
	gormDB.Raw(`SELECT orphaned FROM users WHERE id = ?`, bodyUserTarget).Row().Scan(&targetOrphaned)
	if !targetOrphaned {
		t.Error("Target user should be orphaned")
	}

	// Verify platform_users for losing platform was transferred to winning user
	if !platformUserExists(store, bodyUserSource, namespace, "steam") {
		t.Error("Steam platform should be transferred to winning user (AccelByte approach)")
	}
}

func TestUserStore_CheckMergeEligibility(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewUserStore(gormDB)
	ctx := context.Background()

	// Create two FULL accounts with same platform type (should NOT be mergeable)
	targetHeadID := uniqueLinkTestID("target-head-same-platform")
	targetHeadlessID := uniqueLinkTestID("target-headless-same-platform")
	sourceHeadID := uniqueLinkTestID("source-head-same-platform")
	sourceHeadlessID := uniqueLinkTestID("source-headless-same-platform")
	namespace := "SAMEPLAT"

	// Both with steam (same platform type)
	createTestHeadAccount(t, store, targetHeadID)
	createTestHeadlessAccount(t, store, targetHeadlessID, namespace, "steam", "steam-target")
	store.Link(ctx, namespace, targetHeadID, targetHeadlessID)

	createTestHeadAccount(t, store, sourceHeadID)
	createTestHeadlessAccount(t, store, sourceHeadlessID, namespace, "steam", "steam-source")
	store.Link(ctx, namespace, sourceHeadID, sourceHeadlessID)

	defer cleanupLinkTestData(store, targetHeadID, targetHeadlessID, sourceHeadID, sourceHeadlessID)

	// Check merge eligibility - should not be eligible for same platform
	eligibility, err := store.CheckMergeEligibility(ctx, sourceHeadID, targetHeadID)
	if err != nil {
		t.Fatalf("CheckMergeEligibility failed: %v", err)
	}

	if eligibility.Eligible {
		t.Error("Merge should not be eligible for same platform type conflict")
	}
}
