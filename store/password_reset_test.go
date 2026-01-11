package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var resetTestCounter int64 = time.Now().UnixNano()

func uniqueResetTestID(prefix string) string {
	resetTestCounter++
	return fmt.Sprintf("%s-%d", prefix, resetTestCounter)
}

func cleanupPasswordResetTestData(db *PasswordResetStore, email string) {
	db.DB.Exec(`DELETE FROM password_reset_codes WHERE email = ?`, email)
	db.DB.Exec(`DELETE FROM password_reset_rate_limits WHERE email = ?`, email)
}

func TestPasswordResetStore_CreateResetCode(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create reset code
	result, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}

	if result.RateLimited {
		t.Error("First request should not be rate limited")
	}
	if result.Code == nil {
		t.Fatal("Code should not be nil")
	}
	if len(result.Code.Code) != 6 {
		t.Errorf("Code should be 6 digits, got %d", len(result.Code.Code))
	}
	if result.Code.AccountID != accountID {
		t.Errorf("AccountID mismatch: expected %s, got %s", accountID, result.Code.AccountID)
	}
	if result.Code.Email != email {
		t.Errorf("Email mismatch: expected %s, got %s", email, result.Code.Email)
	}
	if result.Code.Used {
		t.Error("New code should not be marked as used")
	}
}

func TestPasswordResetStore_CreateResetCode_ExistingCode(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create first code
	result1, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("First CreateResetCode failed: %v", err)
	}
	firstCode := result1.Code

	// Try to create second code - should return existing code expiration
	result2, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("Second CreateResetCode failed: %v", err)
	}

	if result2.Code != nil {
		t.Error("Should not create new code when valid code exists")
	}
	if result2.ExistingCodeExp == nil {
		t.Error("Should return existing code expiration")
	}
	// Compare truncated to second precision to handle database timestamp differences
	if result2.ExistingCodeExp != nil {
		exp1 := firstCode.ExpiresAt.Truncate(time.Second)
		exp2 := result2.ExistingCodeExp.Truncate(time.Second)
		if !exp1.Equal(exp2) {
			t.Errorf("Existing code expiration mismatch: expected %v, got %v", exp1, exp2)
		}
	}
}

func TestPasswordResetStore_RateLimit(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	// Configure store with shorter rate limit for testing
	cfg := DefaultPasswordResetConfig()
	cfg.RateLimitMaxReqs = 2
	cfg.RateLimitWindow = 1 * time.Minute

	store := NewPasswordResetStoreWithConfig(gormDB, cfg)
	ctx := context.Background()

	email := uniqueResetTestID("ratelimit") + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// First request - should succeed
	result1, err := store.CreateResetCode(ctx, "acc1", email)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	if result1.RateLimited {
		t.Error("First request should not be rate limited")
	}

	// Mark first code as used so next request creates new code
	if result1.Code != nil {
		store.ConsumeCode(ctx, result1.Code.ID)
	}

	// Second request - should succeed
	result2, err := store.CreateResetCode(ctx, "acc1", email)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	if result2.RateLimited {
		t.Error("Second request should not be rate limited")
	}

	// Mark second code as used
	if result2.Code != nil {
		store.ConsumeCode(ctx, result2.Code.ID)
	}

	// Third request - should be rate limited
	result3, err := store.CreateResetCode(ctx, "acc1", email)
	if err != nil {
		t.Fatalf("Third request failed: %v", err)
	}
	if !result3.RateLimited {
		t.Error("Third request should be rate limited")
	}
	if result3.RetryAfterSecs <= 0 {
		t.Error("RetryAfterSecs should be positive")
	}
}

func TestPasswordResetStore_ValidateCode(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}
	code := createResult.Code

	// Validate with correct code
	validResult, err := store.ValidateCode(ctx, email, code.Code)
	if err != nil {
		t.Fatalf("ValidateCode failed: %v", err)
	}
	if !validResult.Valid {
		t.Error("Code should be valid")
	}
	if validResult.Code == nil {
		t.Error("Code should be returned on valid validation")
	}

	// Validate with wrong code
	wrongResult, err := store.ValidateCode(ctx, email, "000000")
	if err != nil {
		t.Fatalf("ValidateCode with wrong code failed: %v", err)
	}
	if wrongResult.Valid {
		t.Error("Wrong code should not be valid")
	}
	if wrongResult.RemainingAttempts >= store.Config.MaxFailedAttempts {
		t.Error("Failed attempts should be incremented")
	}
}

func TestPasswordResetStore_ValidateCode_Lockout(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	// Configure with low max attempts for testing
	cfg := DefaultPasswordResetConfig()
	cfg.MaxFailedAttempts = 3

	store := NewPasswordResetStoreWithConfig(gormDB, cfg)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}

	// Fail multiple times to trigger lockout
	for i := 0; i < cfg.MaxFailedAttempts; i++ {
		result, err := store.ValidateCode(ctx, email, "000000")
		if err != nil {
			t.Fatalf("ValidateCode failed: %v", err)
		}
		if i < cfg.MaxFailedAttempts-1 && result.Locked {
			t.Errorf("Should not be locked after %d attempts", i+1)
		}
	}

	// Next attempt should be locked
	lockedResult, err := store.ValidateCode(ctx, email, createResult.Code.Code)
	if err != nil {
		t.Fatalf("ValidateCode after lockout failed: %v", err)
	}
	if !lockedResult.Locked {
		t.Error("Account should be locked after max failed attempts")
	}
	if lockedResult.LockedUntil == nil {
		t.Error("LockedUntil should be set")
	}
}

func TestPasswordResetStore_ValidateCodeOnly(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}

	// ValidateCodeOnly with wrong code should NOT increment failed attempts
	for i := 0; i < 10; i++ {
		result, err := store.ValidateCodeOnly(ctx, email, "000000")
		if err != nil {
			t.Fatalf("ValidateCodeOnly failed: %v", err)
		}
		if result.Locked {
			t.Error("ValidateCodeOnly should not cause lockout")
		}
	}

	// Original code should still be valid
	validResult, err := store.ValidateCode(ctx, email, createResult.Code.Code)
	if err != nil {
		t.Fatalf("ValidateCode failed: %v", err)
	}
	if !validResult.Valid {
		t.Error("Code should still be valid after ValidateCodeOnly calls")
	}
}

func TestPasswordResetStore_ConsumeCode(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}
	code := createResult.Code

	// Consume the code
	err = store.ConsumeCode(ctx, code.ID)
	if err != nil {
		t.Fatalf("ConsumeCode failed: %v", err)
	}

	// Validate should show already used
	result, err := store.ValidateCode(ctx, email, code.Code)
	if err != nil {
		t.Fatalf("ValidateCode after consume failed: %v", err)
	}
	if result.Valid {
		t.Error("Consumed code should not be valid")
	}
	if !result.AlreadyUsed {
		t.Error("Code should be marked as already used")
	}

	// Consuming again should fail
	err = store.ConsumeCode(ctx, code.ID)
	if err == nil {
		t.Error("Consuming already-used code should fail")
	}
}

func TestPasswordResetStore_InvalidateCodesForAccount(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}
	code := createResult.Code

	// Invalidate all codes for account
	err = store.InvalidateCodesForAccount(ctx, accountID)
	if err != nil {
		t.Fatalf("InvalidateCodesForAccount failed: %v", err)
	}

	// Validate should show already used
	result, err := store.ValidateCode(ctx, email, code.Code)
	if err != nil {
		t.Fatalf("ValidateCode after invalidate failed: %v", err)
	}
	if result.Valid {
		t.Error("Invalidated code should not be valid")
	}
	if !result.AlreadyUsed {
		t.Error("Code should be marked as already used")
	}
}

func TestPasswordResetStore_ExpiredCode(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	// Configure with very short TTL for testing
	cfg := DefaultPasswordResetConfig()
	cfg.CodeTTL = 1 * time.Millisecond

	store := NewPasswordResetStoreWithConfig(gormDB, cfg)
	ctx := context.Background()

	accountID := uniqueResetTestID("account")
	email := accountID + "@test.com"
	defer cleanupPasswordResetTestData(store, email)

	// Create code
	createResult, err := store.CreateResetCode(ctx, accountID, email)
	if err != nil {
		t.Fatalf("CreateResetCode failed: %v", err)
	}
	code := createResult.Code

	// Wait for code to expire
	time.Sleep(10 * time.Millisecond)

	// Validate should show expired
	result, err := store.ValidateCode(ctx, email, code.Code)
	if err != nil {
		t.Fatalf("ValidateCode failed: %v", err)
	}
	if result.Valid {
		t.Error("Expired code should not be valid")
	}
	if !result.Expired {
		t.Error("Code should be marked as expired")
	}
}

func TestPasswordResetStore_NotFound(t *testing.T) {
	gormDB, err := getTestGormDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	sqlDB, _ := gormDB.DB()
	defer sqlDB.Close()

	store := NewPasswordResetStore(gormDB)
	ctx := context.Background()

	email := uniqueResetTestID("nonexistent") + "@test.com"

	// Validate code for non-existent email
	result, err := store.ValidateCode(ctx, email, "123456")
	if err != nil {
		t.Fatalf("ValidateCode failed: %v", err)
	}
	if result.Valid {
		t.Error("Non-existent code should not be valid")
	}
	if !result.NotFound {
		t.Error("Code should be marked as not found")
	}
}

func TestGenerateNumericCode(t *testing.T) {
	// Test that generateNumericCode produces 6-digit codes
	for i := 0; i < 100; i++ {
		code, err := generateNumericCode()
		if err != nil {
			t.Fatalf("generateNumericCode failed: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("Code should be 6 digits, got %d: %s", len(code), code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("Code should contain only digits: %s", code)
			}
		}
	}
}
