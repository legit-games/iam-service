package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/email"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newPasswordResetTestEngine creates a test engine with password reset configured
func newPasswordResetTestEngine(t *testing.T) (*gin.Engine, *Server, *gorm.DB) {
	dsn, err := getTestDSN()
	if err != nil {
		t.Skip("No database connection available")
	}

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	cs.Set("test-client", &models.Client{ID: "test-client", Secret: "secret", Domain: "http://localhost"})
	m.MapClientStorage(cs)

	srv := NewServer(NewConfig(), m)
	srv.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		return "test-client", "secret", nil
	})

	// Initialize password reset store and email sender
	srv.passwordResetStore = store.NewPasswordResetStore(gormDB)
	srv.emailSender = email.NewNoOpSender()

	// Set up DB connections for handlers
	srv.userWrite = gormDB
	srv.userRead = gormDB

	return NewGinEngine(srv), srv, gormDB
}

// cleanupPasswordResetTest cleans up test data
func cleanupPasswordResetTest(db *gorm.DB, email string, accountID string) {
	db.Exec(`DELETE FROM password_reset_codes WHERE email = $1`, email)
	db.Exec(`DELETE FROM password_reset_rate_limits WHERE email = $1`, email)
	if accountID != "" {
		db.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)
	}
}

// createTestAccountWithEmail creates a test account with email for password reset tests
func createTestAccountWithEmail(t *testing.T, db *gorm.DB, accountID, username, emailAddr string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	result := db.Exec(`INSERT INTO accounts (id, username, password_hash, email, account_type) VALUES ($1, $2, $3, $4, 'HEAD')`,
		accountID, username, string(hash), emailAddr)
	if result.Error != nil {
		t.Fatalf("Failed to create test account: %v", result.Error)
	}
}

func TestHandleForgotPasswordGin_Success(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("test_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	body := []byte(fmt.Sprintf(`{"email":"%s"}`, emailAddr))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp ForgotPasswordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Error("Expected success=true")
	}
	if resp.ExpiresInSecs <= 0 {
		t.Error("Expected expires_in_secs > 0")
	}
}

func TestHandleForgotPasswordGin_NonExistentEmail(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Non-existent email should still return success (security - prevent enumeration)
	body := []byte(`{"email":"nonexistent@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even for non-existent email, got %d", w.Code)
	}

	var resp ForgotPasswordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Error("Expected success=true even for non-existent email")
	}
}

func TestHandleForgotPasswordGin_InvalidEmail(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	body := []byte(`{"email":"invalid-email"}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d", w.Code)
	}
}

func TestHandleForgotPasswordGin_MissingEmail(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d", w.Code)
	}
}

func TestHandleForgotPasswordGin_RateLimit(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Configure lower rate limit for testing
	srv.passwordResetStore.Config.RateLimitMaxReqs = 2
	srv.passwordResetStore.Config.RateLimitWindow = 5 * time.Minute

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("ratelimit_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	body := []byte(fmt.Sprintf(`{"email":"%s"}`, emailAddr))

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/forgot-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for rate limit, got %d", w.Code)
	}
}

func TestHandleValidateResetCodeGin_Success(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("validate_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code directly
	ctx := context.Background()
	result, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}
	code := result.Code.Code

	// Validate the code
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/iam/v1/public/users/reset-password/validate?email=%s&code=%s", emailAddr, code), nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp ValidateResetCodeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !resp.Valid {
		t.Errorf("Expected valid=true, got reason=%s", resp.Reason)
	}
}

func TestHandleValidateResetCodeGin_InvalidCode(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("validate_invalid_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	_, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}

	// Validate with wrong code
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/iam/v1/public/users/reset-password/validate?email=%s&code=000000", emailAddr), nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp ValidateResetCodeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if resp.Valid {
		t.Error("Expected valid=false for wrong code")
	}
}

func TestHandleValidateResetCodeGin_MissingParams(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Missing email
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/public/users/reset-password/validate?code=123456", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d", w.Code)
	}

	// Missing code
	req2 := httptest.NewRequest(http.MethodGet, "/iam/v1/public/users/reset-password/validate?email=test@test.com", nil)
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing code, got %d", w2.Code)
	}
}

func TestHandleValidateResetCodeGin_InvalidCodeFormat(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Code too short
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/public/users/reset-password/validate?email=test@test.com&code=123", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp ValidateResetCodeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if resp.Valid {
		t.Error("Expected valid=false for invalid code format")
	}
	if resp.Reason != "invalid_code_format" {
		t.Errorf("Expected reason=invalid_code_format, got %s", resp.Reason)
	}
}

func TestHandleResetPasswordGin_Success(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("reset_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	result, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}
	code := result.Code.Code

	// Reset password
	body := []byte(fmt.Sprintf(`{"email":"%s","code":"%s","new_password":"newpassword123"}`, emailAddr, code))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp ResetPasswordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Error("Expected success=true")
	}

	// Verify password was changed
	var storedHash string
	db.Raw(`SELECT password_hash FROM accounts WHERE id = $1`, accountID).Row().Scan(&storedHash)
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte("newpassword123")); err != nil {
		t.Error("Password was not updated correctly")
	}

	// Verify old password no longer works
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte("oldpassword")); err == nil {
		t.Error("Old password should no longer work")
	}
}

func TestHandleResetPasswordGin_InvalidCode(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("reset_invalid_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	_, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}

	// Try to reset with wrong code
	body := []byte(fmt.Sprintf(`{"email":"%s","code":"000000","new_password":"newpassword123"}`, emailAddr))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong code, got %d", w.Code)
	}
}

func TestHandleResetPasswordGin_WeakPassword(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("reset_weak_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	result, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}
	code := result.Code.Code

	// Try to reset with weak password (< 8 chars)
	body := []byte(fmt.Sprintf(`{"email":"%s","code":"%s","new_password":"short"}`, emailAddr, code))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d", w.Code)
	}
}

func TestHandleResetPasswordGin_CodeAlreadyUsed(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("reset_used_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	result, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}
	code := result.Code.Code

	// First reset should succeed
	body := []byte(fmt.Sprintf(`{"email":"%s","code":"%s","new_password":"newpassword123"}`, emailAddr, code))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("First reset: expected 200, got %d", w.Code)
	}

	// Second reset with same code should fail
	body2 := []byte(fmt.Sprintf(`{"email":"%s","code":"%s","new_password":"anotherpassword"}`, emailAddr, code))
	req2 := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("Second reset: expected 400 for already used code, got %d", w2.Code)
	}
}

func TestHandleResetPasswordGin_Lockout(t *testing.T) {
	engine, srv, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Configure low max attempts for testing
	srv.passwordResetStore.Config.MaxFailedAttempts = 3

	accountID := models.LegitID()
	emailAddr := fmt.Sprintf("reset_lockout_%s@example.com", accountID)
	username := fmt.Sprintf("user_%s", accountID)
	defer cleanupPasswordResetTest(db, emailAddr, accountID)

	createTestAccountWithEmail(t, db, accountID, username, emailAddr)

	// Create a reset code
	ctx := context.Background()
	_, err := srv.passwordResetStore.CreateResetCode(ctx, accountID, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create reset code: %v", err)
	}

	// Fail multiple times
	for i := 0; i < 3; i++ {
		body := []byte(fmt.Sprintf(`{"email":"%s","code":"000000","new_password":"newpassword123"}`, emailAddr))
		req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
	}

	// Next attempt should be locked
	body := []byte(fmt.Sprintf(`{"email":"%s","code":"000000","new_password":"newpassword123"}`, emailAddr))
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for lockout, got %d", w.Code)
	}
}

func TestHandleResetPasswordGin_MissingFields(t *testing.T) {
	engine, _, db := newPasswordResetTestEngine(t)
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	testCases := []struct {
		name string
		body string
	}{
		{"missing email", `{"code":"123456","new_password":"newpass123"}`},
		{"missing code", `{"email":"test@test.com","new_password":"newpass123"}`},
		{"missing password", `{"email":"test@test.com","code":"123456"}`},
		{"empty body", `{}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users/reset-password", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d", tc.name, w.Code)
			}
		})
	}
}
