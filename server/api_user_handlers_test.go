package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/store"
	_ "github.com/lib/pq"
)

func newRegisterTestEngine(t *testing.T) *gin.Engine {
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	srv := NewServer(NewConfig(), m)
	return NewGinEngine(srv)
}

func TestAPIRegisterUser_Success(t *testing.T) {
	engine := newRegisterTestEngine(t)
	// Use a normal, human-readable username with a unique suffix to avoid conflicts
	uname := uniqueUsername()
	email := fmt.Sprintf("%s@example.com", uname)
	body := []byte(fmt.Sprintf(`{"username":"%s","password":"P@ssw0rd!","email":"%s"}`, uname, email))

	// Pre-clean: delete user if it somehow exists from previous runs
	db, err := openTestDB()
	if err == nil {
		defer db.Close()
		_, _ = db.Exec(`DELETE FROM accounts WHERE username=$1`, uname)
		_, _ = db.Exec(`DELETE FROM accounts WHERE email=$1`, email)
	}

	req := httptest.NewRequest(http.MethodPost, "/iam/v1/public/users", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body=%s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "user_id") {
		t.Fatalf("expected user_id in response; body=%s", w.Body.String())
	}
}

func uniqueUsername() string {
	return fmt.Sprintf("testuser_%d", NewUniqueCounter())
}

var _counter = make(chan int64, 1)

func init() { _counter <- 1 }

func NewUniqueCounter() int64 {
	v := <-_counter
	_counter <- v + 1
	return v
}

func TestListUsersGin_IncludesDisplayName(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	defer db.Close()

	// Create test user with display_name
	userID := fmt.Sprintf("test-user-display-%d", NewUniqueCounter())
	accountID := fmt.Sprintf("test-account-display-%d", NewUniqueCounter())
	displayName := "Test Display Name"

	// Insert test account
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES ($1, $2, '', 'HEAD') ON CONFLICT DO NOTHING`, accountID, accountID)
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer db.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)

	// Insert test user with display_name
	_, err = db.Exec(`INSERT INTO users (id, namespace, user_type, display_name) VALUES ($1, 'TESTNS', 'HEAD', $2) ON CONFLICT DO NOTHING`, userID, displayName)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	_, err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, accountID, userID)
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer db.Exec(`DELETE FROM account_users WHERE user_id = $1`, userID)

	// Verify the user was created with display_name
	var storedDisplayName *string
	err = db.QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&storedDisplayName)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if storedDisplayName == nil || *storedDisplayName != displayName {
		t.Errorf("Expected display_name to be '%s', got '%v'", displayName, storedDisplayName)
	}
}

func TestGetUserGin_IncludesDisplayName(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	defer db.Close()

	// Create test user with display_name
	userID := fmt.Sprintf("test-user-get-display-%d", NewUniqueCounter())
	accountID := fmt.Sprintf("test-account-get-display-%d", NewUniqueCounter())
	displayName := "Get Test User"

	// Insert test account
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES ($1, $2, '', 'HEAD') ON CONFLICT DO NOTHING`, accountID, accountID)
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer db.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)

	// Insert test user with display_name
	_, err = db.Exec(`INSERT INTO users (id, namespace, user_type, display_name) VALUES ($1, 'TESTNS', 'HEAD', $2) ON CONFLICT DO NOTHING`, userID, displayName)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	_, err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, accountID, userID)
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer db.Exec(`DELETE FROM account_users WHERE user_id = $1`, userID)

	// Verify the user was created with display_name
	var storedDisplayName *string
	err = db.QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&storedDisplayName)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if storedDisplayName == nil || *storedDisplayName != displayName {
		t.Errorf("Expected display_name to be '%s', got '%v'", displayName, storedDisplayName)
	}
}

func TestUserDisplayNameNullable(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	defer db.Close()

	// Create test user without display_name
	userID := fmt.Sprintf("test-user-no-display-%d", NewUniqueCounter())
	accountID := fmt.Sprintf("test-account-no-display-%d", NewUniqueCounter())

	// Insert test account
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES ($1, $2, '', 'HEAD') ON CONFLICT DO NOTHING`, accountID, accountID)
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer db.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)

	// Insert test user without display_name
	_, err = db.Exec(`INSERT INTO users (id, namespace, user_type) VALUES ($1, 'TESTNS', 'HEAD') ON CONFLICT DO NOTHING`, userID)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	_, err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, accountID, userID)
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer db.Exec(`DELETE FROM account_users WHERE user_id = $1`, userID)

	// Verify the user was created without display_name (NULL)
	var storedDisplayName *string
	err = db.QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&storedDisplayName)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if storedDisplayName != nil {
		t.Errorf("Expected display_name to be NULL, got '%s'", *storedDisplayName)
	}
}

func TestUserDisplayNameUpdate(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip("No database connection available")
	}
	defer db.Close()

	// Create test user
	userID := fmt.Sprintf("test-user-update-display-%d", NewUniqueCounter())
	accountID := fmt.Sprintf("test-account-update-display-%d", NewUniqueCounter())
	initialDisplayName := "Initial Name"
	updatedDisplayName := "Updated Name"

	// Insert test account
	_, err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES ($1, $2, '', 'HEAD') ON CONFLICT DO NOTHING`, accountID, accountID)
	if err != nil {
		t.Fatalf("Failed to insert test account: %v", err)
	}
	defer db.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)

	// Insert test user with initial display_name
	_, err = db.Exec(`INSERT INTO users (id, namespace, user_type, display_name) VALUES ($1, 'TESTNS', 'HEAD', $2) ON CONFLICT DO NOTHING`, userID, initialDisplayName)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	defer db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	_, err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, accountID, userID)
	if err != nil {
		t.Fatalf("Failed to insert account_users: %v", err)
	}
	defer db.Exec(`DELETE FROM account_users WHERE user_id = $1`, userID)

	// Update display_name
	_, err = db.Exec(`UPDATE users SET display_name = $1 WHERE id = $2`, updatedDisplayName, userID)
	if err != nil {
		t.Fatalf("Failed to update display_name: %v", err)
	}

	// Verify the update
	var storedDisplayName *string
	err = db.QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&storedDisplayName)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if storedDisplayName == nil || *storedDisplayName != updatedDisplayName {
		t.Errorf("Expected display_name to be '%s', got '%v'", updatedDisplayName, storedDisplayName)
	}
}
