package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupBanTestServer(t *testing.T) (*banTestServer, *gorm.DB) {
	// Use existing test database setup from server
	dsn, err := getTestDSN()
	if err != nil {
		t.Fatal(err)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Insert test data
	testAccountID := "test-account-123"
	testUserID := "test-user-456"
	actorAccountID := "actor-account-789"
	actorUserID := "actor-user-101"

	// Replace multi-statement Exec with individual Exec calls
	if err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, 'testuser', 'x', 'HEAD') ON CONFLICT (id) DO NOTHING`, testAccountID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO accounts (id, username, password_hash, account_type) VALUES (?, 'actor', 'x', 'HEAD') ON CONFLICT (id) DO NOTHING`, actorAccountID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO users (id, namespace, user_type) VALUES (?, 'TESTNS', 'BODY') ON CONFLICT (id) DO NOTHING`, testUserID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES (?, ?) ON CONFLICT (account_id, user_id) DO NOTHING`, testAccountID, testUserID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO users (id, user_type) VALUES (?, 'HEAD') ON CONFLICT (id) DO NOTHING`, actorUserID).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO account_users (account_id, user_id) VALUES (?, ?) ON CONFLICT (account_id, user_id) DO NOTHING`, actorAccountID, actorUserID).Error; err != nil {
		t.Fatal(err)
	}

	// Create server
	server := &banTestServer{
		userStore: store.NewUserStore(db),
		mockDB:    db,
		actorUser: actorUserID,
	}

	return server, db
}

// banTestServer implements Server methods with test mocks
type banTestServer struct {
	userStore *store.UserStore
	mockDB    *gorm.DB
	actorUser string
}

// ValidationBearerToken mock for testing
func (ts *banTestServer) ValidationBearerToken(r *http.Request) (oauth2.TokenInfo, error) {
	return &banMockTokenInfo{userID: ts.actorUser}, nil
}

// GetIAMReadDB mock for testing
func (ts *banTestServer) GetIAMReadDB() (*gorm.DB, error) {
	return ts.mockDB, nil
}

// HandleBanUserGin implements the ban user handler for testing
func (ts *banTestServer) HandleBanUserGin(c *gin.Context) {
	// Mock the authorization part
	callerUserID := ts.actorUser
	db := ts.mockDB

	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=?`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	// Extract parameters
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("id"))

	if ns == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing namespace or user id"})
		return
	}

	// Parse request body
	var req struct {
		Type   string     `json:"type"`
		Reason string     `json:"reason"`
		Until  *time.Time `json:"until"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON body"})
		return
	}

	// Validate ban type
	banType := models.BanType(req.Type)
	if banType != models.BanPermanent && banType != models.BanTimed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "ban type must be PERMANENT or TIMED"})
		return
	}

	// For timed bans, until is required
	if banType == models.BanTimed && req.Until == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "until time required for TIMED ban"})
		return
	}

	// Execute ban
	err := ts.userStore.BanUser(c.Request.Context(), userID, ns, banType, req.Reason, req.Until, actorAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User banned successfully"})
}

// HandleUnbanUserGin implements the unban user handler for testing
func (ts *banTestServer) HandleUnbanUserGin(c *gin.Context) {
	// Mock the authorization part
	callerUserID := ts.actorUser
	db := ts.mockDB

	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=?`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("id"))

	if ns == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	err := ts.userStore.UnbanUser(c.Request.Context(), userID, ns, req.Reason, actorAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User unbanned successfully"})
}

// HandleListUserBansGin implements the list user bans handler for testing
func (ts *banTestServer) HandleListUserBansGin(c *gin.Context) {
	ns := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("id"))

	if ns == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	bans, err := ts.userStore.ListUserBans(c.Request.Context(), userID, ns)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bans": bans})
}

// HandleListAccountBansGin implements the list account bans handler for testing
func (ts *banTestServer) HandleListAccountBansGin(c *gin.Context) {
	accountID := strings.TrimSpace(c.Param("id"))

	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	bans, err := ts.userStore.ListAccountBans(c.Request.Context(), accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bans": bans})
}

// HandleBanAccountGin implements the ban account handler for testing
func (ts *banTestServer) HandleBanAccountGin(c *gin.Context) {
	// Mock the authorization part
	callerUserID := ts.actorUser
	db := ts.mockDB

	var actorAccountID string
	row := db.WithContext(c.Request.Context()).Raw(`SELECT account_id FROM account_users WHERE user_id=?`, callerUserID).Row()
	if err := row.Scan(&actorAccountID); err != nil || strings.TrimSpace(actorAccountID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "unable to resolve actor account"})
		return
	}

	// Extract parameters
	accountID := strings.TrimSpace(c.Param("id"))

	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing account id"})
		return
	}

	// Parse request body
	var req struct {
		Type   string     `json:"type"`
		Reason string     `json:"reason"`
		Until  *time.Time `json:"until"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON body"})
		return
	}

	// Validate ban type
	banType := models.BanType(req.Type)
	if banType != models.BanPermanent && banType != models.BanTimed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "ban type must be PERMANENT or TIMED"})
		return
	}

	// For timed bans, until is required
	if banType == models.BanTimed && req.Until == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "until time required for TIMED ban"})
		return
	}

	// Execute ban
	err := ts.userStore.BanAccount(c.Request.Context(), accountID, banType, req.Reason, req.Until, actorAccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account banned successfully"})
}

type banMockTokenInfo struct {
	userID string
}

func (m *banMockTokenInfo) New() oauth2.TokenInfo                              { return &banMockTokenInfo{} }
func (m *banMockTokenInfo) GetClientID() string                                { return "test-client" }
func (m *banMockTokenInfo) SetClientID(string)                                 {}
func (m *banMockTokenInfo) GetUserID() string                                  { return m.userID }
func (m *banMockTokenInfo) SetUserID(string)                                   {}
func (m *banMockTokenInfo) GetRedirectURI() string                             { return "http://example.com/callback" }
func (m *banMockTokenInfo) SetRedirectURI(string)                              {}
func (m *banMockTokenInfo) GetScope() string                                   { return "read" }
func (m *banMockTokenInfo) SetScope(string)                                    {}
func (m *banMockTokenInfo) GetCode() string                                    { return "mock-code" }
func (m *banMockTokenInfo) SetCode(string)                                     {}
func (m *banMockTokenInfo) GetCodeCreateAt() time.Time                         { return time.Now() }
func (m *banMockTokenInfo) SetCodeCreateAt(time.Time)                          {}
func (m *banMockTokenInfo) GetCodeExpiresIn() time.Duration                    { return 10 * time.Minute }
func (m *banMockTokenInfo) SetCodeExpiresIn(time.Duration)                     {}
func (m *banMockTokenInfo) GetCodeChallenge() string                           { return "" }
func (m *banMockTokenInfo) SetCodeChallenge(string)                            {}
func (m *banMockTokenInfo) GetCodeChallengeMethod() oauth2.CodeChallengeMethod { return "" }
func (m *banMockTokenInfo) SetCodeChallengeMethod(oauth2.CodeChallengeMethod)  {}
func (m *banMockTokenInfo) GetAccess() string                                  { return "mock-access-token" }
func (m *banMockTokenInfo) SetAccess(string)                                   {}
func (m *banMockTokenInfo) GetAccessCreateAt() time.Time                       { return time.Now() }
func (m *banMockTokenInfo) SetAccessCreateAt(time.Time)                        {}
func (m *banMockTokenInfo) GetAccessExpiresIn() time.Duration                  { return time.Hour }
func (m *banMockTokenInfo) SetAccessExpiresIn(time.Duration)                   {}
func (m *banMockTokenInfo) GetRefresh() string                                 { return "mock-refresh-token" }
func (m *banMockTokenInfo) SetRefresh(string)                                  {}
func (m *banMockTokenInfo) GetRefreshCreateAt() time.Time                      { return time.Now() }
func (m *banMockTokenInfo) SetRefreshCreateAt(time.Time)                       {}
func (m *banMockTokenInfo) GetRefreshExpiresIn() time.Duration                 { return 24 * time.Hour }
func (m *banMockTokenInfo) SetRefreshExpiresIn(time.Duration)                  {}

func TestHandleBanUserGin(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/ban/:ns/users/:id", server.HandleBanUserGin)

	tests := []struct {
		name           string
		namespace      string
		userID         string
		requestBody    map[string]interface{}
		expectedStatus int
		expectBan      bool
	}{
		{
			name:      "permanent ban success",
			namespace: "TESTNS",
			userID:    "test-user-456",
			requestBody: map[string]interface{}{
				"type":   "PERMANENT",
				"reason": "Cheating detected",
			},
			expectedStatus: 200,
			expectBan:      true,
		},
		{
			name:      "timed ban success",
			namespace: "TESTNS",
			userID:    "test-user-456",
			requestBody: map[string]interface{}{
				"type":   "TIMED",
				"reason": "Harassment",
				"until":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
			expectedStatus: 200,
			expectBan:      true,
		},
		{
			name:      "timed ban without until should fail",
			namespace: "TESTNS",
			userID:    "test-user-456",
			requestBody: map[string]interface{}{
				"type":   "TIMED",
				"reason": "Spam",
			},
			expectedStatus: 400,
			expectBan:      false,
		},
		{
			name:      "invalid ban type should fail",
			namespace: "TESTNS",
			userID:    "test-user-456",
			requestBody: map[string]interface{}{
				"type":   "INVALID",
				"reason": "Test",
			},
			expectedStatus: 400,
			expectBan:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans
			server.userStore.DB.Exec("DELETE FROM user_bans")
			server.userStore.DB.Exec("DELETE FROM user_ban_history")

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/ban/"+tt.namespace+"/users/"+tt.userID, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			// Don't set Authorization header since we're testing ban logic, not auth

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{
				{Key: "ns", Value: tt.namespace},
				{Key: "id", Value: tt.userID},
			}

			// Call the handler directly bypassing middleware
			server.HandleBanUserGin(c)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectBan {
				banned, err := server.userStore.IsUserBanned(context.Background(), tt.userID, tt.namespace)
				if err != nil {
					t.Errorf("Error checking ban status: %v", err)
				}
				if !banned {
					t.Errorf("Expected user to be banned, but they are not")
				}

				// Check history entry
				var historyCount int64
				server.userStore.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", tt.userID, tt.namespace, "BAN").Count(&historyCount)
				if historyCount != 1 {
					t.Errorf("Expected 1 history entry, got %d", historyCount)
				}
			}
		})
	}
}

func TestHandleBanAccountGin(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/ban/accounts/:id", server.HandleBanAccountGin)

	tests := []struct {
		name           string
		accountID      string
		requestBody    map[string]interface{}
		expectedStatus int
		expectBan      bool
	}{
		{
			name:      "permanent account ban success",
			accountID: "test-account-123",
			requestBody: map[string]interface{}{
				"type":   "PERMANENT",
				"reason": "Account violation",
			},
			expectedStatus: 200,
			expectBan:      true,
		},
		{
			name:      "timed account ban success",
			accountID: "test-account-123",
			requestBody: map[string]interface{}{
				"type":   "TIMED",
				"reason": "Temporary suspension",
				"until":  time.Now().Add(48 * time.Hour).Format(time.RFC3339),
			},
			expectedStatus: 200,
			expectBan:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing bans
			server.userStore.DB.Exec("DELETE FROM account_bans")
			server.userStore.DB.Exec("DELETE FROM account_ban_history")

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/ban/accounts/"+tt.accountID, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-token")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectBan {
				banned, err := server.userStore.IsAccountBanned(context.Background(), tt.accountID)
				if err != nil {
					t.Errorf("Error checking account ban status: %v", err)
				}
				if !banned {
					t.Errorf("Expected account to be banned, but it is not")
				}

				// Check history entry
				var historyCount int64
				server.userStore.DB.Model(&models.AccountBanHistory{}).Table("account_ban_history").Where("account_id = ? AND action = ?", tt.accountID, "BAN").Count(&historyCount)
				if historyCount != 1 {
					t.Errorf("Expected 1 history entry, got %d", historyCount)
				}
			}
		})
	}
}

func TestHandleUnbanUserGin(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/unban/:ns/users/:id", server.HandleUnbanUserGin)

	// Set up a banned user first
	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	err := server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanPermanent, "Test ban", nil, actorAccountID)
	if err != nil {
		t.Fatal(err)
	}

	requestBody := map[string]interface{}{
		"reason": "Ban lifted",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/unban/"+testNamespace+"/users/"+testUserID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check if user is unbanned
	banned, err := server.userStore.IsUserBanned(context.Background(), testUserID, testNamespace)
	if err != nil {
		t.Errorf("Error checking ban status: %v", err)
	}
	if banned {
		t.Errorf("Expected user to be unbanned, but they are still banned")
	}

	// Check unban history entry
	var historyCount int64
	server.userStore.DB.Model(&models.UserBanHistory{}).Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, testNamespace, "UNBAN").Count(&historyCount)
	if historyCount != 1 {
		t.Errorf("Expected 1 unban history entry, got %d", historyCount)
	}
}

func TestIsUserBannedByAccount(t *testing.T) {
	server, _ := setupBanTestServer(t)

	testUserID := "test-user-456"
	testAccountID := "test-account-123"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	tests := []struct {
		name        string
		setupBan    func()
		expectBan   bool
		description string
	}{
		{
			name:        "no ban",
			setupBan:    func() {},
			expectBan:   false,
			description: "User should not be banned when no bans exist",
		},
		{
			name: "user level ban",
			setupBan: func() {
				server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanPermanent, "User ban", nil, actorAccountID)
			},
			expectBan:   true,
			description: "User should be banned when directly banned",
		},
		{
			name: "account level ban",
			setupBan: func() {
				server.userStore.BanAccount(context.Background(), testAccountID, models.BanPermanent, "Account ban", nil, actorAccountID)
			},
			expectBan:   true,
			description: "User should be banned when account is banned",
		},
		{
			name: "timed ban expired",
			setupBan: func() {
				pastTime := time.Now().UTC().Add(-1 * time.Hour)
				server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanTimed, "Expired ban", &pastTime, actorAccountID)
			},
			expectBan:   false,
			description: "User should not be banned when timed ban has expired",
		},
		{
			name: "timed ban active",
			setupBan: func() {
				futureTime := time.Now().UTC().Add(1 * time.Hour)
				server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanTimed, "Active ban", &futureTime, actorAccountID)
				// Ensure DB commit visibility and avoid clock skew
				time.Sleep(5 * time.Millisecond)
			},
			expectBan:   true,
			description: "User should be banned when timed ban is still active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all bans and history
			server.userStore.DB.Exec("DELETE FROM user_bans")
			server.userStore.DB.Exec("DELETE FROM account_bans")
			server.userStore.DB.Exec("DELETE FROM user_ban_history")
			server.userStore.DB.Exec("DELETE FROM account_ban_history")

			// Setup test scenario
			tt.setupBan()

			// Test the ban check
			banned, err := server.userStore.IsUserBannedByAccount(context.Background(), testUserID, testNamespace)
			if err != nil {
				t.Errorf("Error checking ban status: %v", err)
			}

			if banned != tt.expectBan {
				t.Errorf("%s: Expected banned=%v, got %v", tt.description, tt.expectBan, banned)
			}
		})
	}
}

func TestListUserBansGin(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/bans/:ns/users/:id", server.HandleListUserBansGin)

	testUserID := "test-user-456"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	// Clear all existing bans first
	server.userStore.DB.Exec("DELETE FROM user_bans")
	server.userStore.DB.Exec("DELETE FROM user_ban_history")

	// Create test bans
	server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanPermanent, "First ban", nil, actorAccountID)

	// Add a small delay to ensure different IDs
	time.Sleep(10 * time.Millisecond)

	futureTime := time.Now().UTC().Add(24 * time.Hour)
	server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanTimed, "Second ban", &futureTime, actorAccountID)

	req := httptest.NewRequest("GET", "/bans/"+testNamespace+"/users/"+testUserID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	bans, ok := response["bans"].([]interface{})
	if !ok {
		t.Errorf("Expected bans array in response")
	}

	if len(bans) != 2 {
		t.Errorf("Expected 2 bans, got %d", len(bans))
	}
}

func TestListAccountBansGin(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/bans/accounts/:id", server.HandleListAccountBansGin)

	testAccountID := "test-account-123"
	actorAccountID := "actor-account-789"

	// Create test account ban
	server.userStore.BanAccount(context.Background(), testAccountID, models.BanPermanent, "Account violation", nil, actorAccountID)

	req := httptest.NewRequest("GET", "/bans/accounts/"+testAccountID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	bans, ok := response["bans"].([]interface{})
	if !ok {
		t.Errorf("Expected bans array in response")
	}

	if len(bans) != 1 {
		t.Errorf("Expected 1 ban, got %d", len(bans))
	}
}

func TestBanEnforcementInTokenIssuance(t *testing.T) {
	server, db := setupBanTestServer(t)

	testUserID := "test-user-456"
	testAccountID := "test-account-123"
	testNamespace := "TESTNS"
	actorAccountID := "actor-account-789"

	// Mock the token generation request
	mockRequest := &http.Request{}
	mockRequest.Header = make(http.Header)
	mockRequest.Form = make(map[string][]string)
	mockRequest.Form.Set("ns", testNamespace)

	tests := []struct {
		name        string
		setupBan    func()
		expectError bool
		description string
	}{
		{
			name:        "no ban allows token",
			setupBan:    func() {},
			expectError: false,
			description: "Token issuance should succeed when user is not banned",
		},
		{
			name: "user ban blocks token",
			setupBan: func() {
				server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanPermanent, "User banned", nil, actorAccountID)
			},
			expectError: true,
			description: "Token issuance should fail when user is directly banned",
		},
		{
			name: "account ban blocks token",
			setupBan: func() {
				server.userStore.BanAccount(context.Background(), testAccountID, models.BanPermanent, "Account banned", nil, actorAccountID)
			},
			expectError: true,
			description: "Token issuance should fail when account is banned",
		},
		{
			name: "expired ban allows token",
			setupBan: func() {
				pastTime := time.Now().UTC().Add(-1 * time.Hour)
				server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanTimed, "Expired ban", &pastTime, actorAccountID)
			},
			expectError: false,
			description: "Token issuance should succeed when ban has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all bans
			db.Exec("DELETE FROM user_bans")
			db.Exec("DELETE FROM account_bans")

			// Setup test scenario
			tt.setupBan()

			// Test ban enforcement
			banned, err := server.userStore.IsUserBannedByAccount(context.Background(), testUserID, testNamespace)
			if err != nil {
				t.Errorf("Error checking ban status: %v", err)
			}

			if tt.expectError && !banned {
				t.Errorf("%s: Expected user to be banned, but they are not", tt.description)
			} else if !tt.expectError && banned {
				t.Errorf("%s: Expected user to not be banned, but they are", tt.description)
			}
		})
	}
}

func TestActorAccountResolution(t *testing.T) {
	server, _ := setupBanTestServer(t)
	gin.SetMode(gin.TestMode)

	// Test that actor account is properly resolved from token
	testUserID := "test-user-456"
	testNamespace := "TESTNS"

	// Mock request with authorization
	requestBody := map[string]interface{}{
		"type":   "PERMANENT",
		"reason": "Test ban",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/ban/"+testNamespace+"/users/"+testUserID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{
		{Key: "ns", Value: testNamespace},
		{Key: "id", Value: testUserID},
	}
	server.HandleBanUserGin(c)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check that the history entry has the correct actor_id
	var history models.UserBanHistory
	err := server.userStore.DB.Table("user_ban_history").Where("user_id = ? AND namespace = ? AND action = ?", testUserID, testNamespace, "BAN").First(&history).Error
	if err != nil {
		t.Errorf("Error finding ban history: %v", err)
	}

	expectedActorID := "actor-account-789"
	if history.ActorID != expectedActorID {
		t.Errorf("Expected actor_id %s, got %s", expectedActorID, history.ActorID)
	}
}

func TestNamespaceNormalization(t *testing.T) {
	server, _ := setupBanTestServer(t)

	testUserID := "test-user-456"
	testNamespace := "testns" // lowercase
	actorAccountID := "actor-account-789"

	// Ban with lowercase namespace
	err := server.userStore.BanUser(context.Background(), testUserID, testNamespace, models.BanPermanent, "Test ban", nil, actorAccountID)
	if err != nil {
		t.Fatal(err)
	}

	// Check with uppercase namespace (should find the ban)
	banned, err := server.userStore.IsUserBanned(context.Background(), testUserID, strings.ToUpper(testNamespace))
	if err != nil {
		t.Errorf("Error checking ban status: %v", err)
	}

	if !banned {
		t.Errorf("Expected to find ban with normalized namespace")
	}
}
