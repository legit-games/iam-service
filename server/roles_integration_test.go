package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gavv/httpexpect/v2"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// Test integration path that uses the configured Postgres to resolve roles -> permissions into JWT
func TestPasswordGrant_UserRolePermissionsInJWT_WithDB(t *testing.T) {
	// Setup manager and server
	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())
	m.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	cliStore := store.NewClientStore()
	_ = cliStore.Set("confidential", &models.Client{ID: "confidential", Secret: "secret"})
	m.MapClientStorage(cliStore)

	s := NewDefaultServer(m)
	s.SetClientInfoHandler(ClientFormHandler)
	s.SetAllowedGrantType(oauth2.PasswordCredentials)
	s.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		if username == "test" && password == "test" {
			return "user-1", nil
		}
		return "", nil
	})

	// Seed DB: account, user, role, user_role
	db, err := s.GetIAMWriteDB()
	if err != nil {
		t.Skipf("no DB configured for integration test: %v", err)
		return
	}

	ns := "TESTNS"
	perm := "ADMIN:NAMESPACE:TESTNS:ROLE_READ"
	// Best-effort cleanup first
	db.Exec(`DELETE FROM user_roles WHERE user_id = ?`, "user-1")
	db.Exec(`DELETE FROM roles WHERE id = ?`, "role-1")
	db.Exec(`DELETE FROM account_users WHERE user_id = ?`, "user-1")
	db.Exec(`DELETE FROM users WHERE id = ?`, "user-1")
	db.Exec(`DELETE FROM accounts WHERE id = ?`, "acc-1")

	if err := db.Exec(`INSERT INTO accounts(id, username, password_hash) VALUES(?,?,?)`, "acc-1", "user-1", "x").Error; err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if err := db.Exec(`INSERT INTO users(id, namespace, user_type, orphaned) VALUES(?,?,?,FALSE)`, "user-1", ns, "BODY").Error; err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := db.Exec(`INSERT INTO account_users(account_id, user_id) VALUES(?,?)`, "acc-1", "user-1").Error; err != nil {
		t.Fatalf("insert account_users: %v", err)
	}
	permJSON := `{"permissions":["` + perm + `"]}`
	if err := db.Exec(`INSERT INTO roles(id, namespace, name, role_type, permissions, description) VALUES(?,?,?,?,?::jsonb,?)`, "role-1", ns, "MOD", "USER", permJSON, "test role").Error; err != nil {
		t.Fatalf("insert role: %v", err)
	}
	if err := db.Exec(`INSERT INTO user_roles(id, user_id, role_id, namespace) VALUES(?,?,?,?)`, "ur-1", "user-1", "role-1", ns).Error; err != nil {
		t.Fatalf("insert user_role: %v", err)
	}
	defer func() {
		db.Exec(`DELETE FROM user_roles WHERE user_id = ?`, "user-1")
		db.Exec(`DELETE FROM roles WHERE id = ?`, "role-1")
		db.Exec(`DELETE FROM account_users WHERE user_id = ?`, "user-1")
		db.Exec(`DELETE FROM users WHERE id = ?`, "user-1")
		db.Exec(`DELETE FROM accounts WHERE id = ?`, "acc-1")
	}()

	// Start HTTP server and request token
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = s.HandleTokenRequest(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	e := httpexpect.New(t, ts.URL)
	obj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "test").
		WithFormField("password", "test").
		WithFormField("client_id", "confidential").
		WithFormField("client_secret", "secret").
		WithFormField("ns", ns).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	access := obj.Value("access_token").String().Raw()
	if access == "" {
		t.Fatalf("no access token returned")
	}
	parts := strings.Split(access, ".")
	if len(parts) < 2 {
		t.Fatalf("invalid jwt")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	arr, ok := claims["permissions"].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("expected permissions in jwt, got: %v", claims)
	}
	found := false
	for _, v := range arr {
		if s, ok := v.(string); ok && s == perm {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected permission %s in jwt, got %v", perm, arr)
	}
}
