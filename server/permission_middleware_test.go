package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/permission"
)

// Build an unsigned JWT with given payload claims
func makeBearerWithClaims(t *testing.T, m map[string]any) string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(m)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	return "Bearer " + h + "." + p + "."
}

// helper to build a test router
func buildRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

func TestRequireAuthorization_AllowsWhenPermissionMatches(t *testing.T) {
	r := buildRouter()
	// route requiring CREATE on ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT
	r.GET("/clients", RequireAuthorization("ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", permission.CREATE, nil), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	bearer := makeBearerWithClaims(t, map[string]any{
		"permissions": []string{"ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE"},
		"accountId":   "018b28126a5f767500000009a4404002",
		"namespace":   "LEGIT-GAMES",
	})
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	req.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuthorization_ForbiddenWhenMissingAction(t *testing.T) {
	r := buildRouter()
	// route requiring UPDATE which user doesn't have
	r.GET("/clients", RequireAuthorization("ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", permission.UPDATE, nil), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	bearer := makeBearerWithClaims(t, map[string]any{
		"permissions": []string{"ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE"},
		"accountId":   "018b28126a5f767500000009a4404002",
		"namespace":   "LEGIT-GAMES",
	})
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	req.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireAuthorization_PlaceholderReplacedWithPathParam(t *testing.T) {
	r := buildRouter()
	// route requiring READ on PUBLIC:ACCOUNT:{accountId} and uses path param replacement
	r.GET("/accounts/:accountId", RequireAuthorization("PUBLIC:ACCOUNT:{accountId}", permission.READ, nil), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	bearer := makeBearerWithClaims(t, map[string]any{
		"permissions": []string{"PUBLIC:ACCOUNT:{accountId}_READ"},
		"accountId":   "018b28126a5f767500000009a4404002",
		"namespace":   "LEGIT-GAMES",
	})
	req := httptest.NewRequest(http.MethodGet, "/accounts/018b28126a5f767500000009a4404002", nil)
	req.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuthorization_WildcardResourceAllowsRead(t *testing.T) {
	r := buildRouter()
	// user has ADMIN:NAMESPACE:LEGIT-GAMES:*_READ
	r.GET("/docs", RequireAuthorization("ADMIN:NAMESPACE:LEGIT-GAMES:DOCUMENT", permission.READ, nil), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	bearer := makeBearerWithClaims(t, map[string]any{
		"permissions": []string{"ADMIN:NAMESPACE:LEGIT-GAMES:*_READ"},
		"accountId":   "018b28126a5f767500000009a4404002",
		"namespace":   "LEGIT-GAMES",
	})
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 via wildcard READ, got %d", w.Code)
	}
}
