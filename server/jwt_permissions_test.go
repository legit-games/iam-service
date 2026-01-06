package server

import (
	"context"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/golang-jwt/jwt/v5"
)

// TestJWTPermissionsBasic tests the basic JWT permission functionality
func TestJWTPermissionsBasic(t *testing.T) {
	// Create JWT generator
	gen := generates.NewJWTAccessGenerate("", []byte("test-key"), jwt.SigningMethodHS256)

	// Create mock client and token info
	client := &models.Client{ID: "test-client", Secret: "secret"}
	tokenInfo := &models.Token{
		AccessCreateAt:  time.Now(),
		AccessExpiresIn: time.Hour,
	}

	// Test 1: Without context values (should have empty permissions)
	ctx := context.Background()
	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "test-user",
		TokenInfo: tokenInfo,
	}

	accessToken, _, err := gen.Token(ctx, data, false)
	if err != nil {
		t.Fatalf("Failed to generate token without context: %v", err)
	}

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-key"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token without context: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if perms, exists := claims["permissions"]; exists {
			t.Errorf("Expected no permissions without context, but got: %v", perms)
		} else {
			t.Log("✅ Test 1 PASSED: No permissions without context")
		}
	} else {
		t.Error("Invalid JWT token without context")
	}

	// Test 2: With context but no namespace (should have empty permissions)
	ctx2 := context.WithValue(context.Background(), "perm_resolver", func(c context.Context, userID, ns string) []string {
		return []string{"SHOULD_NOT_APPEAR"}
	})

	accessToken2, _, err := gen.Token(ctx2, data, false)
	if err != nil {
		t.Fatalf("Failed to generate token with resolver but no namespace: %v", err)
	}

	token2, err := jwt.Parse(accessToken2, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-key"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token with resolver but no namespace: %v", err)
	}

	if claims2, ok := token2.Claims.(jwt.MapClaims); ok && token2.Valid {
		if perms, exists := claims2["permissions"]; exists {
			t.Errorf("Expected no permissions without namespace, but got: %v", perms)
		} else {
			t.Log("✅ Test 2 PASSED: No permissions without namespace")
		}
	} else {
		t.Error("Invalid JWT token with resolver but no namespace")
	}

	// Test 3: With both context and namespace (should have permissions)
	ctx3 := context.WithValue(context.Background(), "ns", "TESTNS")
	ctx3 = context.WithValue(ctx3, "perm_resolver", func(c context.Context, userID, ns string) []string {
		if userID == "test-user" && ns == "TESTNS" {
			return []string{"TEST_PERMISSION"}
		}
		return []string{}
	})

	accessToken3, _, err := gen.Token(ctx3, data, false)
	if err != nil {
		t.Fatalf("Failed to generate token with full context: %v", err)
	}

	token3, err := jwt.Parse(accessToken3, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-key"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token with full context: %v", err)
	}

	if claims3, ok := token3.Claims.(jwt.MapClaims); ok && token3.Valid {
		if perms, exists := claims3["permissions"]; exists {
			if permsArray, ok := perms.([]interface{}); ok && len(permsArray) > 0 {
				if permsArray[0].(string) == "TEST_PERMISSION" {
					t.Log("✅ Test 3 PASSED: Found expected permission in JWT")
				} else {
					t.Errorf("Expected TEST_PERMISSION, got %v", permsArray[0])
				}
			} else {
				t.Errorf("Permissions array is wrong type or empty: %v", perms)
			}
		} else {
			t.Error("Expected permissions in JWT with full context but not found")
		}
	} else {
		t.Error("Invalid JWT token with full context")
	}
}
