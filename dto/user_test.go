package dto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
)

func TestFromUserWithDisplayName(t *testing.T) {
	displayName := "John Doe"
	user := &models.User{
		ID:          "user-123",
		UserType:    models.UserHead,
		DisplayName: &displayName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	response := FromUser(user)

	if response.DisplayName == nil {
		t.Fatal("DisplayName should not be nil")
	}
	if *response.DisplayName != "John Doe" {
		t.Errorf("Expected DisplayName to be 'John Doe', got '%s'", *response.DisplayName)
	}
}

func TestFromUserWithoutDisplayName(t *testing.T) {
	user := &models.User{
		ID:          "user-123",
		UserType:    models.UserHead,
		DisplayName: nil,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	response := FromUser(user)

	if response.DisplayName != nil {
		t.Errorf("DisplayName should be nil, got '%s'", *response.DisplayName)
	}
}

func TestFromUsersWithDisplayName(t *testing.T) {
	displayName1 := "User One"
	displayName2 := "User Two"
	users := []*models.User{
		{
			ID:          "user-1",
			UserType:    models.UserHead,
			DisplayName: &displayName1,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "user-2",
			UserType:    models.UserBody,
			DisplayName: &displayName2,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	responses := FromUsers(users)

	if len(responses) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(responses))
	}

	if responses[0].DisplayName == nil || *responses[0].DisplayName != "User One" {
		t.Errorf("Expected first user DisplayName to be 'User One'")
	}
	if responses[1].DisplayName == nil || *responses[1].DisplayName != "User Two" {
		t.Errorf("Expected second user DisplayName to be 'User Two'")
	}
}

func TestUserResponseJSONSerialization(t *testing.T) {
	displayName := "Test User"
	response := UserResponse{
		ID:          "user-123",
		UserType:    models.UserHead,
		DisplayName: &displayName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["display_name"] != "Test User" {
		t.Errorf("Expected display_name to be 'Test User', got '%v'", result["display_name"])
	}
}

func TestUserResponseJSONOmitEmpty(t *testing.T) {
	response := UserResponse{
		ID:          "user-123",
		UserType:    models.UserHead,
		DisplayName: nil,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if _, exists := result["display_name"]; exists {
		t.Error("display_name should be omitted when nil")
	}
}

func TestFromUserPreservesAllFields(t *testing.T) {
	displayName := "Complete User"
	namespace := "TESTNS"
	providerType := "google"
	providerAccountID := "google-123"
	now := time.Now()

	user := &models.User{
		ID:                "user-full",
		Namespace:         &namespace,
		UserType:          models.UserBody,
		DisplayName:       &displayName,
		ProviderType:      &providerType,
		ProviderAccountID: &providerAccountID,
		Orphaned:          false,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	response := FromUser(user)

	if response.ID != user.ID {
		t.Errorf("ID mismatch: expected '%s', got '%s'", user.ID, response.ID)
	}
	if *response.Namespace != *user.Namespace {
		t.Errorf("Namespace mismatch: expected '%s', got '%s'", *user.Namespace, *response.Namespace)
	}
	if response.UserType != user.UserType {
		t.Errorf("UserType mismatch: expected '%s', got '%s'", user.UserType, response.UserType)
	}
	if *response.DisplayName != *user.DisplayName {
		t.Errorf("DisplayName mismatch: expected '%s', got '%s'", *user.DisplayName, *response.DisplayName)
	}
	if *response.ProviderType != *user.ProviderType {
		t.Errorf("ProviderType mismatch: expected '%s', got '%s'", *user.ProviderType, *response.ProviderType)
	}
	if *response.ProviderAccountID != *user.ProviderAccountID {
		t.Errorf("ProviderAccountID mismatch: expected '%s', got '%s'", *user.ProviderAccountID, *response.ProviderAccountID)
	}
	if response.Orphaned != user.Orphaned {
		t.Errorf("Orphaned mismatch: expected '%v', got '%v'", user.Orphaned, response.Orphaned)
	}
}
