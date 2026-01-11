package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/store"
)

// GetAllSettingsResponse represents all settings by category.
type GetAllSettingsResponse struct {
	Settings map[string][]SettingItem `json:"settings"`
}

// SettingItem represents a single setting item.
type SettingItem struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	IsSecret    bool   `json:"is_secret"`
}

// HandleGetAllSettingsGin retrieves all settings grouped by category.
// GET /iam/v1/admin/settings
func (s *Server) HandleGetAllSettingsGin(c *gin.Context) {
	if s.settingsStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Settings store not configured",
		})
		return
	}

	ctx := c.Request.Context()
	settings, err := s.settingsStore.ListAll(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to retrieve settings",
		})
		return
	}

	// Group by category
	grouped := make(map[string][]SettingItem)
	for _, setting := range settings {
		value := setting.Value
		if setting.IsSecret && value != "" {
			value = "********"
		}
		grouped[setting.Category] = append(grouped[setting.Category], SettingItem{
			Key:         setting.Key,
			Value:       value,
			Description: setting.Description,
			IsSecret:    setting.IsSecret,
		})
	}

	c.JSON(http.StatusOK, GetAllSettingsResponse{Settings: grouped})
}

// RegistrationSettingsResponse represents registration-related settings.
type RegistrationSettingsResponse struct {
	RequireEmailVerification bool   `json:"require_email_verification"`
	Namespace                string `json:"namespace"`
}

// HandleGetRegistrationSettingsGin retrieves registration settings for a namespace.
// GET /iam/v1/admin/namespaces/:ns/settings/registration
func (s *Server) HandleGetRegistrationSettingsGin(c *gin.Context) {
	if s.settingsStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Settings store not configured",
		})
		return
	}

	namespace := c.Param("ns")
	ctx := c.Request.Context()
	config, err := s.settingsStore.GetRegistrationConfig(ctx, namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to retrieve registration settings",
		})
		return
	}

	c.JSON(http.StatusOK, RegistrationSettingsResponse{
		RequireEmailVerification: config.RequireEmailVerification,
		Namespace:                namespace,
	})
}

// HandleUpdateRegistrationSettingsGin updates registration settings for a namespace.
// PUT /iam/v1/admin/namespaces/:ns/settings/registration
func (s *Server) HandleUpdateRegistrationSettingsGin(c *gin.Context) {
	if s.settingsStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Settings store not configured",
		})
		return
	}

	namespace := c.Param("ns")
	var req struct {
		RequireEmailVerification bool `json:"require_email_verification"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
		})
		return
	}

	ctx := c.Request.Context()
	config := &store.RegistrationConfig{
		RequireEmailVerification: req.RequireEmailVerification,
		Namespace:                namespace,
	}
	if err := s.settingsStore.SetRegistrationConfig(ctx, namespace, config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to update registration settings",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":                    true,
		"namespace":                  namespace,
		"require_email_verification": req.RequireEmailVerification,
	})
}
