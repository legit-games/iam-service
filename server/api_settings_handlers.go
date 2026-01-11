package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
