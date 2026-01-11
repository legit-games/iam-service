package store

import (
	"context"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// SystemSetting represents a system configuration setting.
type SystemSetting struct {
	Key         string    `gorm:"column:key;primaryKey" json:"key"`
	Value       string    `gorm:"column:value" json:"value"`
	Description string    `gorm:"column:description" json:"description,omitempty"`
	Category    string    `gorm:"column:category" json:"category"`
	IsSecret    bool      `gorm:"column:is_secret" json:"is_secret"`
	CreatedAt   time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (SystemSetting) TableName() string {
	return "system_settings"
}

// SystemSettingsStore manages system settings in the database.
type SystemSettingsStore struct {
	db *gorm.DB
}

// NewSystemSettingsStore creates a new SystemSettingsStore.
func NewSystemSettingsStore(db *gorm.DB) *SystemSettingsStore {
	return &SystemSettingsStore{db: db}
}

// Get retrieves a single setting by key.
func (s *SystemSettingsStore) Get(ctx context.Context, key string) (*SystemSetting, error) {
	var setting SystemSetting
	if err := s.db.WithContext(ctx).Where("key = ?", key).First(&setting).Error; err != nil {
		return nil, err
	}
	return &setting, nil
}

// GetValue retrieves just the value of a setting by key.
func (s *SystemSettingsStore) GetValue(ctx context.Context, key string) (string, error) {
	setting, err := s.Get(ctx, key)
	if err != nil {
		return "", err
	}
	return setting.Value, nil
}

// GetValueOrDefault retrieves the value or returns a default if not found.
func (s *SystemSettingsStore) GetValueOrDefault(ctx context.Context, key, defaultValue string) string {
	value, err := s.GetValue(ctx, key)
	if err != nil || value == "" {
		return defaultValue
	}
	return value
}

// GetBool retrieves a boolean setting.
func (s *SystemSettingsStore) GetBool(ctx context.Context, key string, defaultValue bool) bool {
	value, err := s.GetValue(ctx, key)
	if err != nil || value == "" {
		return defaultValue
	}
	return value == "true" || value == "1"
}

// GetInt retrieves an integer setting.
func (s *SystemSettingsStore) GetInt(ctx context.Context, key string, defaultValue int) int {
	value, err := s.GetValue(ctx, key)
	if err != nil || value == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intVal
}

// Set creates or updates a setting.
func (s *SystemSettingsStore) Set(ctx context.Context, key, value string) error {
	return s.db.WithContext(ctx).Exec(`
		INSERT INTO system_settings (key, value, updated_at)
		VALUES (?, ?, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`, key, value).Error
}

// SetWithMeta creates or updates a setting with metadata.
func (s *SystemSettingsStore) SetWithMeta(ctx context.Context, setting *SystemSetting) error {
	setting.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(setting).Error
}

// Delete removes a setting.
func (s *SystemSettingsStore) Delete(ctx context.Context, key string) error {
	return s.db.WithContext(ctx).Delete(&SystemSetting{}, "key = ?", key).Error
}

// ListByCategory retrieves all settings in a category.
func (s *SystemSettingsStore) ListByCategory(ctx context.Context, category string) ([]SystemSetting, error) {
	var settings []SystemSetting
	if err := s.db.WithContext(ctx).Where("category = ?", category).Order("key").Find(&settings).Error; err != nil {
		return nil, err
	}
	return settings, nil
}

// ListAll retrieves all settings.
func (s *SystemSettingsStore) ListAll(ctx context.Context) ([]SystemSetting, error) {
	var settings []SystemSetting
	if err := s.db.WithContext(ctx).Order("category, key").Find(&settings).Error; err != nil {
		return nil, err
	}
	return settings, nil
}

// GetMultiple retrieves multiple settings by keys.
func (s *SystemSettingsStore) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	var settings []SystemSetting
	if err := s.db.WithContext(ctx).Where("key IN ?", keys).Find(&settings).Error; err != nil {
		return nil, err
	}
	result := make(map[string]string, len(settings))
	for _, setting := range settings {
		result[setting.Key] = setting.Value
	}
	return result, nil
}

// SetMultiple sets multiple settings at once.
func (s *SystemSettingsStore) SetMultiple(ctx context.Context, settings map[string]string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for key, value := range settings {
			if err := tx.Exec(`
				INSERT INTO system_settings (key, value, updated_at)
				VALUES (?, ?, NOW())
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
			`, key, value).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// EmailConfig holds email configuration retrieved from settings.
type EmailConfig struct {
	Provider     string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromAddress  string
	FromName     string
	UseTLS       bool
	UseSSL       bool
	SkipVerify   bool
	AppName      string
	SupportEmail string
}

// GetEmailConfig retrieves all email configuration settings.
func (s *SystemSettingsStore) GetEmailConfig(ctx context.Context) (*EmailConfig, error) {
	keys := []string{
		"email.provider",
		"email.smtp.host",
		"email.smtp.port",
		"email.smtp.username",
		"email.smtp.password",
		"email.smtp.from_address",
		"email.smtp.from_name",
		"email.smtp.use_tls",
		"email.smtp.use_ssl",
		"email.smtp.skip_verify",
		"email.app_name",
		"email.support_email",
	}

	values, err := s.GetMultiple(ctx, keys)
	if err != nil {
		return nil, err
	}

	port := 587
	if portStr, ok := values["email.smtp.port"]; ok && portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	return &EmailConfig{
		Provider:     getOrDefault(values, "email.provider", "console"),
		SMTPHost:     values["email.smtp.host"],
		SMTPPort:     port,
		SMTPUsername: values["email.smtp.username"],
		SMTPPassword: values["email.smtp.password"],
		FromAddress:  values["email.smtp.from_address"],
		FromName:     getOrDefault(values, "email.smtp.from_name", "OAuth2 Service"),
		UseTLS:       values["email.smtp.use_tls"] == "true",
		UseSSL:       values["email.smtp.use_ssl"] == "true",
		SkipVerify:   values["email.smtp.skip_verify"] == "true",
		AppName:      getOrDefault(values, "email.app_name", "OAuth2 Service"),
		SupportEmail: values["email.support_email"],
	}, nil
}

func getOrDefault(m map[string]string, key, defaultValue string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return defaultValue
}
