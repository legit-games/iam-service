package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4/email"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// EmailProvider represents an email provider configuration in the database
type EmailProvider struct {
	ID             string          `gorm:"column:id;primaryKey" json:"id"`
	NamespaceID    *string         `gorm:"column:namespace_id" json:"namespace_id,omitempty"`
	Name           string          `gorm:"column:name" json:"name"`
	ProviderType   string          `gorm:"column:provider_type" json:"provider_type"`
	IsActive       bool            `gorm:"column:is_active" json:"is_active"`
	IsDefault      bool            `gorm:"column:is_default" json:"is_default"`
	FromAddress    string          `gorm:"column:from_address" json:"from_address"`
	FromName       string          `gorm:"column:from_name" json:"from_name"`
	ReplyToAddress string          `gorm:"column:reply_to_address" json:"reply_to_address,omitempty"`
	Config         json.RawMessage `gorm:"column:config;type:jsonb" json:"config"`
	AppName        string          `gorm:"column:app_name" json:"app_name"`
	SupportEmail   string          `gorm:"column:support_email" json:"support_email,omitempty"`
	Description    string          `gorm:"column:description" json:"description,omitempty"`
	CreatedAt      time.Time       `gorm:"column:created_at" json:"created_at"`
	UpdatedAt      time.Time       `gorm:"column:updated_at" json:"updated_at"`
}

func (EmailProvider) TableName() string {
	return "email_providers"
}

// ToProviderConfig converts to email.ProviderConfig
func (e *EmailProvider) ToProviderConfig() *email.ProviderConfig {
	return &email.ProviderConfig{
		ID:             e.ID,
		Name:           e.Name,
		ProviderType:   email.ProviderType(e.ProviderType),
		IsActive:       e.IsActive,
		IsDefault:      e.IsDefault,
		FromAddress:    e.FromAddress,
		FromName:       e.FromName,
		ReplyToAddress: e.ReplyToAddress,
		Config:         e.Config,
		AppName:        e.AppName,
		SupportEmail:   e.SupportEmail,
		Description:    e.Description,
	}
}

// EmailProviderStore manages email providers in the database
type EmailProviderStore struct {
	db *gorm.DB
}

// NewEmailProviderStore creates a new EmailProviderStore
func NewEmailProviderStore(db *gorm.DB) *EmailProviderStore {
	return &EmailProviderStore{db: db}
}

// Create creates a new email provider
func (s *EmailProviderStore) Create(ctx context.Context, provider *EmailProvider) error {
	if provider.ID == "" {
		provider.ID = uuid.New().String()
	}
	provider.CreatedAt = time.Now()
	provider.UpdatedAt = time.Now()

	return s.db.WithContext(ctx).Create(provider).Error
}

// GetByID retrieves an email provider by ID
func (s *EmailProviderStore) GetByID(ctx context.Context, id string) (*EmailProvider, error) {
	var provider EmailProvider
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&provider).Error; err != nil {
		return nil, err
	}
	return &provider, nil
}

// GetByIDAndNamespace retrieves an email provider by ID within a namespace
func (s *EmailProviderStore) GetByIDAndNamespace(ctx context.Context, id, namespaceID string) (*EmailProvider, error) {
	var provider EmailProvider
	if err := s.db.WithContext(ctx).Where("id = ? AND namespace_id = ?", id, namespaceID).First(&provider).Error; err != nil {
		return nil, err
	}
	return &provider, nil
}

// GetDefault retrieves the default email provider for a namespace
func (s *EmailProviderStore) GetDefault(ctx context.Context, namespaceID string) (*EmailProvider, error) {
	var provider EmailProvider
	err := s.db.WithContext(ctx).
		Where("namespace_id = ? AND is_default = ? AND is_active = ?", namespaceID, true, true).
		First(&provider).Error
	if err != nil {
		return nil, err
	}
	return &provider, nil
}

// GetActiveByType retrieves an active email provider by type within a namespace
func (s *EmailProviderStore) GetActiveByType(ctx context.Context, namespaceID, providerType string) (*EmailProvider, error) {
	var provider EmailProvider
	if err := s.db.WithContext(ctx).
		Where("namespace_id = ? AND provider_type = ? AND is_active = ?", namespaceID, providerType, true).
		First(&provider).Error; err != nil {
		return nil, err
	}
	return &provider, nil
}

// ListByNamespace retrieves all email providers for a namespace
func (s *EmailProviderStore) ListByNamespace(ctx context.Context, namespaceID string) ([]EmailProvider, error) {
	var providers []EmailProvider
	if err := s.db.WithContext(ctx).
		Where("namespace_id = ?", namespaceID).
		Order("is_default DESC, created_at DESC").
		Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

// List retrieves all email providers (for admin use)
func (s *EmailProviderStore) List(ctx context.Context) ([]EmailProvider, error) {
	var providers []EmailProvider
	if err := s.db.WithContext(ctx).Order("namespace_id NULLS FIRST, created_at DESC").Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

// ListActive retrieves all active email providers for a namespace
func (s *EmailProviderStore) ListActive(ctx context.Context, namespaceID string) ([]EmailProvider, error) {
	var providers []EmailProvider
	if err := s.db.WithContext(ctx).
		Where("namespace_id = ? AND is_active = ?", namespaceID, true).
		Order("is_default DESC, created_at DESC").
		Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

// Update updates an email provider
func (s *EmailProviderStore) Update(ctx context.Context, provider *EmailProvider) error {
	provider.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(provider).Error
}

// Delete deletes an email provider
func (s *EmailProviderStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&EmailProvider{}, "id = ?", id).Error
}

// DeleteByIDAndNamespace deletes an email provider within a namespace
func (s *EmailProviderStore) DeleteByIDAndNamespace(ctx context.Context, id, namespaceID string) error {
	return s.db.WithContext(ctx).Delete(&EmailProvider{}, "id = ? AND namespace_id = ?", id, namespaceID).Error
}

// SetDefault sets a provider as the default within its namespace (unsets others in same namespace)
func (s *EmailProviderStore) SetDefault(ctx context.Context, id string) error {
	// Get the provider to find its namespace
	provider, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Unset current default in the same namespace
		if provider.NamespaceID != nil {
			if err := tx.Model(&EmailProvider{}).
				Where("namespace_id = ? AND is_default = ?", *provider.NamespaceID, true).
				Update("is_default", false).Error; err != nil {
				return err
			}
		} else {
			// Global namespace
			if err := tx.Model(&EmailProvider{}).
				Where("namespace_id IS NULL AND is_default = ?", true).
				Update("is_default", false).Error; err != nil {
				return err
			}
		}

		// Set new default
		if err := tx.Model(&EmailProvider{}).Where("id = ?", id).Updates(map[string]interface{}{
			"is_default": true,
			"is_active":  true,
			"updated_at": time.Now(),
		}).Error; err != nil {
			return err
		}

		return nil
	})
}

// SetActive sets a provider's active status
func (s *EmailProviderStore) SetActive(ctx context.Context, id string, active bool) error {
	return s.db.WithContext(ctx).Model(&EmailProvider{}).Where("id = ?", id).Updates(map[string]interface{}{
		"is_active":  active,
		"updated_at": time.Now(),
	}).Error
}

// GetSender returns a Sender for the default provider in a namespace
func (s *EmailProviderStore) GetSender(ctx context.Context, namespaceID string) (email.Sender, error) {
	provider, err := s.GetDefault(ctx, namespaceID)
	if err != nil {
		// No provider configured for this namespace
		return nil, fmt.Errorf("no email provider configured for namespace: %s", namespaceID)
	}

	return email.Factory(provider.ToProviderConfig())
}

// GetSenderByID returns a Sender for a specific provider
func (s *EmailProviderStore) GetSenderByID(ctx context.Context, id string) (email.Sender, error) {
	provider, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	return email.Factory(provider.ToProviderConfig())
}

// CreateProviderRequest represents a request to create an email provider
type CreateProviderRequest struct {
	Name           string          `json:"name" binding:"required"`
	ProviderType   string          `json:"provider_type" binding:"required"`
	FromAddress    string          `json:"from_address" binding:"required,email"`
	FromName       string          `json:"from_name"`
	ReplyToAddress string          `json:"reply_to_address"`
	Config         json.RawMessage `json:"config" binding:"required"`
	AppName        string          `json:"app_name"`
	SupportEmail   string          `json:"support_email"`
	Description    string          `json:"description"`
	IsActive       bool            `json:"is_active"`
	SetAsDefault   bool            `json:"set_as_default"`
}

// UpdateProviderRequest represents a request to update an email provider
type UpdateProviderRequest struct {
	Name           string          `json:"name"`
	FromAddress    string          `json:"from_address"`
	FromName       string          `json:"from_name"`
	ReplyToAddress string          `json:"reply_to_address"`
	Config         json.RawMessage `json:"config"`
	AppName        string          `json:"app_name"`
	SupportEmail   string          `json:"support_email"`
	Description    string          `json:"description"`
	IsActive       *bool           `json:"is_active"`
}

// Validate validates that the provider type is supported and config is valid
func (r *CreateProviderRequest) Validate() error {
	validTypes := map[string]bool{
		"console":   true,
		"smtp":      true,
		"sendgrid":  true,
		"aws_ses":   true,
		"mailgun":   true,
		"mailchimp": true,
	}

	if !validTypes[r.ProviderType] {
		return fmt.Errorf("unsupported provider type: %s", r.ProviderType)
	}

	// Validate config based on provider type
	switch r.ProviderType {
	case "smtp":
		var cfg email.SMTPConfig
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return fmt.Errorf("invalid SMTP config: %w", err)
		}
		if cfg.Host == "" {
			return fmt.Errorf("SMTP host is required")
		}
	case "sendgrid":
		var cfg email.SendGridConfig
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return fmt.Errorf("invalid SendGrid config: %w", err)
		}
		if cfg.APIKey == "" {
			return fmt.Errorf("SendGrid API key is required")
		}
	case "aws_ses":
		var cfg email.AWSSESConfig
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return fmt.Errorf("invalid AWS SES config: %w", err)
		}
		if cfg.Region == "" {
			return fmt.Errorf("AWS region is required")
		}
	case "mailgun":
		var cfg email.MailgunConfig
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return fmt.Errorf("invalid Mailgun config: %w", err)
		}
		if cfg.Domain == "" || cfg.APIKey == "" {
			return fmt.Errorf("Mailgun domain and API key are required")
		}
	case "mailchimp":
		var cfg email.MailchimpConfig
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return fmt.Errorf("invalid Mailchimp config: %w", err)
		}
		if cfg.APIKey == "" {
			return fmt.Errorf("Mailchimp API key is required")
		}
	}

	return nil
}
