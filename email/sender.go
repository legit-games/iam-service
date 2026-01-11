package email

import (
	"context"
	"encoding/json"
)

// ProviderType represents the type of email provider
type ProviderType string

const (
	ProviderTypeConsole   ProviderType = "console"
	ProviderTypeSMTP      ProviderType = "smtp"
	ProviderTypeSendGrid  ProviderType = "sendgrid"
	ProviderTypeAWSSES    ProviderType = "aws_ses"
	ProviderTypeMailgun   ProviderType = "mailgun"
	ProviderTypeMailchimp ProviderType = "mailchimp"
)

// SupportedProviders returns list of all supported provider types
func SupportedProviders() []ProviderInfo {
	return []ProviderInfo{
		{Type: ProviderTypeConsole, Name: "Console (Development)", Description: "Prints emails to server console for development"},
		{Type: ProviderTypeSMTP, Name: "SMTP", Description: "Generic SMTP server"},
		{Type: ProviderTypeSendGrid, Name: "SendGrid", Description: "SendGrid transactional email service"},
		{Type: ProviderTypeAWSSES, Name: "AWS SES", Description: "Amazon Simple Email Service"},
		{Type: ProviderTypeMailgun, Name: "Mailgun", Description: "Mailgun email API"},
		{Type: ProviderTypeMailchimp, Name: "Mailchimp Transactional", Description: "Mailchimp Transactional (Mandrill)"},
	}
}

// ProviderInfo contains metadata about a provider type
type ProviderInfo struct {
	Type        ProviderType `json:"type"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
}

// ProviderConfig represents configuration for an email provider
type ProviderConfig struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	ProviderType   ProviderType    `json:"provider_type"`
	IsActive       bool            `json:"is_active"`
	IsDefault      bool            `json:"is_default"`
	FromAddress    string          `json:"from_address"`
	FromName       string          `json:"from_name"`
	ReplyToAddress string          `json:"reply_to_address,omitempty"`
	Config         json.RawMessage `json:"config"`
	AppName        string          `json:"app_name"`
	SupportEmail   string          `json:"support_email,omitempty"`
	Description    string          `json:"description,omitempty"`
}

// SMTPConfig holds SMTP-specific configuration
type SMTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	UseTLS     bool   `json:"use_tls"`
	UseSSL     bool   `json:"use_ssl"`
	SkipVerify bool   `json:"skip_verify"`
}

// SendGridConfig holds SendGrid-specific configuration
type SendGridConfig struct {
	APIKey string `json:"api_key"`
}

// AWSSESConfig holds AWS SES-specific configuration
type AWSSESConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	// Optional: Use IAM role instead of credentials
	UseIAMRole bool `json:"use_iam_role"`
}

// MailgunConfig holds Mailgun-specific configuration
type MailgunConfig struct {
	Domain       string `json:"domain"`
	APIKey       string `json:"api_key"`
	APIBase      string `json:"api_base"` // "https://api.mailgun.net/v3" or "https://api.eu.mailgun.net/v3"
}

// MailchimpConfig holds Mailchimp Transactional (Mandrill) configuration
type MailchimpConfig struct {
	APIKey string `json:"api_key"`
}

// PasswordResetEmailData contains data for password reset emails
type PasswordResetEmailData struct {
	To           string
	Username     string
	Code         string
	ExpiresInMin int
	AppName      string
	SupportEmail string
}

// EmailData represents generic email data
type EmailData struct {
	To          string
	Subject     string
	TextBody    string
	HTMLBody    string
	FromAddress string
	FromName    string
	ReplyTo     string
}

// Sender defines the interface for sending emails
type Sender interface {
	// SendPasswordReset sends a password reset code email
	SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error

	// SendEmail sends a generic email
	SendEmail(ctx context.Context, data EmailData) error

	// Health checks if the email service is available
	Health(ctx context.Context) error

	// ProviderType returns the type of the provider
	ProviderType() ProviderType
}

// Factory creates a Sender from a ProviderConfig
func Factory(config *ProviderConfig) (Sender, error) {
	switch config.ProviderType {
	case ProviderTypeConsole:
		return NewConsoleSender(), nil
	case ProviderTypeSMTP:
		return NewSMTPSenderFromConfig(config)
	case ProviderTypeSendGrid:
		return NewSendGridSenderFromConfig(config)
	case ProviderTypeAWSSES:
		return NewAWSSESSenderFromConfig(config)
	case ProviderTypeMailgun:
		return NewMailgunSenderFromConfig(config)
	case ProviderTypeMailchimp:
		return NewMailchimpSenderFromConfig(config)
	default:
		return NewConsoleSender(), nil
	}
}
