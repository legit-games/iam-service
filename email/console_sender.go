package email

import (
	"context"
	"log"
)

// ConsoleSender logs emails to console (for development/testing)
type ConsoleSender struct{}

// NewConsoleSender creates a console-based email sender
func NewConsoleSender() Sender {
	return &ConsoleSender{}
}

// SendPasswordReset logs the password reset code to console
func (c *ConsoleSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
	log.Printf("[EMAIL] Password Reset Code")
	log.Printf("  To: %s", data.To)
	log.Printf("  Username: %s", data.Username)
	log.Printf("  Code: %s", data.Code)
	log.Printf("  Expires in: %d minutes", data.ExpiresInMin)
	return nil
}

// SendEmail logs the email to console
func (c *ConsoleSender) SendEmail(ctx context.Context, data EmailData) error {
	log.Printf("[EMAIL] Sending Email")
	log.Printf("  From: %s <%s>", data.FromName, data.FromAddress)
	log.Printf("  To: %s", data.To)
	log.Printf("  Subject: %s", data.Subject)
	log.Printf("  Body: %s", data.TextBody)
	return nil
}

// Health always returns nil for console sender
func (c *ConsoleSender) Health(ctx context.Context) error {
	return nil
}

// ProviderType returns the provider type
func (c *ConsoleSender) ProviderType() ProviderType {
	return ProviderTypeConsole
}

// NoOpSender is a no-operation sender that discards emails silently
type NoOpSender struct{}

// NewNoOpSender creates a no-operation email sender
func NewNoOpSender() Sender {
	return &NoOpSender{}
}

// SendPasswordReset does nothing and returns nil
func (n *NoOpSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
	return nil
}

// SendEmail does nothing and returns nil
func (n *NoOpSender) SendEmail(ctx context.Context, data EmailData) error {
	return nil
}

// Health always returns nil for no-op sender
func (n *NoOpSender) Health(ctx context.Context) error {
	return nil
}

// ProviderType returns the provider type
func (n *NoOpSender) ProviderType() ProviderType {
	return ProviderTypeConsole
}
