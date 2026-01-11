package email

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MailgunSender sends emails via Mailgun API
type MailgunSender struct {
	domain       string
	apiKey       string
	apiBase      string
	fromAddress  string
	fromName     string
	appName      string
	supportEmail string
	httpClient   *http.Client
}

// NewMailgunSenderFromConfig creates a new Mailgun sender from ProviderConfig
func NewMailgunSenderFromConfig(pc *ProviderConfig) (Sender, error) {
	var cfg MailgunConfig
	if err := json.Unmarshal(pc.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid Mailgun config: %w", err)
	}

	if cfg.Domain == "" {
		return nil, fmt.Errorf("Mailgun domain is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Mailgun API key is required")
	}

	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = "https://api.mailgun.net/v3"
	}

	return &MailgunSender{
		domain:       cfg.Domain,
		apiKey:       cfg.APIKey,
		apiBase:      apiBase,
		fromAddress:  pc.FromAddress,
		fromName:     pc.FromName,
		appName:      pc.AppName,
		supportEmail: pc.SupportEmail,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SendPasswordReset sends a password reset email via Mailgun
func (s *MailgunSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
	appName := data.AppName
	if appName == "" {
		appName = s.appName
	}
	supportEmail := data.SupportEmail
	if supportEmail == "" {
		supportEmail = s.supportEmail
	}

	data.AppName = appName
	data.SupportEmail = supportEmail

	subject := fmt.Sprintf("Password Reset Code: %s", data.Code)
	htmlBody := s.renderPasswordResetHTML(data)
	textBody := s.renderPasswordResetText(data)

	return s.SendEmail(ctx, EmailData{
		To:          data.To,
		Subject:     subject,
		TextBody:    textBody,
		HTMLBody:    htmlBody,
		FromAddress: s.fromAddress,
		FromName:    s.fromName,
	})
}

// SendEmailVerification sends an email verification code via Mailgun
func (s *MailgunSender) SendEmailVerification(ctx context.Context, data EmailVerificationEmailData) error {
	appName := data.AppName
	if appName == "" {
		appName = s.appName
	}
	supportEmail := data.SupportEmail
	if supportEmail == "" {
		supportEmail = s.supportEmail
	}

	data.AppName = appName
	data.SupportEmail = supportEmail

	subject := fmt.Sprintf("Email Verification Code: %s", data.Code)
	htmlBody := s.renderEmailVerificationHTML(data)
	textBody := s.renderEmailVerificationText(data)

	return s.SendEmail(ctx, EmailData{
		To:          data.To,
		Subject:     subject,
		TextBody:    textBody,
		HTMLBody:    htmlBody,
		FromAddress: s.fromAddress,
		FromName:    s.fromName,
	})
}

// SendEmail sends an email via Mailgun API
func (s *MailgunSender) SendEmail(ctx context.Context, data EmailData) error {
	fromAddr := data.FromAddress
	if fromAddr == "" {
		fromAddr = s.fromAddress
	}
	fromName := data.FromName
	if fromName == "" {
		fromName = s.fromName
	}

	from := fromAddr
	if fromName != "" {
		from = fmt.Sprintf("%s <%s>", fromName, fromAddr)
	}

	// Build form data
	formData := url.Values{}
	formData.Set("from", from)
	formData.Set("to", data.To)
	formData.Set("subject", data.Subject)
	if data.TextBody != "" {
		formData.Set("text", data.TextBody)
	}
	if data.HTMLBody != "" {
		formData.Set("html", data.HTMLBody)
	}

	endpoint := fmt.Sprintf("%s/%s/messages", s.apiBase, s.domain)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create Mailgun request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Mailgun API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Mailgun API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// Health checks if Mailgun API is accessible
func (s *MailgunSender) Health(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/domains/%s", s.apiBase, s.domain)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.SetBasicAuth("api", s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Mailgun health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("Mailgun authentication failed: invalid API key")
	}

	if resp.StatusCode == 404 {
		return fmt.Errorf("Mailgun domain not found: %s", s.domain)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Mailgun health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// ProviderType returns the provider type
func (s *MailgunSender) ProviderType() ProviderType {
	return ProviderTypeMailgun
}

func (s *MailgunSender) renderPasswordResetHTML(data PasswordResetEmailData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">%s</h1>
    </div>
    <div style="background: #fff; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
        <h2>Password Reset Request</h2>
        <p>Hello%s,</p>
        <p>Your password reset code is:</p>
        <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea;">%s</span>
        </div>
        <p>This code expires in %d minutes.</p>
    </div>
</body>
</html>`,
		data.AppName,
		func() string {
			if data.Username != "" {
				return " " + data.Username
			}
			return ""
		}(),
		data.Code,
		data.ExpiresInMin)
}

func (s *MailgunSender) renderPasswordResetText(data PasswordResetEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf("%s - Password Reset\n\n%s,\n\nYour code: %s\n\nExpires in %d minutes.",
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}

func (s *MailgunSender) renderEmailVerificationHTML(data EmailVerificationEmailData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">%s</h1>
    </div>
    <div style="background: #fff; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
        <h2>Verify Your Email Address</h2>
        <p>Hello%s,</p>
        <p>Your verification code is:</p>
        <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea;">%s</span>
        </div>
        <p>This code expires in %d minutes.</p>
    </div>
</body>
</html>`,
		data.AppName,
		func() string {
			if data.Username != "" {
				return " " + data.Username
			}
			return ""
		}(),
		data.Code,
		data.ExpiresInMin)
}

func (s *MailgunSender) renderEmailVerificationText(data EmailVerificationEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf("%s - Email Verification\n\n%s,\n\nYour code: %s\n\nExpires in %d minutes.",
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}
