package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SendGridSender sends emails via SendGrid API
type SendGridSender struct {
	apiKey       string
	fromAddress  string
	fromName     string
	appName      string
	supportEmail string
	httpClient   *http.Client
}

// NewSendGridSenderFromConfig creates a new SendGrid sender from ProviderConfig
func NewSendGridSenderFromConfig(pc *ProviderConfig) (Sender, error) {
	var cfg SendGridConfig
	if err := json.Unmarshal(pc.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid SendGrid config: %w", err)
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("SendGrid API key is required")
	}

	return &SendGridSender{
		apiKey:       cfg.APIKey,
		fromAddress:  pc.FromAddress,
		fromName:     pc.FromName,
		appName:      pc.AppName,
		supportEmail: pc.SupportEmail,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SendPasswordReset sends a password reset email via SendGrid
func (s *SendGridSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
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

// SendEmail sends an email via SendGrid API
func (s *SendGridSender) SendEmail(ctx context.Context, data EmailData) error {
	fromAddr := data.FromAddress
	if fromAddr == "" {
		fromAddr = s.fromAddress
	}
	fromName := data.FromName
	if fromName == "" {
		fromName = s.fromName
	}

	// Build SendGrid API payload
	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": data.To},
				},
			},
		},
		"from": map[string]string{
			"email": fromAddr,
			"name":  fromName,
		},
		"subject": data.Subject,
		"content": []map[string]string{},
	}

	content := []map[string]string{}
	if data.TextBody != "" {
		content = append(content, map[string]string{
			"type":  "text/plain",
			"value": data.TextBody,
		})
	}
	if data.HTMLBody != "" {
		content = append(content, map[string]string{
			"type":  "text/html",
			"value": data.HTMLBody,
		})
	}
	payload["content"] = content

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal SendGrid payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create SendGrid request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SendGrid API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SendGrid API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// Health checks if SendGrid API is accessible
func (s *SendGridSender) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SendGrid health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("SendGrid authentication failed: invalid API key")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SendGrid health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// ProviderType returns the provider type
func (s *SendGridSender) ProviderType() ProviderType {
	return ProviderTypeSendGrid
}

func (s *SendGridSender) renderPasswordResetHTML(data PasswordResetEmailData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">%s</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Password Reset Request</h2>
        <p>Hello%s,</p>
        <p>We received a request to reset your password. Use the code below:</p>
        <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea;">%s</span>
        </div>
        <p style="color: #666; font-size: 14px;">This code will expire in <strong>%d minutes</strong>.</p>
        <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
    </div>
</body>
</html>`,
		data.AppName,
		func() string {
			if data.Username != "" {
				return " <strong>" + data.Username + "</strong>"
			}
			return ""
		}(),
		data.Code,
		data.ExpiresInMin)
}

func (s *SendGridSender) renderPasswordResetText(data PasswordResetEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf(`%s - Password Reset

%s,

We received a request to reset your password.

Your password reset code is:

    %s

This code will expire in %d minutes.

If you didn't request a password reset, you can safely ignore this email.
`,
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}
