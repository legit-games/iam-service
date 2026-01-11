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

// MailchimpSender sends emails via Mailchimp Transactional (Mandrill) API
type MailchimpSender struct {
	apiKey       string
	fromAddress  string
	fromName     string
	appName      string
	supportEmail string
	httpClient   *http.Client
}

// NewMailchimpSenderFromConfig creates a new Mailchimp sender from ProviderConfig
func NewMailchimpSenderFromConfig(pc *ProviderConfig) (Sender, error) {
	var cfg MailchimpConfig
	if err := json.Unmarshal(pc.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid Mailchimp config: %w", err)
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Mailchimp API key is required")
	}

	return &MailchimpSender{
		apiKey:       cfg.APIKey,
		fromAddress:  pc.FromAddress,
		fromName:     pc.FromName,
		appName:      pc.AppName,
		supportEmail: pc.SupportEmail,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SendPasswordReset sends a password reset email via Mailchimp Transactional
func (s *MailchimpSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
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

// SendEmail sends an email via Mailchimp Transactional (Mandrill) API
func (s *MailchimpSender) SendEmail(ctx context.Context, data EmailData) error {
	fromAddr := data.FromAddress
	if fromAddr == "" {
		fromAddr = s.fromAddress
	}
	fromName := data.FromName
	if fromName == "" {
		fromName = s.fromName
	}

	// Build Mandrill API payload
	payload := map[string]interface{}{
		"key": s.apiKey,
		"message": map[string]interface{}{
			"from_email": fromAddr,
			"from_name":  fromName,
			"to": []map[string]interface{}{
				{
					"email": data.To,
					"type":  "to",
				},
			},
			"subject": data.Subject,
			"text":    data.TextBody,
			"html":    data.HTMLBody,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Mandrill payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://mandrillapp.com/api/1.0/messages/send.json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create Mandrill request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Mandrill API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Mandrill API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response to check for errors
	var respData []map[string]interface{}
	if err := json.Unmarshal(body, &respData); err == nil && len(respData) > 0 {
		if status, ok := respData[0]["status"].(string); ok {
			if status == "rejected" || status == "invalid" {
				reason := ""
				if r, ok := respData[0]["reject_reason"].(string); ok {
					reason = r
				}
				return fmt.Errorf("Mandrill rejected email: %s", reason)
			}
		}
	}

	return nil
}

// Health checks if Mailchimp Transactional (Mandrill) API is accessible
func (s *MailchimpSender) Health(ctx context.Context) error {
	payload := map[string]string{
		"key": s.apiKey,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal health check payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://mandrillapp.com/api/1.0/users/ping.json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Mandrill health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("Mandrill authentication failed: invalid API key")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Mandrill health check failed: %s", string(body))
	}

	return nil
}

// ProviderType returns the provider type
func (s *MailchimpSender) ProviderType() ProviderType {
	return ProviderTypeMailchimp
}

func (s *MailchimpSender) renderPasswordResetHTML(data PasswordResetEmailData) string {
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

func (s *MailchimpSender) renderPasswordResetText(data PasswordResetEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf("%s - Password Reset\n\n%s,\n\nYour code: %s\n\nExpires in %d minutes.",
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}
