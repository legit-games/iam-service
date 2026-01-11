package email

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"
)

// SMTPSender sends emails via SMTP
type SMTPSender struct {
	config       SMTPConfig
	fromAddress  string
	fromName     string
	appName      string
	supportEmail string
}

// NewSMTPSender creates a new SMTP email sender (legacy constructor)
func NewSMTPSender(config SMTPConfig) *SMTPSender {
	if config.Port == 0 {
		if config.UseSSL {
			config.Port = 465
		} else {
			config.Port = 587
		}
	}
	return &SMTPSender{
		config:   config,
		fromName: "OAuth2 Service",
		appName:  "OAuth2 Service",
	}
}

// NewSMTPSenderFromConfig creates a new SMTP sender from ProviderConfig
func NewSMTPSenderFromConfig(pc *ProviderConfig) (Sender, error) {
	var cfg SMTPConfig
	if err := json.Unmarshal(pc.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid SMTP config: %w", err)
	}

	if cfg.Port == 0 {
		if cfg.UseSSL {
			cfg.Port = 465
		} else {
			cfg.Port = 587
		}
	}

	return &SMTPSender{
		config:       cfg,
		fromAddress:  pc.FromAddress,
		fromName:     pc.FromName,
		appName:      pc.AppName,
		supportEmail: pc.SupportEmail,
	}, nil
}

// SendPasswordReset sends a password reset email
func (s *SMTPSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
	// Use provider config values if data doesn't have them
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

	htmlBody, err := s.renderPasswordResetHTML(data)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

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

// SendEmail sends a generic email
func (s *SMTPSender) SendEmail(ctx context.Context, data EmailData) error {
	fromAddr := data.FromAddress
	if fromAddr == "" {
		fromAddr = s.fromAddress
	}
	fromName := data.FromName
	if fromName == "" {
		fromName = s.fromName
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Build email headers and body
	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", fromName, fromAddr)
	headers["To"] = data.To
	headers["Subject"] = data.Subject
	headers["MIME-Version"] = "1.0"

	var msg strings.Builder

	if data.HTMLBody != "" {
		// Build multipart message
		boundary := "boundary-oauth2-email"
		headers["Content-Type"] = fmt.Sprintf("multipart/alternative; boundary=%s", boundary)

		for k, v := range headers {
			msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		msg.WriteString("\r\n")

		// Plain text part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		msg.WriteString(data.TextBody)
		msg.WriteString("\r\n")

		// HTML part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		msg.WriteString(data.HTMLBody)
		msg.WriteString("\r\n")

		msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		headers["Content-Type"] = "text/plain; charset=UTF-8"
		for k, v := range headers {
			msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		msg.WriteString("\r\n")
		msg.WriteString(data.TextBody)
	}

	// Set up authentication
	var auth smtp.Auth
	if s.config.Username != "" && s.config.Password != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	if s.config.UseSSL {
		return s.sendEmailSSL(addr, auth, data.To, msg.String())
	}

	return s.sendEmailTLS(addr, auth, data.To, msg.String())
}

// Health checks if the SMTP server is reachable
func (s *SMTPSender) Health(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	done := make(chan error, 1)

	go func() {
		conn, err := smtp.Dial(addr)
		if err != nil {
			done <- fmt.Errorf("failed to connect to SMTP server: %w", err)
			return
		}
		conn.Close()
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("SMTP health check timeout")
	}
}

// ProviderType returns the provider type
func (s *SMTPSender) ProviderType() ProviderType {
	return ProviderTypeSMTP
}

func (s *SMTPSender) sendEmailTLS(addr string, auth smtp.Auth, to, message string) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()

	if s.config.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         s.config.Host,
			InsecureSkipVerify: s.config.SkipVerify,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	fromAddr := s.fromAddress
	if fromAddr == "" {
		fromAddr = s.config.Username
	}

	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close email body: %w", err)
	}

	return client.Quit()
}

func (s *SMTPSender) sendEmailSSL(addr string, auth smtp.Auth, to, message string) error {
	tlsConfig := &tls.Config{
		ServerName:         s.config.Host,
		InsecureSkipVerify: s.config.SkipVerify,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server via SSL: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	fromAddr := s.fromAddress
	if fromAddr == "" {
		fromAddr = s.config.Username
	}

	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close email body: %w", err)
	}

	return client.Quit()
}

func (s *SMTPSender) renderPasswordResetHTML(data PasswordResetEmailData) (string, error) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">{{.AppName}}</h1>
    </div>

    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Password Reset Request</h2>

        <p>Hello{{if .Username}} <strong>{{.Username}}</strong>{{end}},</p>

        <p>We received a request to reset your password. Use the code below to complete the process:</p>

        <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea;">{{.Code}}</span>
        </div>

        <p style="color: #666; font-size: 14px;">
            This code will expire in <strong>{{.ExpiresInMin}} minutes</strong>.
        </p>

        <p style="color: #666; font-size: 14px;">
            If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.
        </p>

        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 25px 0;">

        <p style="color: #999; font-size: 12px; margin-bottom: 0;">
            This is an automated message from {{.AppName}}.
            {{if .SupportEmail}}If you need help, contact us at <a href="mailto:{{.SupportEmail}}" style="color: #667eea;">{{.SupportEmail}}</a>.{{end}}
        </p>
    </div>
</body>
</html>`

	t, err := template.New("password_reset").Parse(tmpl)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (s *SMTPSender) renderPasswordResetText(data PasswordResetEmailData) string {
	var buf strings.Builder

	buf.WriteString(fmt.Sprintf("%s - Password Reset\n\n", data.AppName))

	if data.Username != "" {
		buf.WriteString(fmt.Sprintf("Hello %s,\n\n", data.Username))
	} else {
		buf.WriteString("Hello,\n\n")
	}

	buf.WriteString("We received a request to reset your password.\n\n")
	buf.WriteString("Your password reset code is:\n\n")
	buf.WriteString(fmt.Sprintf("    %s\n\n", data.Code))
	buf.WriteString(fmt.Sprintf("This code will expire in %d minutes.\n\n", data.ExpiresInMin))
	buf.WriteString("If you didn't request a password reset, you can safely ignore this email.\n\n")

	if data.SupportEmail != "" {
		buf.WriteString(fmt.Sprintf("If you need help, contact us at %s.\n", data.SupportEmail))
	}

	return buf.String()
}
