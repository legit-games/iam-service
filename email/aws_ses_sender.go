package email

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSSESSender sends emails via AWS Simple Email Service
type AWSSESSender struct {
	region          string
	accessKeyID     string
	secretAccessKey string
	fromAddress     string
	fromName        string
	appName         string
	supportEmail    string
	httpClient      *http.Client
}

// NewAWSSESSenderFromConfig creates a new AWS SES sender from ProviderConfig
func NewAWSSESSenderFromConfig(pc *ProviderConfig) (Sender, error) {
	var cfg AWSSESConfig
	if err := json.Unmarshal(pc.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid AWS SES config: %w", err)
	}

	if cfg.Region == "" {
		return nil, fmt.Errorf("AWS region is required")
	}

	if !cfg.UseIAMRole && (cfg.AccessKeyID == "" || cfg.SecretAccessKey == "") {
		return nil, fmt.Errorf("AWS credentials are required when not using IAM role")
	}

	return &AWSSESSender{
		region:          cfg.Region,
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		fromAddress:     pc.FromAddress,
		fromName:        pc.FromName,
		appName:         pc.AppName,
		supportEmail:    pc.SupportEmail,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SendPasswordReset sends a password reset email via AWS SES
func (s *AWSSESSender) SendPasswordReset(ctx context.Context, data PasswordResetEmailData) error {
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

// SendEmailVerification sends an email verification code via AWS SES
func (s *AWSSESSender) SendEmailVerification(ctx context.Context, data EmailVerificationEmailData) error {
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

// SendEmail sends an email via AWS SES API
func (s *AWSSESSender) SendEmail(ctx context.Context, data EmailData) error {
	fromAddr := data.FromAddress
	if fromAddr == "" {
		fromAddr = s.fromAddress
	}
	fromName := data.FromName
	if fromName == "" {
		fromName = s.fromName
	}

	source := fromAddr
	if fromName != "" {
		source = fmt.Sprintf("%s <%s>", fromName, fromAddr)
	}

	// Build SES SendEmail request parameters
	params := url.Values{}
	params.Set("Action", "SendEmail")
	params.Set("Version", "2010-12-01")
	params.Set("Source", source)
	params.Set("Destination.ToAddresses.member.1", data.To)
	params.Set("Message.Subject.Data", data.Subject)
	params.Set("Message.Subject.Charset", "UTF-8")

	if data.TextBody != "" {
		params.Set("Message.Body.Text.Data", data.TextBody)
		params.Set("Message.Body.Text.Charset", "UTF-8")
	}
	if data.HTMLBody != "" {
		params.Set("Message.Body.Html.Data", data.HTMLBody)
		params.Set("Message.Body.Html.Charset", "UTF-8")
	}

	endpoint := fmt.Sprintf("https://email.%s.amazonaws.com/", s.region)
	body := params.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create SES request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Sign the request with AWS Signature Version 4
	if err := s.signRequest(req, []byte(body)); err != nil {
		return fmt.Errorf("failed to sign SES request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SES API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SES API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Health checks if AWS SES is accessible
func (s *AWSSESSender) Health(ctx context.Context) error {
	// Perform a simple GetSendQuota request to check connectivity
	params := url.Values{}
	params.Set("Action", "GetSendQuota")
	params.Set("Version", "2010-12-01")

	endpoint := fmt.Sprintf("https://email.%s.amazonaws.com/", s.region)
	body := params.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := s.signRequest(req, []byte(body)); err != nil {
		return fmt.Errorf("failed to sign health check request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SES health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return fmt.Errorf("SES authentication failed: invalid credentials")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SES health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// ProviderType returns the provider type
func (s *AWSSESSender) ProviderType() ProviderType {
	return ProviderTypeAWSSES
}

// signRequest signs an HTTP request using AWS Signature Version 4
func (s *AWSSESSender) signRequest(req *http.Request, payload []byte) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Set required headers
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", req.Host)

	// Create canonical request
	canonicalURI := "/"
	canonicalQueryString := ""

	// Canonical headers
	signedHeaders := "content-type;host;x-amz-date"
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-date:%s\n",
		req.Header.Get("Content-Type"),
		req.Host,
		amzDate)

	// Payload hash
	payloadHash := sha256Hash(payload)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/ses/aws4_request", dateStamp, s.region)
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		credentialScope,
		sha256Hash([]byte(canonicalRequest)),
	}, "\n")

	// Calculate signature
	signingKey := getSignatureKey(s.secretAccessKey, dateStamp, s.region, "ses")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Create authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		s.accessKeyID,
		credentialScope,
		signedHeaders,
		signature)

	req.Header.Set("Authorization", authHeader)

	return nil
}

func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(secretKey, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(regionName))
	kService := hmacSHA256(kRegion, []byte(serviceName))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func (s *AWSSESSender) renderPasswordResetHTML(data PasswordResetEmailData) string {
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

func (s *AWSSESSender) renderPasswordResetText(data PasswordResetEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf("%s - Password Reset\n\n%s,\n\nYour code: %s\n\nExpires in %d minutes.",
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}

func (s *AWSSESSender) renderEmailVerificationHTML(data EmailVerificationEmailData) string {
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

func (s *AWSSESSender) renderEmailVerificationText(data EmailVerificationEmailData) string {
	greeting := "Hello"
	if data.Username != "" {
		greeting = "Hello " + data.Username
	}
	return fmt.Sprintf("%s - Email Verification\n\n%s,\n\nYour code: %s\n\nExpires in %d minutes.",
		data.AppName, greeting, data.Code, data.ExpiresInMin)
}

// Unused but kept for canonical header ordering if needed
func sortedHeaderKeys(headers http.Header) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	return keys
}
