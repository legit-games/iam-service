package totp

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Config holds TOTP configuration
type Config struct {
	Issuer    string // e.g., "MyApp"
	Digits    int    // Default: 6
	Period    int    // Default: 30 (seconds)
	Algorithm string // Default: SHA1
	Window    int    // Validation window (default: 1 = +/- 30 seconds)
}

// DefaultConfig returns standard TOTP configuration compatible with Google Authenticator
func DefaultConfig() Config {
	return Config{
		Issuer:    "OAuth2 Service",
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Window:    1,
	}
}

// GenerateSecret generates a new TOTP secret using the pquerna/otp library
func GenerateSecret(accountName string, cfg Config) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: accountName,
		Period:      uint(cfg.Period),
		Digits:      otp.Digits(cfg.Digits),
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}
	return key.Secret(), nil
}

// GenerateQRCodeURL generates the otpauth:// URL for QR code generation
func GenerateQRCodeURL(secret, accountName string, cfg Config) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		url.QueryEscape(cfg.Issuer),
		url.QueryEscape(accountName),
		secret,
		url.QueryEscape(cfg.Issuer),
		cfg.Algorithm,
		cfg.Digits,
		cfg.Period,
	)
}

// ValidateCode validates a TOTP code against the secret with window tolerance
func ValidateCode(secret, code string, cfg Config) bool {
	// Use the pquerna/otp library for validation
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    uint(cfg.Period),
		Skew:      uint(cfg.Window),
		Digits:    otp.Digits(cfg.Digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return valid
}

// BackupCodeCharset contains characters for backup codes
// Excludes ambiguous characters: 0/O, 1/l/I
const BackupCodeCharset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// GenerateBackupCodes generates cryptographically secure backup codes
func GenerateBackupCodes(count, length int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code := make([]byte, length)
		for j := 0; j < length; j++ {
			b := make([]byte, 1)
			if _, err := rand.Read(b); err != nil {
				return nil, fmt.Errorf("failed to generate random byte: %w", err)
			}
			code[j] = BackupCodeCharset[int(b[0])%len(BackupCodeCharset)]
		}
		codes[i] = string(code)
	}

	return codes, nil
}

// FormatBackupCode formats a backup code for display (e.g., "ABCD-EFGH")
func FormatBackupCode(code string) string {
	if len(code) <= 4 {
		return code
	}
	mid := len(code) / 2
	return code[:mid] + "-" + code[mid:]
}

// NormalizeBackupCode removes formatting from a backup code for comparison
func NormalizeBackupCode(code string) string {
	// Remove dashes and convert to uppercase
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}
