package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client provides IP geolocation lookup functionality.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a new GeoIP client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ipAPIResponse represents the response from ip-api.com
type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Message     string `json:"message"`
}

// LookupCountry returns the ISO 3166-1 alpha-2 country code for the given IP address.
// Returns empty string if lookup fails.
// For private/local IPs, it falls back to detecting country from server's public IP.
func (c *Client) LookupCountry(ctx context.Context, ip string) string {
	ip = strings.TrimSpace(ip)

	// Use ip-api.com (free, no API key required, 45 requests/minute limit)
	// If IP is empty or private, call without IP to get server's public IP country
	var url string
	if ip == "" || isPrivateIP(ip) {
		// Get country from server's public IP (useful for local development)
		url = "http://ip-api.com/json/?fields=status,countryCode,message"
	} else {
		url = fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode,message", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var result ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	if result.Status != "success" {
		return ""
	}

	return result.CountryCode
}

// isPrivateIP checks if the IP address is a private/local address.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // Invalid IP, treat as private
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for private ranges
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// GetClientIP extracts the client IP from the HTTP request.
// It checks X-Forwarded-For and X-Real-IP headers first (for proxied requests),
// then falls back to RemoteAddr.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
