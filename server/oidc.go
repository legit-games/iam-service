package server

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signIDToken creates a minimal ID Token (JWT) for the given token info when scope includes openid.
func (s *Server) signIDToken(ti interface {
	GetClientID() string
	GetUserID() string
	GetAccessCreateAt() time.Time
	GetAccessExpiresIn() time.Duration
}) (string, error) {
	if s.privKey == nil {
		if err := s.ensureOIDCKeys(); err != nil {
			return "", err
		}
	}
	issuer := s.Config.Issuer
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": ti.GetUserID(),
		"aud": ti.GetClientID(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privKey)
}

// HandleOIDCDiscovery serves the OpenID Provider Metadata.
func (s *Server) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	issuer := s.Config.Issuer
	meta := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(meta)
}

// HandleOIDCJWKS serves the public JWKS derived from the RSA key.
func (s *Server) HandleOIDCJWKS(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	if err := s.ensureOIDCKeys(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}
	pub := s.privKey.Public().(*rsa.PublicKey)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": s.kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(jwks)
}

// HandleOIDCUserInfo serves basic user info claims when provided a valid access token.
func (s *Server) HandleOIDCUserInfo(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	ti, err := s.ValidationBearerToken(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	userID := ti.GetUserID()
	claims := map[string]interface{}{
		"sub":   userID,
		"aud":   ti.GetClientID(),
		"iss":   s.Config.Issuer,
		"email": "",
	}

	// Fetch user details from database to get display_name and username
	// Note: userID from token is actually account_id (from accounts table)
	db, err := s.GetIAMReadDB()
	if err == nil {
		var displayName, username *string
		row := db.WithContext(r.Context()).Raw(`
			SELECT u.display_name, a.username
			FROM users u
			JOIN account_users au ON au.user_id = u.id
			LEFT JOIN accounts a ON au.account_id = a.id
			WHERE au.account_id = ?`, userID).Row()
		if row.Scan(&displayName, &username) == nil {
			if displayName != nil && *displayName != "" {
				claims["display_name"] = *displayName
			}
			if username != nil && *username != "" {
				claims["preferred_username"] = *username
			}
			claims["account_id"] = userID
		}
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(claims)
}

// Helper to compute base64url without padding for big.Int
func base64urlUInt(i *big.Int) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(i.Bytes()), "=")
}
