package generates

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	jwt.RegisteredClaims
	ClientID    string   `json:"client_id,omitempty"`
	UserID      string   `json:"user_id,omitempty"`      // Actual user ID from users table
	Namespace   string   `json:"namespace,omitempty"`    // Client's namespace
	Permissions []string `json:"permissions"`            // Always include, even if empty
	Roles       []string `json:"roles"`                  // Always include, even if empty
	Scope       string   `json:"scope,omitempty"`        // Space-separated scopes per RFC 6749
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if a.ExpiresAt != nil && time.Unix(a.ExpiresAt.Unix(), 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(kid string, key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	// Resolve user_id from context (actual user ID from users table)
	// Use user_id for sub field, fallback to account_id (data.UserID) if not resolved
	subject := data.UserID // Default to account ID
	userID := ""

	// First try to get user_id directly from context
	if uid, ok := ctx.Value("user_id").(string); ok && uid != "" {
		subject = uid // Use actual user ID for sub
		userID = uid
	} else if data.UserID != "" {
		// If user_id not in context but we have accountID, try to resolve via user_id_resolver
		// This is needed for Authorization Code flow where accountID is only known at generation time
		if resolver, ok := ctx.Value("user_id_resolver").(func(context.Context, string) string); ok {
			if resolvedUID := resolver(ctx, data.UserID); resolvedUID != "" {
				subject = resolvedUID
				userID = resolvedUID
			}
		}
	}

	claims := &JWTAccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{data.Client.GetID()},
			Subject:   subject, // user_id if resolved, otherwise account_id
			ExpiresAt: jwt.NewNumericDate(data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn())),
		},
		ClientID:    data.Client.GetID(),
		UserID:      userID,      // Actual user ID from users table (may be empty)
		Scope:       data.TokenInfo.GetScope(), // Include OAuth scopes in JWT
		Permissions: []string{},               // Always initialize as empty array
		Roles:       []string{},               // Always initialize as empty array
	}

	// Set namespace from client
	if nsGetter, ok := any(data.Client).(interface{ GetNamespace() string }); ok {
		claims.Namespace = nsGetter.GetNamespace()
	}

	// Collect permissions and roles
	// 1) client credentials (no user) -> include client permissions
	if data.UserID == "" {
		if permsGetter, ok := any(data.Client).(interface{ GetPermissions() []string }); ok {
			perms := permsGetter.GetPermissions()
			if len(perms) > 0 {
				claims.Permissions = append(claims.Permissions, perms...)
			}
		}
	} else {
		// 2) user token -> use resolvers from context with provided namespace
		ns, hasNs := ctx.Value("ns").(string)

		// Get permissions
		if permResolver, ok := ctx.Value("perm_resolver").(func(context.Context, string, string) []string); ok && hasNs && ns != "" {
			perms := permResolver(ctx, data.UserID, ns)
			if len(perms) > 0 {
				claims.Permissions = append(claims.Permissions, perms...)
			}
		}

		// Get roles
		if rolesResolver, ok := ctx.Value("roles_resolver").(func(context.Context, string, string) []string); ok && hasNs && ns != "" {
			roles := rolesResolver(ctx, data.UserID, ns)
			if len(roles) > 0 {
				claims.Roles = append(claims.Roles, roles...)
			}
		}
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool { return strings.HasPrefix(a.SignedMethod.Alg(), "HS") }
func (a *JWTAccessGenerate) isEd() bool { return strings.HasPrefix(a.SignedMethod.Alg(), "Ed") }
