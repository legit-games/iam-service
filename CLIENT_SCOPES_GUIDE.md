# Client Scopes Implementation Guide

This document explains the OAuth 2.0 client scopes functionality that has been added to the system.

## Overview

OAuth 2.0 scopes provide a way to limit access to protected resources by specifying what permissions a client is allowed to request. This implementation adds full scope support to both clients and access tokens.

## Features

### ✅ **Client Scope Management**
- Clients can have a list of allowed scopes
- Scopes are stored in the database as JSON arrays
- API endpoints for managing client scopes
- Scope validation during token requests

### ✅ **JWT Access Token Integration** 
- Access tokens include requested scopes per RFC 6749
- Scopes appear as space-separated string in `scope` JWT claim
- Compatible with existing permission-based authorization

### ✅ **Scope Validation**
- Token requests validate that requested scopes are within client's allowed scopes
- Backwards compatible - allows all scopes if none configured
- Proper error responses for invalid scope requests

## Database Schema

The `oauth2_clients` table now includes a `scopes` column:

```sql
ALTER TABLE oauth2_clients ADD COLUMN scopes JSONB DEFAULT '[]'::jsonb;
CREATE INDEX idx_oauth2_clients_scopes ON oauth2_clients USING gin (scopes);
```

## API Endpoints

### **Create/Update Client with Scopes**
```bash
POST /iam/v1/admin/namespaces/{namespace}/clients
Content-Type: application/json

{
  "id": "my-client",
  "secret": "client-secret", 
  "domain": "https://example.com",
  "scopes": ["read", "write", "admin"]
}
```

### **Update Client Scopes**
```bash
PUT /iam/v1/admin/clients/{client_id}/scopes
Content-Type: application/json

{
  "scopes": ["read", "write", "profile"]
}
```

### **Update Client Scopes by Namespace**
```bash
PUT /iam/v1/admin/namespaces/{namespace}/clients/{client_id}/scopes
Content-Type: application/json

{
  "scopes": ["read", "write"]
}
```

### **Get Client with Scopes**
```bash
GET /iam/v1/admin/clients/{client_id}

Response:
{
  "id": "my-client",
  "domain": "https://example.com", 
  "public": false,
  "namespace": "MY_NAMESPACE",
  "permissions": ["USERS_READ", "ACCOUNTS_WRITE"],
  "scopes": ["read", "write", "admin"]
}
```

## OAuth 2.0 Token Flows

### **Client Credentials with Scopes**
```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=my-client&client_secret=secret&scope=read write
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "read write"
}
```

**JWT Claims:**
```json
{
  "aud": ["my-client"],
  "client_id": "my-client",
  "scope": "read write",
  "exp": 1767715500
}
```

### **Password Grant with Scopes**
```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user&password=pass&client_id=my-client&client_secret=secret&scope=read&ns=MY_NAMESPACE
```

**JWT Claims include both scopes and permissions:**
```json
{
  "aud": ["my-client"],
  "sub": "user-123",
  "client_id": "my-client", 
  "scope": "read",
  "permissions": ["USERS_READ", "ACCOUNTS_WRITE"],
  "exp": 1767715500
}
```

## Error Handling

### **Invalid Scope Request**
```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=my-client&client_secret=secret&scope=read invalid_scope
```

**Response:**
```json
{
  "error": "invalid_request",
  "error_description": "..."
}
```

### **Insufficient Scope (403 Forbidden)**
```bash
GET /iam/v1/admin/clients/my-client
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Response when token lacks required scope:**
```json
{
  "error": "insufficient_scope",
  "error_description": "token lacks required scope",
  "scope": "client:read admin"
}
```

## Scope-Based Authorization

Each API endpoint is protected by specific scope requirements. Access tokens must contain the required scopes to access protected endpoints.

### **Endpoint Scope Requirements**

| Endpoint | Required Scopes | Description |
|----------|----------------|-------------|
| `GET /iam/v1/admin/clients` | `client:read` OR `admin` | List all clients |
| `GET /iam/v1/admin/clients/:id` | `client:read` OR `admin` | Get specific client |
| `POST /iam/v1/admin/namespaces/:ns/clients` | `client:write` OR `admin` | Create client in namespace |
| `PUT /iam/v1/admin/clients/:id/scopes` | `client:admin` OR `admin` | Update client scopes |
| `DELETE /iam/v1/admin/clients/:id` | `client:admin` OR `admin` | Delete client |
| `POST /oauth/introspect` | `token:introspect` OR `admin` | Introspect token |
| `POST /oauth/revoke` | `token:revoke` OR `admin` | Revoke token |
| `GET /oauth/userinfo` | `profile` | Get user profile (OIDC) |

### **Scope Hierarchy**

The system supports a scope hierarchy where `admin` scope grants access to all endpoints:

1. **admin** - Super scope that grants access to all endpoints
2. **{resource}:admin** - Admin access to specific resource type
3. **{resource}:write** - Write access to specific resource type  
4. **{resource}:read** - Read access to specific resource type

**Example Resource Scopes:**
- `client:read`, `client:write`, `client:admin`
- `user:read`, `user:write`, `user:admin`
- `role:read`, `role:write`, `role:admin`
- `account:read`, `account:write`, `account:admin`
- `namespace:read`, `namespace:write`, `namespace:admin`

### **Multiple Scope Logic**

Endpoints use **OR logic** for scope requirements - the client needs at least one of the listed scopes:

```go
// This endpoint requires EITHER client:read OR admin scope
r.GET("/clients", s.RequireAnyScope("client:read", "admin"), handler)

// This endpoint requires ALL listed scopes (AND logic)  
r.GET("/sensitive", s.RequireAllScopes("client:admin", "user:admin"), handler)
```

## Scope Validation Rules

1. **No Scopes Configured**: All scopes are allowed (backwards compatibility)
2. **Scopes Configured**: Only configured scopes are allowed
3. **Empty Scope Request**: Always allowed
4. **Invalid Scope Format**: Scopes must match `[A-Za-z0-9:._-]+`
5. **Unauthorized Scope**: Returns `invalid_request` error

## Integration Examples

### **Resource Server Authorization**

When validating access tokens, extract scopes from JWT:

```go
func validateToken(tokenString string) (*Claims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil
    })
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        scopes := strings.Fields(claims["scope"].(string))
        permissions := claims["permissions"].([]interface{})
        
        // Use scopes for OAuth-style authorization
        // Use permissions for role-based authorization
        return &Claims{
            Scopes: scopes,
            Permissions: permissions,
        }, nil
    }
    
    return nil, errors.New("invalid token")
}

// Check if token has required scope
func hasScope(userScopes []string, requiredScope string) bool {
    for _, scope := range userScopes {
        if scope == requiredScope || scope == "admin" {
            return true
        }
    }
    return false
}
```

### **API Gateway Integration**

For API gateways or reverse proxies, you can validate scopes before forwarding requests:

```go
func scopeMiddleware(requiredScopes []string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte("your-secret"), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
            return
        }

        claims := token.Claims.(jwt.MapClaims)
        tokenScopes := strings.Fields(claims["scope"].(string))

        // Check if token has any required scope
        hasRequiredScope := false
        for _, required := range requiredScopes {
            for _, userScope := range tokenScopes {
                if userScope == required || userScope == "admin" {
                    hasRequiredScope = true
                    break
                }
            }
            if hasRequiredScope {
                break
            }
        }

        if !hasRequiredScope {
            http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
            return
        }

        // Continue to next handler
        next.ServeHTTP(w, r)
    }
}
```

### **Client Registration**

```go
// Create client with specific scopes
client := &models.Client{
    ID: "mobile-app",
    Secret: "mobile-secret", 
    Domain: "com.example.mobile://callback",
    Scopes: []string{"profile", "read:posts", "write:posts"},
}

err := clientStore.Upsert(ctx, client)
```

## Migration Guide

### **Existing Clients**
- Existing clients will have `scopes: []` (empty array)
- Empty scopes allows all scope requests (backwards compatible)
- No immediate action required for existing implementations

### **Recommended Migration Steps**
1. **Deploy the update** - No breaking changes
2. **Audit existing clients** - Review what scopes they should have
3. **Configure scopes** - Set appropriate scopes for each client
4. **Update client applications** - Start requesting specific scopes
5. **Monitor and adjust** - Fine-tune scope assignments as needed

## Best Practices

### **Scope Design**
- Use meaningful scope names: `read:posts`, `write:profile`, `admin:users`
- Keep scopes granular but not overly complex
- Use namespacing for different resource types
- Document scope meanings for client developers

### **Client Configuration**
- Assign minimal necessary scopes to each client
- Review and audit client scopes regularly
- Use namespace-specific scope management for multi-tenant setups
- Combine with permissions for fine-grained authorization

### **Security Considerations**
- Validate scopes at both token issuance and resource access
- Log scope usage for audit and debugging
- Revoke or update client scopes when access requirements change
- Use HTTPS for all OAuth 2.0 flows

## Testing

The implementation includes comprehensive tests:
- Scope validation during token requests
- JWT token generation with scopes
- API endpoint functionality
- Backwards compatibility verification

Run tests with:
```bash
go test ./server -run TestClientScopes -v
```

## Conclusion

The client scopes implementation provides a robust foundation for OAuth 2.0 scope-based authorization while maintaining backwards compatibility with existing permission-based systems. The dual approach allows for flexible authorization strategies depending on your application's needs.
