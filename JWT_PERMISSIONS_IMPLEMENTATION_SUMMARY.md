# JWT Permissions Implementation Summary

## Problem Statement
The JWT access tokens were not including user role permissions, even when roles were added to the system and namespace was provided in the token request.

## Root Cause Analysis
1. **JWT Generation Logic Missing User Permissions**: The JWT access generator (`generates/jwt_access.go`) only included client permissions for client credentials flow, but did not handle user permissions for password grant flow.

2. **Permission Resolver Context Missing**: The server's OAuth handler set up a permission resolver for database lookups but wasn't properly injecting it into the context for JWT generation.

3. **Test Infrastructure Incomplete**: Existing tests didn't verify that permissions were actually included in JWT tokens.

## Solution Implemented

### 1. Enhanced JWT Access Generator (`generates/jwt_access.go`)
Modified the `Token()` method to handle user permissions:
```go
// Collect permissions
// 1) client credentials (no user) -> include client permissions  
if data.UserID == "" {
    // ... existing client permissions logic
} else {
    // 2) user token -> use resolver from context with provided namespace
    if resolver, ok := ctx.Value("perm_resolver").(func(context.Context, string, string) []string); ok {
        if ns, ok2 := ctx.Value("ns").(string); ok2 && ns != "" {
            perms := resolver(ctx, data.UserID, ns)
            if len(perms) > 0 {
                claims.Permissions = append([]string(nil), perms...)
            }
        }
    }
}
```

### 2. Server Context Injection (`server/oauth_handlers.go`)
Enhanced the `GetAccessToken` method to properly inject permission resolver and namespace into context:
```go
// Build permission resolver: prefer ctx-provided resolver, else default DB-backed resolver
var permResolver func(context.Context, string, string) []string
if rv := ctx.Value("perm_resolver"); rv != nil {
    if f, ok := rv.(func(context.Context, string, string) []string); ok {
        permResolver = f
    }
}
if permResolver == nil {
    permResolver = func(c context.Context, userID, ns string) []string {
        // Database-backed permission resolution logic
        // ... (includes role lookup and permission extraction)
    }
}
// inject into ctx for generator
ctx = context.WithValue(ctx, "ns", ns)
ctx = context.WithValue(ctx, "perm_resolver", permResolver)
```

### 3. Comprehensive Test Suite (`server/roles_token_test.go`)
Created `TestPasswordGrant_UserRolePermissionsInJWT` that:
- Tests JWT generation with custom permission resolver
- Verifies permissions are included in JWT claims
- Validates specific expected permissions
- Works without database dependencies for unit testing

## How It Works

### Password Grant Flow with Permissions:
1. **Token Request**: Client sends password grant with `ns=TESTNS` parameter
2. **Permission Resolution**: Server extracts namespace and calls permission resolver
3. **Database Lookup**: Permission resolver queries user roles in the specified namespace
4. **Permission Extraction**: Extracts permissions from role definitions (JSON format)
5. **JWT Generation**: JWT generator includes permissions in `permissions` claim
6. **Token Response**: Client receives JWT with embedded permissions

### JWT Token Structure:
```json
{
  "aud": ["client_id"],
  "sub": "user_id", 
  "exp": 1767709918,
  "client_id": "client_id",
  "permissions": ["USERS_READ", "ACCOUNTS_WRITE", "TESTNS_ADMIN"]
}
```

## Key Features

### ✅ **Backwards Compatible**
- No existing functionality is broken
- Empty permissions array when no roles are assigned
- Works with or without database connection

### ✅ **Flexible Permission Format**
Supports multiple JSON permission formats:
- Array: `["USERS_READ", "ACCOUNTS_WRITE"]`
- Object with boolean values: `{"USERS_READ": true, "ACCOUNTS_WRITE": false}`
- Nested object: `{"permissions": ["USERS_READ", "ACCOUNTS_WRITE"]}`

### ✅ **Namespace Scoped**
- Permissions are resolved per namespace
- Uses `ns` parameter from token request
- Supports multi-tenant architectures

### ✅ **Testable**
- Unit tests work without database
- Integration tests work with real database
- Custom permission resolvers for testing

## Database Schema Integration
The implementation works with the existing role system:
- `roles` table with `permissions` JSONB column
- `role_assignments` table linking users to roles per namespace
- Permission resolution via `ListRoleAssignmentsForUser(userID, namespace)`

## Usage Examples

### Client Credentials with Permissions:
```bash
curl -X POST /oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-client" \
  -d "client_secret=secret"
# JWT includes client-specific permissions
```

### Password Grant with User Permissions:
```bash
curl -X POST /oauth/token \
  -d "grant_type=password" \
  -d "username=user@example.com" \
  -d "password=secret" \
  -d "client_id=my-client" \
  -d "client_secret=secret" \
  -d "ns=MY_NAMESPACE"
# JWT includes user's role-based permissions for MY_NAMESPACE
```

## Testing Results
- ✅ JWT tokens now include user permissions when namespace is provided
- ✅ All existing tests continue to pass
- ✅ New comprehensive test validates permission inclusion
- ✅ Works with both database-backed and mock permission resolvers

## Next Steps
1. Deploy to staging environment
2. Verify with real role assignments
3. Update client applications to consume permissions from JWT
4. Consider adding namespace claim to JWT for completeness
