# Platform Authorization Endpoint

## Endpoint Overview

| Property | Value |
|----------|-------|
| **Path** | `/iam/v3/oauth/platforms/{platformId}/authorize` |
| **Method** | `GET` |
| **Content-Type** | `application/x-www-form-urlencoded` |
| **Response** | HTTP 302 Redirect |
| **Purpose** | Initiates OAuth authorization flow with third-party platforms |

## Purpose

This endpoint serves as the gateway for initiating third-party platform authentication (social login). It:

1. Validates an existing authorization request (created by `/iam/v3/oauth/authorize`)
2. Retrieves platform client configuration (client_id, secret, redirect_uri)
3. Constructs the appropriate OAuth authorization URL for the target platform
4. Redirects the user's browser to the third-party platform's login page

## Request Parameters

### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `platformId` | string | Yes | Platform identifier (1-256 alphanumeric characters) |

**Supported Platform IDs:**
- `steamopenid` - Steam OpenID
- `ps4web` - PlayStation Network
- `xblweb` - Xbox Live
- `epicgames` - Epic Games
- `twitch` - Twitch
- `facebook` - Facebook
- `google` - Google
- `apple` - Apple Sign-In
- `discord` - Discord
- `snapchat` - Snapchat
- `amazon` - Amazon
- `azure` - Azure AD / SAML
- Custom OIDC platforms (configured per namespace)

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `request_id` | string | Yes | UUID4 without hyphens - obtained from initial `/iam/v3/oauth/authorize` call |
| `client_id` | string | No | OAuth client ID (used for error redirects when request_id not found) |
| `redirect_uri` | string | No | Redirect URI (used for error redirects when request_id not found) |

## Response

### Success Response

**Status Code:** `302 Found`

**Headers:**
```
Location: {platform_oauth_authorization_url}
```

The redirect URL includes:
- Platform's OAuth client credentials
- Response type (`code`)
- Platform-specific scopes
- Callback URL pointing to `/iam/v3/platforms/{platformId}/authenticate`
- State parameter (the `request_id` for CSRF protection)

### Error Response

**Status Code:** `302 Found`

Redirects to Justice Login Website with error parameters:

```
Location: {justice_login_endpoint}?error={error_code}&error_description={message}
```

**Error Codes:**
- `invalid_request` - Missing or invalid parameters
- `server_error` - Internal server error
- `unauthorized_client` - Client not authorized

## Complete Request Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AUTHORIZATION FLOW                             │
└─────────────────────────────────────────────────────────────────────────┘

1. Client Application
   │
   │  GET /iam/v3/oauth/platforms/{platformId}/authorize
   │      ?request_id=550e8400e29b41d4a716446655440000
   ▼
2. IAM Service Handler
   │
   ├─► Parse & Validate Parameters
   │   • Validate platformId (alphanumeric, 1-256 chars)
   │   • Validate request_id (UUID4 format)
   │
   ├─► Load Authorization Request from Redis
   │   • Uses request_id as key
   │   • Contains: namespace, client_id, redirect_uri, scope, etc.
   │
   ├─► Fetch Platform Client Configuration from Database
   │   • Query by namespace + platformId
   │   • Returns: client_id, secret, redirect_uri, environment
   │
   ├─► Route to Platform-Specific Handler
   │   • Select handler based on platformId
   │   • Build platform-specific authorization URL
   │
   ├─► Publish Event
   │   • Topic: OauthThirdPartyRequest
   │   • Event: ThirdPartyRequestAuthorized
   │
   └─► Return HTTP 302 with Location header
       ▼
3. User Browser Redirects to Third-Party Platform
   │
   │  (e.g., https://accounts.google.com/o/oauth2/v2/auth?...)
   ▼
4. User Authenticates with Platform
   │
   ▼
5. Platform Redirects to IAM Callback
   │
   │  GET /iam/v3/platforms/{platformId}/authenticate
   │      ?code={authorization_code}&state={request_id}
   ▼
6. IAM Service Exchanges Code for Tokens
```

## Handler Logic Implementation

### Step 1: Parse and Validate Parameters

```go
// Extract parameters
platformID := request.PathParameter("platformId")
requestID := request.Request.FormValue("request_id")
clientIdParam := request.Request.FormValue("client_id")
redirectURI := request.Request.FormValue("redirect_uri")

// Validation rules:
// - platformId: AlphaNumeric, length 1-256
// - requestId: Non-empty UUID4 without hyphens
```

### Step 2: Load Authorization Request

The authorization request is stored in Redis when the user initiates OAuth flow via `/iam/v3/oauth/authorize`.

```go
type AuthorizationRequest struct {
    RequestID          string
    Namespace          string
    ClientID           string
    RedirectURI        string
    Scope              string
    ResponseType       string
    State              string
    CodeChallenge      string
    CodeChallengeMethod string
    // ... additional fields
}
```

### Step 3: Get Platform Client Configuration

```go
type PlatformClient struct {
    Namespace             string   // Tenant namespace
    PlatformID            string   // Platform identifier
    ClientID              string   // OAuth client ID for the platform
    AppID                 string   // Application ID (some platforms)
    Secret                string   // OAuth client secret
    RedirectURI           string   // Registered callback URI
    Environment           string   // dev, prod-qa, prod
    SSOURL                string   // SSO URL (for SAML)
    Type                  string   // Platform type
    OrganizationID        string   // Organization ID (some platforms)
    FederationMetadataURL string   // SAML federation metadata
    ACSURL                string   // SAML Assertion Consumer Service URL
    KeyID                 string   // Apple Key ID
    TeamID                string   // Apple Team ID
    GenericOauthFlow      bool     // Uses generic OIDC handler
    PlatformName          string   // Display name
}
```

### Step 4: Platform-Specific Routing

Each platform has a dedicated handler that constructs the appropriate authorization URL:

| Platform | Authorization URL Pattern |
|----------|---------------------------|
| Google | `https://accounts.google.com/o/oauth2/v2/auth` |
| Facebook | `https://www.facebook.com/v3.3/dialog/oauth` |
| Apple | `https://appleid.apple.com/auth/authorize` |
| Discord | `https://discord.com/api/oauth2/authorize` |
| Twitch | `https://id.twitch.tv/oauth2/authorize` |
| Steam | `https://steamcommunity.com/openid/login` |
| Epic Games | `https://www.epicgames.com/id/authorize` |
| Xbox Live | Environment-dependent Microsoft login |
| PSN | Environment-dependent Sony login |
| Generic OIDC | Configured authorization endpoint |

## Platform Handler Examples

### Google Handler

```
Redirect URL: https://accounts.google.com/o/oauth2/v2/auth
  ?client_id={platform_client_id}
  &response_type=code
  &scope=openid+profile+email
  &access_type=offline
  &redirect_uri={iam_base_uri}/iam/v3/platforms/google/authenticate
  &state={request_id}
  &prompt=consent
```

### Steam OpenID Handler

Steam uses OpenID 2.0 (not OAuth 2.0):

```
Redirect URL: https://steamcommunity.com/openid/login
  ?openid.mode=checkid_setup
  &openid.ns=http://specs.openid.net/auth/2.0
  &openid.identity=http://specs.openid.net/auth/2.0/identifier_select
  &openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select
  &openid.return_to={iam_base_uri}/iam/v3/platforms/steamopenid/authenticate?state={request_id}
  &openid.realm={iam_base_uri}
```

### Generic OIDC Handler

For custom OAuth platforms with `GenericOauthFlow=true`:

```
Redirect URL: {configured_authorization_endpoint}
  ?client_id={platform_client_id}
  &response_type=code
  &scope={configured_scopes}
  &redirect_uri={iam_base_uri}/iam/v3/platforms/{platformId}/authenticate
  &state={request_id}
```

## Data Storage Dependencies

### Redis (Authorization Request Storage)

- **Key Pattern:** `auth_request:{request_id}`
- **TTL:** Configurable (typically 5-10 minutes)
- **Purpose:** Temporary storage for OAuth flow state

### PostgreSQL (Platform Client Configuration)

- **Table:** `platform_clients`
- **Key:** `(namespace, platform_id)`
- **Purpose:** Store platform OAuth credentials per tenant

## Security Considerations

### CSRF Protection

The `request_id` serves as the OAuth `state` parameter, providing CSRF protection:

1. Generated by `/iam/v3/oauth/authorize` and stored in Redis
2. Passed to third-party platform as `state` parameter
3. Returned by platform in callback
4. Validated by `/iam/v3/platforms/{platformId}/authenticate`

### No Direct Authentication Required

This endpoint does not require Bearer token or Basic authentication because:

1. It's the entry point for unauthenticated users
2. Security relies on valid `request_id` stored in Redis
3. The `request_id` has a short TTL (expires quickly)

### Redirect URI Validation

- Platform client's redirect URI is pre-registered in the database
- The callback always goes to IAM's authenticate endpoint
- Final redirect to client application is validated separately

## Error Handling

| Scenario | Error Code | Description |
|----------|------------|-------------|
| Missing request_id | `invalid_request` | request_id parameter is required |
| Invalid request_id format | `invalid_request` | Must be UUID4 without hyphens |
| Authorization request not found | `invalid_request` | Session expired or invalid |
| Platform client not configured | `invalid_request` | Platform not set up for namespace |
| Database error | `server_error` | Internal system error |

## Events Published

When the endpoint successfully redirects to a platform:

```go
Event {
    Topic: "OauthThirdPartyRequest"
    Type:  "ThirdPartyRequestAuthorized"
    Data: {
        ClientID:     "{oauth_client_id}",
        ResponseType: "code",
        PlatformID:   "{platform_id}"
    }
}
```

## Example Request/Response

### Request

```http
GET /iam/v3/oauth/platforms/google/authorize?request_id=550e8400e29b41d4a716446655440000&client_id=myclient&redirect_uri=https://myapp.com/callback HTTP/1.1
Host: iam.example.com
```

### Response

```http
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=GOOGLE_CLIENT_ID&response_type=code&scope=openid%20profile%20email&access_type=offline&redirect_uri=https%3A%2F%2Fiam.example.com%2Fiam%2Fv3%2Fplatforms%2Fgoogle%2Fauthenticate&state=550e8400e29b41d4a716446655440000&prompt=consent
```

## Integration Notes for Other Projects

### Prerequisites for Implementation

1. **Authorization Request Storage** - Implement temporary storage (Redis recommended) for OAuth flow state
2. **Platform Client Registry** - Database table to store platform credentials per tenant
3. **Platform Handlers** - Implement handlers for each supported platform
4. **Callback Endpoint** - Implement `/platforms/{platformId}/authenticate` to receive the callback

### Key Design Decisions

1. **Platform-Specific Handlers** - Each platform may have unique parameters, scopes, and authentication methods
2. **Environment Support** - Some platforms (PSN, Xbox) have different endpoints for dev/prod
3. **Generic OIDC Fallback** - Support custom OAuth providers via generic handler
4. **State Parameter** - Always use request_id as state for CSRF protection
5. **Error Redirects** - All errors redirect to a login page rather than returning JSON

### Minimal Implementation Checklist

- [ ] Route registration for `GET /platforms/{platformId}/authorize`
- [ ] Parameter validation (platformId, request_id)
- [ ] Authorization request storage/retrieval
- [ ] Platform client configuration storage
- [ ] Platform-specific handler routing
- [ ] OAuth authorization URL construction
- [ ] HTTP 302 redirect response
- [ ] Error handling with redirects
- [ ] Callback endpoint (`/platforms/{platformId}/authenticate`)

## Source Code References

| Component | Location |
|-----------|----------|
| Route Registration | `pkg/oauth/api/v3api.go:287-326` |
| Main Handler | `pkg/oauth/api/v3handlers.go:791-989` |
| Google Handler | `pkg/oauth/api/v3handlers.go:4208-4239` |
| Steam Handler | `pkg/oauth/api/v3handlers.go:1410-1443` |
| PSN Handler | `pkg/oauth/api/v3handlers.go:1445-1476` |
| Generic OIDC Handler | `pkg/oauth/api/v3handlers.go:5309-5323` |
| Platform Client Model | `pkg/account/accountcommon/models.go:1331-1352` |
| Auth Request DAO | `pkg/oauth/dao/redis/authorizationrequest.go` |