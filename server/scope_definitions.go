package server

// API Scope Definitions
// Each API endpoint requires specific scopes for access

const (
	// OAuth 2.0 Standard Scopes
	ScopeRead    = "read"
	ScopeWrite   = "write"
	ScopeAdmin   = "admin"
	ScopeProfile = "profile"

	// Client Management Scopes
	ScopeClientRead  = "client:read"
	ScopeClientWrite = "client:write"
	ScopeClientAdmin = "client:admin"

	// User Management Scopes
	ScopeUserRead  = "user:read"
	ScopeUserWrite = "user:write"
	ScopeUserAdmin = "user:admin"

	// Account Management Scopes
	ScopeAccountRead  = "account:read"
	ScopeAccountWrite = "account:write"
	ScopeAccountAdmin = "account:admin"

	// Role Management Scopes
	ScopeRoleRead  = "role:read"
	ScopeRoleWrite = "role:write"
	ScopeRoleAdmin = "role:admin"

	// Namespace Management Scopes
	ScopeNamespaceRead  = "namespace:read"
	ScopeNamespaceWrite = "namespace:write"
	ScopeNamespaceAdmin = "namespace:admin"

	// Token Management Scopes
	ScopeTokenIntrospect = "token:introspect"
	ScopeTokenRevoke     = "token:revoke"
)

// Scope requirements for each API endpoint group
var EndpointScopes = map[string]ScopeRequirement{
	// OAuth 2.0 Core Endpoints - no scope required (handled by OAuth flow)
	"oauth:authorize":  {},
	"oauth:token":      {},
	"oauth:introspect": {Required: []string{ScopeTokenIntrospect, ScopeAdmin}},
	"oauth:revoke":     {Required: []string{ScopeTokenRevoke, ScopeAdmin}},

	// OIDC Endpoints
	"oidc:discovery": {},
	"oidc:jwks":      {},
	"oidc:userinfo":  {Required: []string{ScopeProfile}},

	// Public Endpoints
	"public:login":    {},
	"public:register": {},

	// Client Management Endpoints
	"client:list":        {Required: []string{ScopeClientRead, ScopeAdmin}},
	"client:get":         {Required: []string{ScopeClientRead, ScopeAdmin}},
	"client:create":      {Required: []string{ScopeClientWrite, ScopeAdmin}},
	"client:update":      {Required: []string{ScopeClientWrite, ScopeAdmin}},
	"client:delete":      {Required: []string{ScopeClientAdmin, ScopeAdmin}},
	"client:permissions": {Required: []string{ScopeClientAdmin, ScopeAdmin}},
	"client:scopes":      {Required: []string{ScopeClientAdmin, ScopeAdmin}},

	// User Management Endpoints
	"user:list":   {Required: []string{ScopeUserRead, ScopeAdmin}},
	"user:get":    {Required: []string{ScopeUserRead, ScopeAdmin}},
	"user:create": {Required: []string{ScopeUserWrite, ScopeAdmin}},
	"user:update": {Required: []string{ScopeUserWrite, ScopeAdmin}},
	"user:delete": {Required: []string{ScopeUserAdmin, ScopeAdmin}},
	"user:ban":    {Required: []string{ScopeUserAdmin, ScopeAdmin}},
	"user:unban":  {Required: []string{ScopeUserAdmin, ScopeAdmin}},

	// Account Management Endpoints
	"account:list":   {Required: []string{ScopeAccountRead, ScopeAdmin}},
	"account:get":    {Required: []string{ScopeAccountRead, ScopeAdmin}},
	"account:create": {Required: []string{ScopeAccountWrite, ScopeAdmin}},
	"account:link":   {Required: []string{ScopeAccountWrite, ScopeAdmin}},
	"account:unlink": {Required: []string{ScopeAccountWrite, ScopeAdmin}},
	"account:ban":    {Required: []string{ScopeAccountAdmin, ScopeAdmin}},
	"account:unban":  {Required: []string{ScopeAccountAdmin, ScopeAdmin}},

	// Role Management Endpoints
	"role:list":   {Required: []string{ScopeRoleRead, ScopeAdmin}},
	"role:get":    {Required: []string{ScopeRoleRead, ScopeAdmin}},
	"role:create": {Required: []string{ScopeRoleWrite, ScopeAdmin}},
	"role:update": {Required: []string{ScopeRoleWrite, ScopeAdmin}},
	"role:delete": {Required: []string{ScopeRoleAdmin, ScopeAdmin}},
	"role:assign": {Required: []string{ScopeRoleAdmin, ScopeAdmin}},

	// Namespace Management Endpoints
	"namespace:list":   {Required: []string{ScopeNamespaceRead, ScopeAdmin}},
	"namespace:get":    {Required: []string{ScopeNamespaceRead, ScopeAdmin}},
	"namespace:create": {Required: []string{ScopeNamespaceWrite, ScopeAdmin}},
	"namespace:update": {Required: []string{ScopeNamespaceWrite, ScopeAdmin}},
	"namespace:delete": {Required: []string{ScopeNamespaceAdmin, ScopeAdmin}},
}
