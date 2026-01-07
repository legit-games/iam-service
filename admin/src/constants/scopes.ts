// OAuth2 Scopes matching server/scope_definitions.go
export const SCOPES = {
  ADMIN: 'admin',
  READ: 'read',
  WRITE: 'write',
  PROFILE: 'profile',

  CLIENT_READ: 'client:read',
  CLIENT_WRITE: 'client:write',
  CLIENT_ADMIN: 'client:admin',

  USER_READ: 'user:read',
  USER_WRITE: 'user:write',
  USER_ADMIN: 'user:admin',

  ACCOUNT_READ: 'account:read',
  ACCOUNT_WRITE: 'account:write',
  ACCOUNT_ADMIN: 'account:admin',

  ROLE_READ: 'role:read',
  ROLE_WRITE: 'role:write',
  ROLE_ADMIN: 'role:admin',

  NAMESPACE_READ: 'namespace:read',
  NAMESPACE_WRITE: 'namespace:write',
  NAMESPACE_ADMIN: 'namespace:admin',

  PLATFORM_READ: 'platform:read',
  PLATFORM_WRITE: 'platform:write',
  PLATFORM_ADMIN: 'platform:admin',

  TOKEN_INTROSPECT: 'token:introspect',
  TOKEN_REVOKE: 'token:revoke',
} as const;

export const SCOPE_LIST = Object.values(SCOPES);

export const SCOPE_GROUPS = {
  client: [SCOPES.CLIENT_READ, SCOPES.CLIENT_WRITE, SCOPES.CLIENT_ADMIN],
  user: [SCOPES.USER_READ, SCOPES.USER_WRITE, SCOPES.USER_ADMIN],
  account: [SCOPES.ACCOUNT_READ, SCOPES.ACCOUNT_WRITE, SCOPES.ACCOUNT_ADMIN],
  role: [SCOPES.ROLE_READ, SCOPES.ROLE_WRITE, SCOPES.ROLE_ADMIN],
  namespace: [SCOPES.NAMESPACE_READ, SCOPES.NAMESPACE_WRITE, SCOPES.NAMESPACE_ADMIN],
  platform: [SCOPES.PLATFORM_READ, SCOPES.PLATFORM_WRITE, SCOPES.PLATFORM_ADMIN],
  token: [SCOPES.TOKEN_INTROSPECT, SCOPES.TOKEN_REVOKE],
};

// Scopes required for admin console
export const ADMIN_REQUIRED_SCOPES = [
  SCOPES.ADMIN,
  SCOPES.PROFILE,  // Required for /oauth/userinfo endpoint
  SCOPES.CLIENT_ADMIN,
  SCOPES.USER_ADMIN,
  SCOPES.ROLE_ADMIN,
  SCOPES.NAMESPACE_ADMIN,
  SCOPES.PLATFORM_ADMIN,
];
