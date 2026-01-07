// Platform IDs matching platforms/platforms.go
export const PLATFORMS = {
  GOOGLE: 'google',
  FACEBOOK: 'facebook',
  APPLE: 'apple',
  DISCORD: 'discord',
  TWITCH: 'twitch',
  STEAM: 'steam',
  EPIC: 'epicgames',
  PS4: 'ps4',
  PS5: 'ps5',
  PS4_WEB: 'ps4web',
  XBOX: 'xbl',
  XBOX_WEB: 'xblweb',
  AMAZON: 'amazon',
  AZURE: 'azure',
  SNAPCHAT: 'snapchat',
  DEVICE: 'device',
  GENERIC: 'generic',
} as const;

export const PLATFORM_GROUPS = {
  psn: ['ps4', 'ps5', 'ps4web'],
  live: ['xbl', 'xblweb'],
};

export const PLATFORM_NAMES: Record<string, string> = {
  google: 'Google',
  facebook: 'Facebook',
  apple: 'Apple',
  discord: 'Discord',
  twitch: 'Twitch',
  steam: 'Steam',
  epicgames: 'Epic Games',
  ps4: 'PlayStation 4',
  ps5: 'PlayStation 5',
  ps4web: 'PlayStation Web',
  xbl: 'Xbox Live',
  xblweb: 'Xbox Live Web',
  amazon: 'Amazon',
  azure: 'Azure AD',
  snapchat: 'Snapchat',
  device: 'Device (Headless)',
  generic: 'Generic OIDC',
};

export type PlatformId = keyof typeof PLATFORM_NAMES;

// Environment options per platform
export const PLATFORM_ENVIRONMENTS: Record<string, string[]> = {
  google: ['dev', 'prod'],
  facebook: ['dev', 'prod'],
  apple: ['dev', 'prod'],
  discord: ['dev', 'prod'],
  twitch: ['dev', 'prod'],
  steam: ['dev', 'prod'],
  epicgames: ['dev', 'stage', 'prod'],
  ps4: ['sp-int', 'prod-qa', 'prod'],
  ps5: ['sp-int', 'prod-qa', 'prod'],
  ps4web: ['sp-int', 'prod-qa', 'prod'],
  xbl: ['SANDBOX', 'CERT', 'RETAIL'],
  xblweb: ['SANDBOX', 'CERT', 'RETAIL'],
  amazon: ['dev', 'prod'],
  azure: ['dev', 'prod'],
  snapchat: ['dev', 'prod'],
  device: ['dev', 'prod'],
  generic: ['dev', 'prod'],
};

// Default environment per platform
export const PLATFORM_DEFAULT_ENV: Record<string, string> = {
  google: 'dev',
  facebook: 'dev',
  apple: 'dev',
  discord: 'dev',
  twitch: 'dev',
  steam: 'dev',
  epicgames: 'dev',
  ps4: 'sp-int',
  ps5: 'sp-int',
  ps4web: 'sp-int',
  xbl: 'SANDBOX',
  xblweb: 'SANDBOX',
  amazon: 'dev',
  azure: 'dev',
  snapchat: 'dev',
  device: 'dev',
  generic: 'dev',
};

// Field configuration per platform
export interface PlatformFieldConfig {
  label: string;
  name: string;
  required?: boolean;
  placeholder?: string;
  type?: 'text' | 'password' | 'textarea';
  tooltip?: string;
}

export interface PlatformConfig {
  name: string;
  description: string;
  fields: PlatformFieldConfig[];
  defaultScopes?: string;
}

export const PLATFORM_CONFIGS: Record<string, PlatformConfig> = {
  google: {
    name: 'Google',
    description: 'Google OAuth 2.0 authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'xxxxx.apps.googleusercontent.com' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'openid profile email' },
    ],
    defaultScopes: 'openid profile email',
  },
  facebook: {
    name: 'Facebook',
    description: 'Facebook Login OAuth 2.0',
    fields: [
      { name: 'client_id', label: 'App ID', required: true, placeholder: 'Facebook App ID' },
      { name: 'secret', label: 'App Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'email public_profile' },
    ],
    defaultScopes: 'email public_profile',
  },
  apple: {
    name: 'Apple',
    description: 'Sign in with Apple (requires Key ID and Team ID)',
    fields: [
      { name: 'client_id', label: 'Services ID', required: true, placeholder: 'com.your.service.id' },
      { name: 'team_id', label: 'Team ID', required: true, placeholder: '10-character Team ID', tooltip: 'Found in Apple Developer Account' },
      { name: 'key_id', label: 'Key ID', required: true, placeholder: '10-character Key ID', tooltip: 'ID of your Sign in with Apple private key' },
      { name: 'secret', label: 'Private Key', required: true, type: 'textarea', placeholder: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'name email' },
    ],
    defaultScopes: 'name email',
  },
  discord: {
    name: 'Discord',
    description: 'Discord OAuth 2.0 authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'Discord Application ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'identify email' },
    ],
    defaultScopes: 'identify email',
  },
  twitch: {
    name: 'Twitch',
    description: 'Twitch OAuth 2.0 authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'Twitch Application Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'user:read:email' },
    ],
    defaultScopes: 'user:read:email',
  },
  steam: {
    name: 'Steam',
    description: 'Steam OpenID authentication (no client secret required)',
    fields: [
      { name: 'client_id', label: 'Steam Web API Key', required: true, placeholder: 'Steam Web API Key' },
      { name: 'redirect_uri', label: 'Realm/Redirect URI', required: true, placeholder: 'https://your-domain.com' },
    ],
  },
  epicgames: {
    name: 'Epic Games',
    description: 'Epic Games OAuth 2.0 (requires Deployment ID)',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'Epic Games Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'app_id', label: 'Deployment ID', required: true, placeholder: 'Epic Games Deployment ID', tooltip: 'Found in Epic Developer Portal' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'basic_profile friends_list presence' },
    ],
    defaultScopes: 'basic_profile',
  },
  ps4: {
    name: 'PlayStation 4',
    description: 'PlayStation Network SDK authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'PSN Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'scopes', label: 'Scopes', placeholder: 'psn:s2s' },
    ],
    defaultScopes: 'psn:s2s',
  },
  ps5: {
    name: 'PlayStation 5',
    description: 'PlayStation Network SDK authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'PSN Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'scopes', label: 'Scopes', placeholder: 'psn:s2s' },
    ],
    defaultScopes: 'psn:s2s',
  },
  ps4web: {
    name: 'PlayStation Web',
    description: 'PlayStation Network web OAuth',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'PSN Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'openid' },
    ],
    defaultScopes: 'openid',
  },
  xbl: {
    name: 'Xbox Live',
    description: 'Xbox Live SDK authentication',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'Xbox Client ID (GUID)' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'app_id', label: 'Sandbox ID', placeholder: 'XDKS.1', tooltip: 'Xbox Sandbox ID for testing' },
    ],
  },
  xblweb: {
    name: 'Xbox Live Web',
    description: 'Xbox Live web OAuth (Azure AD B2C)',
    fields: [
      { name: 'client_id', label: 'Application (Client) ID', required: true, placeholder: 'Azure AD Application ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'app_id', label: 'Sandbox ID', placeholder: 'XDKS.1', tooltip: 'Xbox Sandbox ID' },
      { name: 'scopes', label: 'Scopes', placeholder: 'Xboxlive.signin Xboxlive.offline_access' },
    ],
    defaultScopes: 'Xboxlive.signin Xboxlive.offline_access',
  },
  amazon: {
    name: 'Amazon',
    description: 'Login with Amazon OAuth 2.0',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'amzn1.application-oa2-client.xxxxx' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'profile' },
    ],
    defaultScopes: 'profile',
  },
  azure: {
    name: 'Azure AD',
    description: 'Azure Active Directory / Entra ID (supports OIDC and SAML)',
    fields: [
      { name: 'client_id', label: 'Application (Client) ID', required: true, placeholder: 'Azure AD Application ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'organization_id', label: 'Tenant ID', required: true, placeholder: 'Azure AD Tenant ID or domain' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'sso_url', label: 'SSO URL (SAML)', placeholder: 'https://login.microsoftonline.com/{tenant}/saml2', tooltip: 'For SAML SSO' },
      { name: 'federation_metadata_url', label: 'Federation Metadata URL', placeholder: 'https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml' },
      { name: 'scopes', label: 'Scopes', placeholder: 'openid profile email' },
    ],
    defaultScopes: 'openid profile email',
  },
  snapchat: {
    name: 'Snapchat',
    description: 'Snap Kit Login OAuth 2.0',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'Snapchat OAuth Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'scopes', label: 'Scopes', placeholder: 'https://auth.snapchat.com/oauth2/api/user.display_name' },
    ],
  },
  device: {
    name: 'Device (Headless)',
    description: 'Device-based authentication without third-party platform',
    fields: [
      { name: 'client_id', label: 'Internal Client ID', required: true, placeholder: 'device-auth-client' },
    ],
  },
  generic: {
    name: 'Generic OIDC',
    description: 'Custom OpenID Connect provider',
    fields: [
      { name: 'client_id', label: 'Client ID', required: true, placeholder: 'OIDC Client ID' },
      { name: 'secret', label: 'Client Secret', required: true, type: 'password' },
      { name: 'redirect_uri', label: 'Redirect URI', required: true, placeholder: 'https://your-domain.com/callback' },
      { name: 'authorization_endpoint', label: 'Authorization Endpoint', required: true, placeholder: 'https://provider.com/oauth/authorize' },
      { name: 'token_endpoint', label: 'Token Endpoint', required: true, placeholder: 'https://provider.com/oauth/token' },
      { name: 'userinfo_endpoint', label: 'UserInfo Endpoint', placeholder: 'https://provider.com/oauth/userinfo' },
      { name: 'jwks_endpoint', label: 'JWKS Endpoint', placeholder: 'https://provider.com/.well-known/jwks.json' },
      { name: 'scopes', label: 'Scopes', placeholder: 'openid profile email' },
    ],
    defaultScopes: 'openid profile email',
  },
};

export const PLATFORM_LIST = Object.entries(PLATFORM_CONFIGS).map(([id, config]) => ({
  id,
  name: config.name,
  description: config.description,
}));

export const ENVIRONMENTS = ['dev', 'prod-qa', 'prod'] as const;
export type Environment = typeof ENVIRONMENTS[number];
