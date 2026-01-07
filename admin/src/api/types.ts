// API Types matching Go models

// Namespace types
export type NamespaceType = 'publisher' | 'game';

export interface Namespace {
  id: string;
  name: string;
  type: NamespaceType;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateNamespaceRequest {
  name: string;
  type: NamespaceType;
  description?: string;
}

// OAuth Client types
export interface Client {
  id: string;
  secret?: string;
  domain: string;
  public: boolean;
  user_id?: string;
  namespace: string;
  permissions: string[];
  scopes: string[];
  created_at?: string;
  updated_at?: string;
}

export interface CreateClientRequest {
  id?: string;
  secret?: string;
  domain: string;
  public?: boolean;
  permissions?: string[];
  scopes?: string[];
}

export interface UpdateClientPermissionsRequest {
  permissions: string[];
}

export interface UpdateClientScopesRequest {
  scopes: string[];
}

// Account types
export type AccountType = 'HEAD' | 'HEADLESS' | 'FULL' | 'ORPHAN';

export interface Account {
  id: string;
  username: string;
  account_type: AccountType;
  created_at: string;
}

// User types
export type UserType = 'HEAD' | 'BODY';

export interface User {
  id: string;
  account_id: string;
  namespace?: string;
  user_type: UserType;
  provider_type?: string;
  provider_account_id?: string;
  orphaned: boolean;
  created_at: string;
  updated_at: string;
}

// Role types
export type RoleType = 'USER' | 'CLIENT';

export interface Role {
  id: string;
  namespace: string;
  name: string;
  role_type: RoleType;
  permissions: Record<string, unknown>;
  description?: string;
  created_at: string;
}

export interface CreateRoleRequest {
  name: string;
  role_type: RoleType;
  permissions: Record<string, unknown>;
  description?: string;
}

export interface UserRole {
  id: string;
  user_id: string;
  role_id: string;
  namespace: string;
  assigned_at: string;
}

export interface ClientRole {
  id: string;
  client_id: string;
  role_id: string;
  namespace: string;
  assigned_at: string;
}

// Ban types
export type BanType = 'PERMANENT' | 'TIMED';

export interface UserBan {
  id: string;
  user_id: string;
  namespace: string;
  type: BanType;
  reason: string;
  until?: string;
  created_at: string;
}

export interface UserBanHistory {
  id: string;
  user_id: string;
  namespace: string;
  action: 'BAN' | 'UNBAN';
  type: BanType;
  reason: string;
  until?: string;
  actor_id: string;
  created_at: string;
}

export interface AccountBan {
  id: string;
  account_id: string;
  type: BanType;
  reason: string;
  until?: string;
  created_at: string;
}

export interface AccountBanHistory {
  id: string;
  account_id: string;
  action: 'BAN' | 'UNBAN';
  type: BanType;
  reason: string;
  until?: string;
  actor_id: string;
  created_at: string;
}

export interface BanRequest {
  type: BanType;
  reason: string;
  until?: string;
}

export interface UnbanRequest {
  reason: string;
}

// Platform types
export interface PlatformClient {
  id: string;
  namespace: string;
  platform_id: string;
  client_id: string;
  secret?: string;
  redirect_uri: string;
  app_id?: string;
  environment: 'dev' | 'prod-qa' | 'prod';
  platform_name?: string;
  type?: string;
  sso_url?: string;
  organization_id?: string;
  federation_metadata_url?: string;
  acs_url?: string;
  key_id?: string;
  team_id?: string;
  generic_oauth_flow?: boolean;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  scopes?: string;
  jwks_endpoint?: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PlatformUser {
  id: string;
  user_id: string;
  namespace: string;
  platform_id: string;
  platform_user_id: string;
  origin_namespace?: string;
  display_name?: string;
  email_address?: string;
  avatar_url?: string;
  online_id?: string;
  linked_at: string;
  created_at: string;
  updated_at: string;
}

// API Response types
export interface ListResponse<T> {
  data: T[];
  total?: number;
  offset?: number;
  limit?: number;
}

export interface ErrorResponse {
  error: string;
  error_description?: string;
}
