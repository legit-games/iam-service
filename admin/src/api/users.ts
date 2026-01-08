import apiClient from './client';
import { Account, User } from './types';

export type SearchType = 'user_id' | 'account_id' | 'username';

export interface CreateHeadAccountRequest {
  username: string;
  password: string;
}

export interface CreateHeadlessAccountRequest {
  provider_type: string;
  provider_account_id: string;
  namespace?: string;
}

export interface LinkAccountRequest {
  target_account_id: string;
  namespace?: string;
}

export interface UnlinkAccountRequest {
  user_id: string;
  namespace?: string;
}

export interface ListUsersParams {
  search_type?: SearchType;
  q?: string;
  created_from?: string;
  created_to?: string;
  limit?: number;
  offset?: number;
}

export const userApi = {
  // Create head account (with password)
  createHeadAccount: (data: CreateHeadAccountRequest) =>
    apiClient.post<Account>('/iam/v1/accounts/head', data),

  // Create headless account (provider-linked)
  createHeadlessAccount: (data: CreateHeadlessAccountRequest) =>
    apiClient.post<Account>('/iam/v1/accounts/headless', data),

  // Link accounts
  linkAccount: (accountId: string, data: LinkAccountRequest) =>
    apiClient.post(`/iam/v1/accounts/${accountId}/link`, data),

  // Unlink accounts
  unlinkAccount: (accountId: string, data: UnlinkAccountRequest) =>
    apiClient.post(`/iam/v1/accounts/${accountId}/unlink`, data),

  // List users with optional filters
  listUsers: (namespace: string, params?: ListUsersParams) =>
    apiClient.get<{ users: User[]; count: number }>(`/iam/v1/admin/namespaces/${namespace}/users`, {
      params,
    }),

  // Get user info by namespace and user ID
  getUser: (namespace: string, userId: string, searchType?: SearchType) =>
    apiClient.get<{ user: User }>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}`, {
      params: searchType ? { search_type: searchType } : undefined,
    }),

  // Get account info (placeholder - may need actual endpoint)
  getAccount: (accountId: string) =>
    apiClient.get<Account>(`/iam/v1/admin/accounts/${accountId}`),

  // Get user permissions
  getUserPermissions: (userId: string) =>
    apiClient.get<{ user_id: string; permissions: string[] }>(`/iam/v1/admin/users/${userId}/permissions`),

  // Update user permissions (replace all)
  updateUserPermissions: (userId: string, permissions: string[]) =>
    apiClient.put<{ user_id: string; permissions: string[] }>(`/iam/v1/admin/users/${userId}/permissions`, { permissions }),

  // Add permissions to user
  addUserPermissions: (userId: string, permissions: string[]) =>
    apiClient.post<{ user_id: string; permissions: string[] }>(`/iam/v1/admin/users/${userId}/permissions`, { permissions }),

  // Remove permissions from user
  removeUserPermissions: (userId: string, permissions: string[]) =>
    apiClient.delete<{ user_id: string; permissions: string[] }>(`/iam/v1/admin/users/${userId}/permissions`, { data: { permissions } }),
};
