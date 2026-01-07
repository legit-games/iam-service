import apiClient from './client';
import { Account, User } from './types';

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

  // Get user info (placeholder - may need actual endpoint)
  getUser: (userId: string) =>
    apiClient.get<User>(`/iam/v1/admin/users/${userId}`),

  // Get account info (placeholder - may need actual endpoint)
  getAccount: (accountId: string) =>
    apiClient.get<Account>(`/iam/v1/admin/accounts/${accountId}`),
};
