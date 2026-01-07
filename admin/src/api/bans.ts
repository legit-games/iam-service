import apiClient from './client';
import {
  UserBan,
  UserBanHistory,
  AccountBan,
  AccountBanHistory,
  BanRequest,
  UnbanRequest,
} from './types';

export const banApi = {
  // User bans (namespace-scoped)
  banUser: (namespace: string, userId: string, data: BanRequest) =>
    apiClient.post<UserBan>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/ban`, data),

  unbanUser: (namespace: string, userId: string, data: UnbanRequest) =>
    apiClient.post(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/unban`, data),

  listUserBans: (namespace: string, userId: string) =>
    apiClient.get<UserBan[]>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/bans`),

  // List all bans in namespace
  listNamespaceBans: (namespace: string, params?: { active?: boolean }) =>
    apiClient.get<UserBan[]>(`/iam/v1/admin/namespaces/${namespace}/bans`, { params }),

  // Account bans (global)
  banAccount: (accountId: string, data: BanRequest) =>
    apiClient.post<AccountBan>(`/iam/v1/admin/accounts/${accountId}/ban`, data),

  unbanAccount: (accountId: string, data: UnbanRequest) =>
    apiClient.post(`/iam/v1/admin/accounts/${accountId}/unban`, data),

  listAccountBans: (accountId: string) =>
    apiClient.get<AccountBan[]>(`/iam/v1/admin/accounts/${accountId}/bans`),

  // Ban history (placeholder - may need actual endpoints)
  getUserBanHistory: (namespace: string, userId: string) =>
    apiClient.get<UserBanHistory[]>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/ban-history`),

  getAccountBanHistory: (accountId: string) =>
    apiClient.get<AccountBanHistory[]>(`/iam/v1/admin/accounts/${accountId}/ban-history`),
};
