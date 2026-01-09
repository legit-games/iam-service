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
    apiClient.get<{ bans: UserBan[] }>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/bans`),

  // List all bans in namespace
  listNamespaceBans: (namespace: string, params?: { active?: boolean }) =>
    apiClient.get<{ bans: UserBan[] }>(`/iam/v1/admin/namespaces/${namespace}/bans`, { params }),

  // Global user bans
  banUserGlobal: (userId: string, data: BanRequest) =>
    apiClient.post<AccountBan>(`/iam/v1/admin/users/${userId}/ban`, data),

  unbanUserGlobal: (userId: string, data: UnbanRequest) =>
    apiClient.post(`/iam/v1/admin/users/${userId}/unban`, data),

  listUserBansGlobal: (userId: string) =>
    apiClient.get<{ bans: AccountBan[] }>(`/iam/v1/admin/users/${userId}/bans`),

  // Ban history (placeholder - may need actual endpoints)
  getUserBanHistory: (namespace: string, userId: string) =>
    apiClient.get<UserBanHistory[]>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/ban-history`),

  getUserBanHistoryGlobal: (userId: string) =>
    apiClient.get<AccountBanHistory[]>(`/iam/v1/admin/users/${userId}/ban-history`),
};
