import apiClient from './client';
import { PlatformClient, PlatformUser } from './types';

export const platformApi = {
  // Platform users
  listUserPlatforms: (namespace: string, userId: string) =>
    apiClient.get<PlatformUser[]>(
      `/iam/v1/oauth/admin/namespaces/${namespace}/users/${userId}/platforms`
    ),

  getPlatformToken: (namespace: string, userId: string, platformId: string) =>
    apiClient.get<{ token: string }>(
      `/iam/v1/oauth/admin/namespaces/${namespace}/users/${userId}/platforms/${platformId}/platformToken`
    ),

  // Platform clients (configuration)
  // Note: These endpoints may need to be added to the backend
  listPlatformClients: (namespace: string) =>
    apiClient.get<PlatformClient[]>(`/iam/v1/admin/namespaces/${namespace}/platform-clients`),

  getPlatformClient: (namespace: string, platformId: string) =>
    apiClient.get<PlatformClient>(
      `/iam/v1/admin/namespaces/${namespace}/platform-clients/${platformId}`
    ),

  createPlatformClient: (namespace: string, data: Partial<PlatformClient>) =>
    apiClient.post<PlatformClient>(`/iam/v1/admin/namespaces/${namespace}/platform-clients`, data),

  updatePlatformClient: (namespace: string, platformId: string, data: Partial<PlatformClient>) =>
    apiClient.put<PlatformClient>(
      `/iam/v1/admin/namespaces/${namespace}/platform-clients/${platformId}`,
      data
    ),

  deletePlatformClient: (namespace: string, platformId: string) =>
    apiClient.delete(`/iam/v1/admin/namespaces/${namespace}/platform-clients/${platformId}`),
};
