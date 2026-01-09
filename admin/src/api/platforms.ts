import apiClient from './client';
import { PlatformClient, PlatformUser, PlatformUserSearchParams, PlatformUserSearchResult } from './types';

export const platformApi = {
  // Platform users
  listUserPlatforms: (namespace: string, userId: string) =>
    apiClient.get<{ platforms: PlatformUser[] }>(
      `/iam/v1/oauth/admin/namespaces/${namespace}/users/${userId}/platforms`
    ),

  searchPlatformUsers: (namespace: string, params: PlatformUserSearchParams) => {
    const queryParams = new URLSearchParams();
    if (params.platform_id) queryParams.set('platform_id', params.platform_id);
    if (params.platform_user_id) queryParams.set('platform_user_id', params.platform_user_id);
    if (params.created_from) queryParams.set('created_from', params.created_from);
    if (params.created_to) queryParams.set('created_to', params.created_to);
    if (params.offset !== undefined) queryParams.set('offset', String(params.offset));
    if (params.limit !== undefined) queryParams.set('limit', String(params.limit));
    return apiClient.get<PlatformUserSearchResult>(
      `/iam/v1/admin/namespaces/${namespace}/platform-users/search?${queryParams.toString()}`
    );
  },

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

  updatePlatformClientActive: (namespace: string, platformId: string, active: boolean) =>
    apiClient.put<PlatformClient>(
      `/iam/v1/admin/namespaces/${namespace}/platform-clients/${platformId}/active`,
      { active }
    ),

  deletePlatformClient: (namespace: string, platformId: string) =>
    apiClient.delete(`/iam/v1/admin/namespaces/${namespace}/platform-clients/${platformId}`),
};
