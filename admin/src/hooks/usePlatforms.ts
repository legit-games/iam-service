import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { platformApi } from '../api/platforms';
import { PlatformClient, PlatformUserSearchParams } from '../api/types';

export const PLATFORMS_KEY = ['platforms'];

export function useUserPlatforms(namespace: string, userId: string) {
  return useQuery({
    queryKey: [...PLATFORMS_KEY, 'users', namespace, userId],
    queryFn: () => platformApi.listUserPlatforms(namespace, userId).then((r) => r.data.platforms || []),
    enabled: !!namespace && !!userId,
  });
}

export function useSearchPlatformUsers(namespace: string, params: PlatformUserSearchParams, enabled = true) {
  return useQuery({
    queryKey: [...PLATFORMS_KEY, 'search', namespace, params],
    queryFn: () => platformApi.searchPlatformUsers(namespace, params).then((r) => r.data),
    enabled: !!namespace && enabled,
  });
}

export function usePlatformToken(namespace: string, userId: string, platformId: string) {
  return useQuery({
    queryKey: [...PLATFORMS_KEY, 'token', namespace, userId, platformId],
    queryFn: () => platformApi.getPlatformToken(namespace, userId, platformId).then((r) => r.data),
    enabled: !!namespace && !!userId && !!platformId,
  });
}

export function usePlatformClients(namespace: string) {
  return useQuery({
    queryKey: [...PLATFORMS_KEY, 'clients', namespace],
    queryFn: () => platformApi.listPlatformClients(namespace).then((r) => r.data),
    enabled: !!namespace,
  });
}

export function usePlatformClient(namespace: string, platformId: string) {
  return useQuery({
    queryKey: [...PLATFORMS_KEY, 'clients', namespace, platformId],
    queryFn: () => platformApi.getPlatformClient(namespace, platformId).then((r) => r.data),
    enabled: !!namespace && !!platformId,
  });
}

export function useCreatePlatformClient(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<PlatformClient>) =>
      platformApi.createPlatformClient(namespace, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...PLATFORMS_KEY, 'clients', namespace] });
    },
  });
}

export function useUpdatePlatformClient(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ platformId, data, active }: { platformId: string; data?: Partial<PlatformClient>; active?: boolean }) => {
      // If only active is provided, use the active-only endpoint
      if (active !== undefined && !data) {
        return platformApi.updatePlatformClientActive(namespace, platformId, active).then((r) => r.data);
      }
      // Otherwise use the full update endpoint
      return platformApi.updatePlatformClient(namespace, platformId, data || {}).then((r) => r.data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...PLATFORMS_KEY, 'clients', namespace] });
    },
  });
}

export function useDeletePlatformClient(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (platformId: string) => platformApi.deletePlatformClient(namespace, platformId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...PLATFORMS_KEY, 'clients', namespace] });
    },
  });
}
