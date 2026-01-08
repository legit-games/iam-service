import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { banApi } from '../api/bans';
import { BanRequest, UnbanRequest } from '../api/types';

export const BANS_KEY = ['bans'];

export function useNamespaceBans(namespace: string, active?: boolean) {
  return useQuery({
    queryKey: [...BANS_KEY, namespace, { active }],
    queryFn: () => banApi.listNamespaceBans(namespace, { active }).then((r) => r.data.bans || []),
    enabled: !!namespace,
  });
}

export function useUserBans(namespace: string, userId: string) {
  return useQuery({
    queryKey: [...BANS_KEY, namespace, 'user', userId],
    queryFn: () => banApi.listUserBans(namespace, userId).then((r) => r.data.bans || []),
    enabled: !!namespace && !!userId,
  });
}

export function useAccountBans(accountId: string) {
  return useQuery({
    queryKey: [...BANS_KEY, 'account', accountId],
    queryFn: () => banApi.listAccountBans(accountId).then((r) => r.data.bans || []),
    enabled: !!accountId,
  });
}

export function useBanUser(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: BanRequest }) =>
      banApi.banUser(namespace, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...BANS_KEY, namespace] });
    },
  });
}

export function useUnbanUser(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: UnbanRequest }) =>
      banApi.unbanUser(namespace, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...BANS_KEY, namespace] });
    },
  });
}

export function useBanAccount() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ accountId, data }: { accountId: string; data: BanRequest }) =>
      banApi.banAccount(accountId, data),
    onSuccess: (_, { accountId }) => {
      queryClient.invalidateQueries({ queryKey: [...BANS_KEY, 'account', accountId] });
    },
  });
}

export function useUnbanAccount() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ accountId, data }: { accountId: string; data: UnbanRequest }) =>
      banApi.unbanAccount(accountId, data),
    onSuccess: (_, { accountId }) => {
      queryClient.invalidateQueries({ queryKey: [...BANS_KEY, 'account', accountId] });
    },
  });
}
