import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi, SearchType } from '../api/users';
import { message } from 'antd';

const USERS_KEY = ['users'];
const USER_PERMISSIONS_KEY = ['user-permissions'];
const LOGIN_HISTORY_KEY = ['login-history'];
const SIGNUP_STATS_KEY = ['signup-stats'];

export function useUser(namespace: string, userId: string, searchType?: SearchType) {
  return useQuery({
    queryKey: [...USERS_KEY, namespace, userId, searchType],
    queryFn: () => userApi.getUser(namespace, userId, searchType).then((r) => r.data.user),
    enabled: !!namespace && !!userId,
    retry: false,
  });
}

export function useUserPermissions(userId: string) {
  return useQuery({
    queryKey: [...USER_PERMISSIONS_KEY, userId],
    queryFn: () => userApi.getUserPermissions(userId).then((r) => r.data.permissions),
    enabled: !!userId,
    retry: false,
  });
}

export function useUpdateUserPermissions(userId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (permissions: string[]) => userApi.updateUserPermissions(userId, permissions),
    onSuccess: (response) => {
      queryClient.setQueryData([...USER_PERMISSIONS_KEY, userId], response.data.permissions);
      message.success('Permissions updated successfully');
    },
    onError: (error: Error) => {
      message.error(`Failed to update permissions: ${error.message}`);
    },
  });
}

export function useLoginHistory(userId: string, limit?: number) {
  return useQuery({
    queryKey: [...LOGIN_HISTORY_KEY, userId, limit],
    queryFn: () => userApi.getLoginHistory(userId, { limit }).then((r) => r.data.login_history),
    enabled: !!userId,
    retry: false,
  });
}

export function useSignupStats(namespace: string) {
  return useQuery({
    queryKey: [...SIGNUP_STATS_KEY, namespace],
    queryFn: () => userApi.getSignupStats(namespace).then((r) => r.data),
    enabled: !!namespace,
    retry: false,
  });
}
