import { useQuery } from '@tanstack/react-query';
import { userApi } from '../api/users';

const USERS_KEY = ['users'];

export function useUser(namespace: string, userId: string) {
  return useQuery({
    queryKey: [...USERS_KEY, namespace, userId],
    queryFn: () => userApi.getUser(namespace, userId).then((r) => r.data.user),
    enabled: !!namespace && !!userId,
    retry: false,
  });
}
