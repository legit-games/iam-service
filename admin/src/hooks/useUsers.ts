import { useQuery } from '@tanstack/react-query';
import { userApi, SearchType } from '../api/users';

const USERS_KEY = ['users'];

export function useUser(namespace: string, userId: string, searchType?: SearchType) {
  return useQuery({
    queryKey: [...USERS_KEY, namespace, userId, searchType],
    queryFn: () => userApi.getUser(namespace, userId, searchType).then((r) => r.data.user),
    enabled: !!namespace && !!userId,
    retry: false,
  });
}
