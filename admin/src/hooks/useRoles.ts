import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { roleApi } from '../api/roles';
import { CreateRoleRequest, RoleType } from '../api/types';

export const ROLES_KEY = ['roles'];

export function useRoles(namespace: string, roleType?: RoleType) {
  return useQuery({
    queryKey: [...ROLES_KEY, namespace, roleType],
    queryFn: () => roleApi.list(namespace, { roleType }).then((r) => r.data.roles),
    enabled: !!namespace,
  });
}

export function useRole(namespace: string, id: string) {
  return useQuery({
    queryKey: [...ROLES_KEY, namespace, 'detail', id],
    queryFn: () => roleApi.get(namespace, id).then((r) => r.data),
    enabled: !!namespace && !!id,
  });
}

export function useCreateRole(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateRoleRequest) => roleApi.create(namespace, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...ROLES_KEY, namespace] });
    },
  });
}

export function useDeleteRole(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => roleApi.delete(namespace, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...ROLES_KEY, namespace] });
    },
  });
}

export function useAssignRoleToUser(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ roleId, userId }: { roleId: string; userId: string }) =>
      roleApi.assignToUser(namespace, roleId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ROLES_KEY });
    },
  });
}

export function useAssignRoleToClient(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ roleId, clientId }: { roleId: string; clientId: string }) =>
      roleApi.assignToClient(namespace, roleId, clientId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ROLES_KEY });
    },
  });
}

export function useAssignRoleToAllUsers(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (roleId: string) => roleApi.assignToAllUsers(namespace, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ROLES_KEY });
    },
  });
}
