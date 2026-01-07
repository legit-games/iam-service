import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clientApi } from '../api/clients';
import { CreateClientRequest, UpdateClientPermissionsRequest, UpdateClientScopesRequest } from '../api/types';

export const CLIENTS_KEY = ['clients'];

export function useClients(namespace?: string) {
  return useQuery({
    queryKey: namespace ? [...CLIENTS_KEY, namespace] : CLIENTS_KEY,
    queryFn: () =>
      namespace
        ? clientApi.listByNamespace(namespace).then((r) => r.data)
        : clientApi.listAll().then((r) => r.data),
  });
}

export function useClient(id: string) {
  return useQuery({
    queryKey: [...CLIENTS_KEY, 'detail', id],
    queryFn: () => clientApi.get(id).then((r) => r.data),
    enabled: !!id,
  });
}

export function useCreateClient(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateClientRequest) => clientApi.create(namespace, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CLIENTS_KEY });
    },
  });
}

export function useDeleteClient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => clientApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CLIENTS_KEY });
    },
  });
}

export function useUpdateClientPermissions(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateClientPermissionsRequest }) =>
      clientApi.updatePermissions(namespace, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CLIENTS_KEY });
    },
  });
}

export function useUpdateClientScopes(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateClientScopesRequest }) =>
      clientApi.updateScopes(namespace, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CLIENTS_KEY });
    },
  });
}
