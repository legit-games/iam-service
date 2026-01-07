import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { namespaceApi } from '../api/namespaces';
import { CreateNamespaceRequest, UpdateNamespaceRequest } from '../api/types';

export const NAMESPACES_KEY = ['namespaces'];

export function useNamespaces() {
  return useQuery({
    queryKey: NAMESPACES_KEY,
    queryFn: () => namespaceApi.list().then((r) => r.data),
  });
}

export function useNamespace(name: string) {
  return useQuery({
    queryKey: [...NAMESPACES_KEY, name],
    queryFn: () => namespaceApi.get(name).then((r) => r.data),
    enabled: !!name,
  });
}

export function useCreateNamespace() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateNamespaceRequest) => namespaceApi.create(data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: NAMESPACES_KEY });
    },
  });
}

export function useUpdateNamespace() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ name, data }: { name: string; data: UpdateNamespaceRequest }) =>
      namespaceApi.update(name, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: NAMESPACES_KEY });
    },
  });
}
