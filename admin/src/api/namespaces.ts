import apiClient from './client';
import { Namespace, CreateNamespaceRequest, UpdateNamespaceRequest } from './types';

const BASE_PATH = '/iam/v1/admin/namespaces';

export const namespaceApi = {
  create: (data: CreateNamespaceRequest) =>
    apiClient.post<Namespace>(BASE_PATH, data),

  list: () =>
    apiClient.get<Namespace[]>(BASE_PATH),

  get: (name: string) =>
    apiClient.get<Namespace>(`${BASE_PATH}/${name}`),

  update: (name: string, data: UpdateNamespaceRequest) =>
    apiClient.put<Namespace>(`${BASE_PATH}/${name}`, data),
};
