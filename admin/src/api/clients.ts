import apiClient from './client';
import {
  Client,
  CreateClientRequest,
  UpdateClientPermissionsRequest,
  UpdateClientScopesRequest,
} from './types';

export const clientApi = {
  // Create or upsert client in namespace
  create: (namespace: string, data: CreateClientRequest) =>
    apiClient.post<Client>(`/iam/v1/admin/namespaces/${namespace}/clients`, data),

  // List all clients
  listAll: () =>
    apiClient.get<Client[]>('/iam/v1/admin/clients'),

  // List clients by namespace
  listByNamespace: (namespace: string, params?: { offset?: number; limit?: number }) =>
    apiClient.get<Client[]>(`/iam/v1/admin/namespaces/${namespace}/clients`, { params }),

  // Get client by ID
  get: (id: string) =>
    apiClient.get<Client>(`/iam/v1/admin/clients/${id}`),

  // Delete client
  delete: (id: string) =>
    apiClient.delete(`/iam/v1/admin/clients/${id}`),

  // Update client permissions
  updatePermissions: (namespace: string, id: string, data: UpdateClientPermissionsRequest) =>
    apiClient.put(`/iam/v1/admin/namespaces/${namespace}/clients/${id}/permissions`, data),

  // Update client scopes
  updateScopes: (namespace: string, id: string, data: UpdateClientScopesRequest) =>
    apiClient.put(`/iam/v1/admin/namespaces/${namespace}/clients/${id}/scopes`, data),

  // Update client scopes (global - without namespace)
  updateScopesGlobal: (id: string, data: UpdateClientScopesRequest) =>
    apiClient.put(`/iam/v1/admin/clients/${id}/scopes`, data),
};
