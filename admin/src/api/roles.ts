import apiClient from './client';
import { Role, CreateRoleRequest, UserRole, ClientRole, RoleType } from './types';

export const roleApi = {
  // Create or upsert role
  create: (namespace: string, data: CreateRoleRequest) =>
    apiClient.post<Role>(`/iam/v1/admin/namespaces/${namespace}/roles`, data),

  // List roles by namespace
  list: (namespace: string, params?: { roleType?: RoleType }) =>
    apiClient.get<{ roles: Role[] }>(`/iam/v1/admin/namespaces/${namespace}/roles`, { params }),

  // Get role by ID
  get: (namespace: string, id: string) =>
    apiClient.get<Role>(`/iam/v1/admin/namespaces/${namespace}/roles/${id}`),

  // Delete role
  delete: (namespace: string, id: string) =>
    apiClient.delete(`/iam/v1/admin/namespaces/${namespace}/roles/${id}`),

  // Assign role to user
  assignToUser: (namespace: string, roleId: string, userId: string) =>
    apiClient.post<UserRole>(`/iam/v1/admin/namespaces/${namespace}/roles/${roleId}/users/${userId}`),

  // Assign role to client
  assignToClient: (namespace: string, roleId: string, clientId: string) =>
    apiClient.post<ClientRole>(`/iam/v1/admin/namespaces/${namespace}/roles/${roleId}/clients/${clientId}`),

  // Assign role to all users in namespace
  assignToAllUsers: (namespace: string, roleId: string) =>
    apiClient.post(`/iam/v1/admin/namespaces/${namespace}/roles/${roleId}/assign-all-users`),

  // Get user's roles (placeholder)
  getUserRoles: (namespace: string, userId: string) =>
    apiClient.get<UserRole[]>(`/iam/v1/admin/namespaces/${namespace}/users/${userId}/roles`),

  // Get client's roles (placeholder)
  getClientRoles: (namespace: string, clientId: string) =>
    apiClient.get<ClientRole[]>(`/iam/v1/admin/namespaces/${namespace}/clients/${clientId}/roles`),
};
