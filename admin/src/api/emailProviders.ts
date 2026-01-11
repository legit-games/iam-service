import apiClient from './client';

export interface EmailProvider {
  id: string;
  namespace_id?: string;
  name: string;
  provider_type: string;
  is_active: boolean;
  is_default: boolean;
  from_address: string;
  from_name: string;
  reply_to_address?: string;
  config: Record<string, unknown>;
  app_name: string;
  support_email?: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface ProviderTypeInfo {
  type: string;
  name: string;
  description: string;
  config_schema: Record<string, {
    type: string;
    required?: boolean;
    default?: unknown;
    label: string;
  }>;
}

export interface CreateProviderRequest {
  name: string;
  provider_type: string;
  from_address: string;
  from_name?: string;
  reply_to_address?: string;
  config: Record<string, unknown>;
  app_name?: string;
  support_email?: string;
  description?: string;
  is_active?: boolean;
  set_as_default?: boolean;
}

export interface UpdateProviderRequest {
  name?: string;
  from_address?: string;
  from_name?: string;
  reply_to_address?: string;
  config?: Record<string, unknown>;
  app_name?: string;
  support_email?: string;
  description?: string;
  is_active?: boolean;
}

export async function getProviderTypes(): Promise<ProviderTypeInfo[]> {
  const response = await apiClient.get<{ provider_types: ProviderTypeInfo[] }>(
    '/iam/v1/admin/email-providers/types'
  );
  return response.data.provider_types;
}

export async function listEmailProviders(): Promise<EmailProvider[]> {
  const response = await apiClient.get<{ providers: EmailProvider[] }>(
    '/iam/v1/admin/email-providers'
  );
  return response.data.providers;
}

export async function getEmailProvider(id: string): Promise<EmailProvider> {
  const response = await apiClient.get<EmailProvider>(
    `/iam/v1/admin/email-providers/${id}`
  );
  return response.data;
}

export async function createEmailProvider(data: CreateProviderRequest): Promise<EmailProvider> {
  const response = await apiClient.post<EmailProvider>(
    '/iam/v1/admin/email-providers',
    data
  );
  return response.data;
}

export async function updateEmailProvider(id: string, data: UpdateProviderRequest): Promise<EmailProvider> {
  const response = await apiClient.put<EmailProvider>(
    `/iam/v1/admin/email-providers/${id}`,
    data
  );
  return response.data;
}

export async function deleteEmailProvider(id: string): Promise<void> {
  await apiClient.delete(`/iam/v1/admin/email-providers/${id}`);
}

export async function setDefaultProvider(id: string): Promise<void> {
  await apiClient.post(`/iam/v1/admin/email-providers/${id}/set-default`);
}

export async function testEmailProvider(id: string, toEmail: string): Promise<{ message: string }> {
  const response = await apiClient.post<{ success: boolean; message: string }>(
    `/iam/v1/admin/email-providers/${id}/test`,
    { to_email: toEmail }
  );
  return response.data;
}

// ============================================================================
// Namespace-Scoped Email Provider APIs
// ============================================================================

export async function listEmailProvidersByNamespace(namespaceId: string): Promise<EmailProvider[]> {
  const response = await apiClient.get<{ providers: EmailProvider[]; namespace_id: string }>(
    `/iam/v1/admin/namespaces/${namespaceId}/email-providers`
  );
  return response.data.providers;
}

export async function getEmailProviderByNamespace(namespaceId: string, id: string): Promise<EmailProvider> {
  const response = await apiClient.get<EmailProvider>(
    `/iam/v1/admin/namespaces/${namespaceId}/email-providers/${id}`
  );
  return response.data;
}

export async function createEmailProviderByNamespace(namespaceId: string, data: CreateProviderRequest): Promise<EmailProvider> {
  const response = await apiClient.post<EmailProvider>(
    `/iam/v1/admin/namespaces/${namespaceId}/email-providers`,
    data
  );
  return response.data;
}

export async function updateEmailProviderByNamespace(namespaceId: string, id: string, data: UpdateProviderRequest): Promise<EmailProvider> {
  const response = await apiClient.put<EmailProvider>(
    `/iam/v1/admin/namespaces/${namespaceId}/email-providers/${id}`,
    data
  );
  return response.data;
}

export async function deleteEmailProviderByNamespace(namespaceId: string, id: string): Promise<void> {
  await apiClient.delete(`/iam/v1/admin/namespaces/${namespaceId}/email-providers/${id}`);
}

export async function setDefaultProviderByNamespace(namespaceId: string, id: string): Promise<void> {
  await apiClient.post(`/iam/v1/admin/namespaces/${namespaceId}/email-providers/${id}/set-default`);
}

export async function testEmailProviderByNamespace(namespaceId: string, id: string, toEmail: string): Promise<{ message: string }> {
  const response = await apiClient.post<{ success: boolean; message: string }>(
    `/iam/v1/admin/namespaces/${namespaceId}/email-providers/${id}/test`,
    { to_email: toEmail }
  );
  return response.data;
}
