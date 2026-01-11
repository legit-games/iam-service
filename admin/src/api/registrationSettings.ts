import apiClient from './client';

export interface RegistrationSettings {
  require_email_verification: boolean;
  namespace: string;
}

export async function getRegistrationSettings(namespace: string): Promise<RegistrationSettings> {
  const response = await apiClient.get<RegistrationSettings>(
    `/iam/v1/admin/namespaces/${namespace}/settings/registration`
  );
  return response.data;
}

export async function updateRegistrationSettings(
  namespace: string,
  settings: { require_email_verification: boolean }
): Promise<{ success: boolean; namespace: string; require_email_verification: boolean }> {
  const response = await apiClient.put<{ success: boolean; namespace: string; require_email_verification: boolean }>(
    `/iam/v1/admin/namespaces/${namespace}/settings/registration`,
    settings
  );
  return response.data;
}
