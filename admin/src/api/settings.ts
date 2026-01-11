import apiClient from './client';

export interface EmailSettings {
  provider: string;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  from_address: string;
  from_name: string;
  use_tls: boolean;
  use_ssl: boolean;
  skip_verify: boolean;
  app_name: string;
  support_email: string;
}

export interface UpdateEmailSettingsRequest {
  provider: string;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password?: string;
  from_address: string;
  from_name: string;
  use_tls: boolean;
  use_ssl: boolean;
  skip_verify: boolean;
  app_name: string;
  support_email: string;
}

export interface TestEmailResponse {
  success: boolean;
  message: string;
}

export async function getEmailSettings(): Promise<EmailSettings> {
  const response = await apiClient.get<EmailSettings>('/iam/v1/admin/settings/email');
  return response.data;
}

export async function updateEmailSettings(settings: UpdateEmailSettingsRequest): Promise<void> {
  await apiClient.put('/iam/v1/admin/settings/email', settings);
}

export async function sendTestEmail(toEmail: string): Promise<TestEmailResponse> {
  const response = await apiClient.post<TestEmailResponse>(
    '/iam/v1/admin/settings/email/test',
    { to_email: toEmail }
  );
  return response.data;
}
