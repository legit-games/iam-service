import apiClient from './client';

// MFA Setup Response
export interface MFASetupResponse {
  secret: string;
  qr_code_url: string;
  account_name: string;
  issuer: string;
}

// MFA Setup Verify Response
export interface MFASetupVerifyResponse {
  success: boolean;
  backup_codes: string[];
}

// MFA Status Response
export interface MFAStatusResponse {
  mfa_enabled: boolean;
  totp_configured: boolean;
  enabled_at?: string;
  backup_codes_remaining?: number;
}

// MFA Backup Codes Response
export interface MFABackupCodesResponse {
  backup_codes: string[];
  created_at: string;
}

// MFA Disable Request
export interface MFADisableRequest {
  password: string;
  code: string;
  code_type: 'totp' | 'backup';
}

// MFA Login Verify Request
export interface MFALoginVerifyRequest {
  mfa_token: string;
  code: string;
  code_type: 'totp' | 'backup';
}

// MFA Login Verify Response
export interface MFALoginVerifyResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

// Namespace MFA Settings
export interface NamespaceMFASettings {
  namespace: string;
  mfa_required: boolean;
  grace_period_days: number;
}

// Admin User MFA Status
export interface AdminUserMFAStatus {
  account_id: string;
  mfa_enabled: boolean;
  totp_configured: boolean;
  enabled_at?: string;
}

export const mfaApi = {
  // User MFA endpoints (requires authentication)

  // Get MFA setup info (generates secret and QR code)
  getSetup: () =>
    apiClient.get<MFASetupResponse>('/iam/v1/auth/mfa/setup'),

  // Verify TOTP code and enable MFA
  verifySetup: (code: string) =>
    apiClient.post<MFASetupVerifyResponse>('/iam/v1/auth/mfa/setup/verify', { code }),

  // Get current MFA status
  getStatus: () =>
    apiClient.get<MFAStatusResponse>('/iam/v1/auth/mfa/status'),

  // Get backup codes (returns masked codes)
  getBackupCodes: () =>
    apiClient.get<MFABackupCodesResponse>('/iam/v1/auth/mfa/backup-codes'),

  // Regenerate backup codes
  regenerateBackupCodes: (data: { password: string; code: string; code_type: 'totp' | 'backup' }) =>
    apiClient.post<MFABackupCodesResponse>('/iam/v1/auth/mfa/backup-codes/regenerate', data),

  // Disable MFA
  disable: (data: MFADisableRequest) =>
    apiClient.post<{ success: boolean }>('/iam/v1/auth/mfa/disable', data),

  // Public MFA login verification
  verifyLogin: (data: MFALoginVerifyRequest) =>
    apiClient.post<MFALoginVerifyResponse>('/iam/v1/public/login/mfa/verify', data),

  // Admin endpoints (requires admin permissions)

  // Get namespace MFA settings
  getNamespaceSettings: (namespace: string) =>
    apiClient.get<NamespaceMFASettings>(`/iam/v1/admin/namespaces/${namespace}/mfa/settings`),

  // Update namespace MFA settings
  updateNamespaceSettings: (namespace: string, data: { mfa_required: boolean; grace_period_days?: number }) =>
    apiClient.post<NamespaceMFASettings>(`/iam/v1/admin/namespaces/${namespace}/mfa/settings`, data),

  // Get user MFA status (admin)
  getUserMFAStatus: (namespace: string, userId: string) =>
    apiClient.get<AdminUserMFAStatus>(`/iam/v1/admin/namespaces/${namespace}/mfa/users/${userId}/status`),

  // Disable user MFA (admin)
  disableUserMFA: (namespace: string, userId: string) =>
    apiClient.delete<{ success: boolean }>(`/iam/v1/admin/namespaces/${namespace}/mfa/users/${userId}`),
};
