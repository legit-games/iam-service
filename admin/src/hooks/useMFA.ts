import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mfaApi, MFADisableRequest } from '../api/mfa';
import { message } from 'antd';

const MFA_STATUS_KEY = ['mfa-status'];
const MFA_SETUP_KEY = ['mfa-setup'];
const MFA_BACKUP_CODES_KEY = ['mfa-backup-codes'];
const NAMESPACE_MFA_SETTINGS_KEY = ['namespace-mfa-settings'];
const USER_MFA_STATUS_KEY = ['user-mfa-status'];

// Get current user's MFA status
export function useMFAStatus() {
  return useQuery({
    queryKey: MFA_STATUS_KEY,
    queryFn: () => mfaApi.getStatus().then((r) => r.data),
    retry: false,
  });
}

// Get MFA setup info (secret + QR code)
export function useMFASetup(enabled = false) {
  const queryClient = useQueryClient();

  return useQuery({
    queryKey: MFA_SETUP_KEY,
    queryFn: async () => {
      try {
        const response = await mfaApi.getSetup();
        return response.data;
      } catch (error: unknown) {
        // Handle 409 Conflict - MFA is already enabled
        if (error && typeof error === 'object' && 'response' in error) {
          const axiosError = error as { response?: { status?: number } };
          if (axiosError.response?.status === 409) {
            // Invalidate status to refresh and show correct state
            queryClient.invalidateQueries({ queryKey: MFA_STATUS_KEY });
            message.info('MFA is already enabled for your account');
            return null;
          }
        }
        throw error;
      }
    },
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

// Verify TOTP code and enable MFA
export function useMFAVerifySetup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (code: string) => mfaApi.verifySetup(code),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: MFA_STATUS_KEY });
      queryClient.removeQueries({ queryKey: MFA_SETUP_KEY });
      message.success('MFA enabled successfully');
      return response.data;
    },
    onError: (error: Error) => {
      message.error(`Failed to enable MFA: ${error.message}`);
    },
  });
}

// Get backup codes
export function useMFABackupCodes(enabled = false) {
  return useQuery({
    queryKey: MFA_BACKUP_CODES_KEY,
    queryFn: () => mfaApi.getBackupCodes().then((r) => r.data),
    enabled,
    retry: false,
  });
}

// Regenerate backup codes
export function useMFARegenerateBackupCodes() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { password: string; code: string; code_type: 'totp' | 'backup' }) =>
      mfaApi.regenerateBackupCodes(data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: MFA_BACKUP_CODES_KEY });
      queryClient.invalidateQueries({ queryKey: MFA_STATUS_KEY });
      message.success('Backup codes regenerated successfully');
      return response.data;
    },
    onError: (error: Error) => {
      message.error(`Failed to regenerate backup codes: ${error.message}`);
    },
  });
}

// Disable MFA
export function useMFADisable() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: MFADisableRequest) => mfaApi.disable(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: MFA_STATUS_KEY });
      queryClient.removeQueries({ queryKey: MFA_SETUP_KEY });
      queryClient.removeQueries({ queryKey: MFA_BACKUP_CODES_KEY });
      message.success('MFA disabled successfully');
    },
    onError: (error: Error) => {
      message.error(`Failed to disable MFA: ${error.message}`);
    },
  });
}

// Admin: Get namespace MFA settings
export function useNamespaceMFASettings(namespace: string) {
  return useQuery({
    queryKey: [...NAMESPACE_MFA_SETTINGS_KEY, namespace],
    queryFn: () => mfaApi.getNamespaceSettings(namespace).then((r) => r.data),
    enabled: !!namespace,
    retry: false,
  });
}

// Admin: Update namespace MFA settings
export function useUpdateNamespaceMFASettings(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { mfa_required: boolean; grace_period_days?: number }) =>
      mfaApi.updateNamespaceSettings(namespace, data),
    onSuccess: (response) => {
      queryClient.setQueryData([...NAMESPACE_MFA_SETTINGS_KEY, namespace], response.data);
      message.success('Namespace MFA settings updated');
    },
    onError: (error: Error) => {
      message.error(`Failed to update MFA settings: ${error.message}`);
    },
  });
}

// Admin: Get user MFA status
export function useUserMFAStatus(namespace: string, userId: string) {
  return useQuery({
    queryKey: [...USER_MFA_STATUS_KEY, namespace, userId],
    queryFn: () => mfaApi.getUserMFAStatus(namespace, userId).then((r) => r.data),
    enabled: !!namespace && !!userId,
    retry: false,
  });
}

// Admin: Disable user MFA
export function useDisableUserMFA(namespace: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (userId: string) => mfaApi.disableUserMFA(namespace, userId),
    onSuccess: (_, userId) => {
      queryClient.invalidateQueries({ queryKey: [...USER_MFA_STATUS_KEY, namespace, userId] });
      message.success('User MFA disabled successfully');
    },
    onError: (error: Error) => {
      message.error(`Failed to disable user MFA: ${error.message}`);
    },
  });
}
