import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE || '';

// Public API client (no auth required for password reset)
const publicClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

export interface ForgotPasswordRequest {
  email: string;
}

export interface ForgotPasswordResponse {
  success: boolean;
  message: string;
  expires_in_secs?: number;
}

export interface ValidateResetCodeResponse {
  valid: boolean;
  reason?: string;
  remaining_attempts?: number;
  locked_until?: string;
}

export interface ResetPasswordRequest {
  email: string;
  code: string;
  new_password: string;
}

export interface ResetPasswordResponse {
  success: boolean;
  message?: string;
}

export interface PasswordResetError {
  error: string;
  error_description: string;
  retry_after?: number;
  remaining_attempts?: number;
  locked_until?: string;
}

export async function forgotPassword(email: string): Promise<ForgotPasswordResponse> {
  const response = await publicClient.post<ForgotPasswordResponse>(
    '/iam/v1/public/users/forgot-password',
    { email }
  );
  return response.data;
}

export async function validateResetCode(email: string, code: string): Promise<ValidateResetCodeResponse> {
  const response = await publicClient.get<ValidateResetCodeResponse>(
    '/iam/v1/public/users/reset-password/validate',
    { params: { email, code } }
  );
  return response.data;
}

export async function resetPassword(
  email: string,
  code: string,
  newPassword: string
): Promise<ResetPasswordResponse> {
  const response = await publicClient.post<ResetPasswordResponse>(
    '/iam/v1/public/users/reset-password',
    { email, code, new_password: newPassword }
  );
  return response.data;
}
