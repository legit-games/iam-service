import apiClient from './client';

export interface RequestEmailVerificationResponse {
  success: boolean;
  message: string;
  expires_in_secs?: number;
  already_verified?: boolean;
}

export interface ValidateEmailVerificationResponse {
  valid: boolean;
  reason?: string;
  remaining_attempts?: number;
  locked_until?: string;
}

export interface VerifyEmailResponse {
  success: boolean;
  message?: string;
}

export interface EmailVerificationStatusResponse {
  email: string;
  verified: boolean;
  verified_at?: string;
  pending_code?: boolean;
  expires_at?: string;
}

export interface EmailVerificationError {
  error: string;
  error_description: string;
  retry_after?: number;
  remaining_attempts?: number;
  locked_until?: string;
}

export async function requestEmailVerification(email: string): Promise<RequestEmailVerificationResponse> {
  const response = await apiClient.post<RequestEmailVerificationResponse>(
    '/iam/v1/users/request-email-verification',
    { email }
  );
  return response.data;
}

export async function validateEmailVerificationCode(
  email: string,
  code: string
): Promise<ValidateEmailVerificationResponse> {
  const response = await apiClient.get<ValidateEmailVerificationResponse>(
    '/iam/v1/users/verify-email/validate',
    { params: { email, code } }
  );
  return response.data;
}

export async function verifyEmail(email: string, code: string): Promise<VerifyEmailResponse> {
  const response = await apiClient.post<VerifyEmailResponse>('/iam/v1/users/verify-email', {
    email,
    code,
  });
  return response.data;
}

export async function resendEmailVerification(email: string): Promise<RequestEmailVerificationResponse> {
  const response = await apiClient.post<RequestEmailVerificationResponse>(
    '/iam/v1/users/resend-email-verification',
    { email }
  );
  return response.data;
}

export async function getEmailVerificationStatus(email: string): Promise<EmailVerificationStatusResponse> {
  const response = await apiClient.get<EmailVerificationStatusResponse>(
    '/iam/v1/users/email-verification-status',
    { params: { email } }
  );
  return response.data;
}
