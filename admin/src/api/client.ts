import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import { getAccessToken, clearAllTokens } from '../auth/storage';

const API_BASE = import.meta.env.VITE_API_BASE || '';

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Request interceptor: Add Bearer token
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: Handle errors
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ error?: string; error_description?: string }>) => {
    if (error.response?.status === 401) {
      clearAllTokens();
      window.location.href = '/admin/login';
      return Promise.reject(error);
    }

    // Extract error message
    const errorData = error.response?.data;
    const message = errorData?.error_description || errorData?.error || error.message;

    return Promise.reject(new Error(message));
  }
);

export default apiClient;

// Helper function for URL-encoded requests (OAuth endpoints)
export async function postUrlEncoded(url: string, data: Record<string, string>) {
  return apiClient.post(url, new URLSearchParams(data), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
}
