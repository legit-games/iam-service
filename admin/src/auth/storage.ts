// Token storage utilities
// Tokens are stored in sessionStorage (cleared when browser tab closes)

const ACCESS_TOKEN_KEY = 'oauth_access_token';
const REFRESH_TOKEN_KEY = 'oauth_refresh_token';
const TOKEN_EXPIRY_KEY = 'oauth_token_expiry';

export function getAccessToken(): string | null {
  const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  const expiryStr = sessionStorage.getItem(TOKEN_EXPIRY_KEY);

  console.log('[storage] getAccessToken - token exists:', !!token, 'expiry:', expiryStr, 'now:', Date.now());

  // Check if token is expired
  if (token && expiryStr) {
    const expiry = parseInt(expiryStr, 10);
    if (Date.now() >= expiry) {
      console.log('[storage] Token expired! Clearing...');
      sessionStorage.removeItem(ACCESS_TOKEN_KEY);
      sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
      return null;
    }
  }
  return token;
}

export function setAccessToken(token: string, expiresIn: number): void {
  console.log('[storage] setAccessToken - expiresIn:', expiresIn, 'computed expiry:', Date.now() + expiresIn * 1000);
  const expiry = Date.now() + expiresIn * 1000;
  sessionStorage.setItem(ACCESS_TOKEN_KEY, token);
  sessionStorage.setItem(TOKEN_EXPIRY_KEY, expiry.toString());
}

export function clearAccessToken(): void {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
}

export function getRefreshToken(): string | null {
  return sessionStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setRefreshToken(token: string): void {
  sessionStorage.setItem(REFRESH_TOKEN_KEY, token);
}

export function clearRefreshToken(): void {
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function clearAllTokens(): void {
  console.log('[storage] clearAllTokens called', new Error().stack);
  clearAccessToken();
  clearRefreshToken();
}

export function getTokenExpiry(): number | null {
  const stored = sessionStorage.getItem(TOKEN_EXPIRY_KEY);
  return stored ? parseInt(stored, 10) : null;
}

export function isTokenExpiringSoon(thresholdMs: number = 60000): boolean {
  const expiry = getTokenExpiry();
  if (!expiry) return true;
  return Date.now() >= expiry - thresholdMs;
}
