import { useState, useEffect, useCallback, useRef, ReactNode } from 'react';
import { AuthContext, AdminUser } from './AuthContext';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  storePKCE,
  getPKCE,
  clearPKCE,
} from './pkce';
import {
  getAccessToken,
  setAccessToken,
  getRefreshToken,
  setRefreshToken,
  clearAllTokens,
  isTokenExpiringSoon,
} from './storage';
import { ADMIN_REQUIRED_SCOPES } from '../constants/scopes';

const CLIENT_ID = import.meta.env.VITE_OAUTH_CLIENT_ID || 'admin-console';
// Use absolute URL for redirect_uri to pass OAuth server validation
const REDIRECT_URI = import.meta.env.VITE_OAUTH_REDIRECT_URI || `${window.location.origin}/admin/callback`;
const API_BASE = import.meta.env.VITE_API_BASE || '';
// OAuth server URL for browser redirects (not proxied by Vite)
const OAUTH_SERVER = import.meta.env.VITE_OAUTH_SERVER || API_BASE;

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

interface UserInfoResponse {
  sub: string;
  preferred_username?: string;
  account_id?: string;
  namespace?: string;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  // Debug: Check sessionStorage immediately on component load
  const debugStorage = {
    token: !!sessionStorage.getItem('oauth_access_token'),
    refresh: !!sessionStorage.getItem('oauth_refresh_token'),
    expiry: sessionStorage.getItem('oauth_token_expiry'),
  };
  console.log('[AuthProvider] IMMEDIATE CHECK on mount:', debugStorage);

  const [user, setUser] = useState<AdminUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [tokenScopes, setTokenScopes] = useState<string[]>([]);
  const initCompleted = useRef(false);

  const fetchUserInfo = useCallback(async (token: string, scopes?: string[]): Promise<AdminUser | null> => {
    console.log('[AuthProvider] fetchUserInfo called, API_BASE:', API_BASE);
    try {
      const url = `${API_BASE}/oauth/userinfo`;
      console.log('[AuthProvider] Fetching userinfo from:', url);
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      console.log('[AuthProvider] userinfo response status:', response.status);
      if (!response.ok) {
        console.log('[AuthProvider] userinfo response not ok');
        return null;
      }

      const data: UserInfoResponse = await response.json();
      console.log('[AuthProvider] userinfo data:', data);
      return {
        id: data.sub,
        username: data.preferred_username || data.sub,
        accountId: data.account_id || data.sub,
        namespace: data.namespace,
        scopes: scopes || [],
      };
    } catch (err) {
      console.error('[AuthProvider] fetchUserInfo error:', err);
      return null;
    }
  }, []);

  const refreshAccessToken = useCallback(async (): Promise<boolean> => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;

    // Prevent concurrent refresh attempts (React StrictMode double-mount)
    const refreshKey = 'oauth_refresh_in_progress';
    if (sessionStorage.getItem(refreshKey)) {
      // Wait for ongoing refresh to complete
      await new Promise(resolve => setTimeout(resolve, 500));
      return !!getAccessToken();
    }
    sessionStorage.setItem(refreshKey, 'true');

    try {
      const response = await fetch(`${API_BASE}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
        }),
      });

      if (!response.ok) {
        clearAllTokens();
        return false;
      }

      const data: TokenResponse = await response.json();
      setAccessToken(data.access_token, data.expires_in);
      if (data.refresh_token) {
        setRefreshToken(data.refresh_token);
      }
      if (data.scope) {
        setTokenScopes(data.scope.split(' '));
      }
      return true;
    } catch {
      clearAllTokens();
      return false;
    } finally {
      sessionStorage.removeItem(refreshKey);
    }
  }, []);

  // Initialize auth state (runs once on mount)
  useEffect(() => {
    console.log('[AuthProvider] initAuth effect running, initCompleted:', initCompleted.current);
    if (initCompleted.current) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    const initAuth = async () => {
      const token = getAccessToken();
      const refreshToken = getRefreshToken();
      console.log('[AuthProvider] initAuth - token:', !!token, 'refreshToken:', !!refreshToken);

      if (token) {
        console.log('[AuthProvider] Calling fetchUserInfo with token');
        const userInfo = await fetchUserInfo(token, tokenScopes);
        console.log('[AuthProvider] fetchUserInfo result:', userInfo);
        if (cancelled) return;
        if (userInfo) {
          initCompleted.current = true;
          setUser(userInfo);
          setIsLoading(false);
          return;
        }
      }

      if (refreshToken) {
        console.log('[AuthProvider] Trying refresh token');
        const refreshed = await refreshAccessToken();
        console.log('[AuthProvider] refresh result:', refreshed);
        if (cancelled) return;
        if (refreshed) {
          const newToken = getAccessToken();
          if (newToken) {
            console.log('[AuthProvider] Calling fetchUserInfo with new token');
            const userInfo = await fetchUserInfo(newToken, tokenScopes);
            console.log('[AuthProvider] fetchUserInfo result after refresh:', userInfo);
            if (cancelled) return;
            if (userInfo) {
              initCompleted.current = true;
              setUser(userInfo);
              setIsLoading(false);
              return;
            }
          }
        }
      }

      if (!cancelled) {
        console.log('[AuthProvider] No valid auth, setting user to null');
        initCompleted.current = true;
        setUser(null);
        setIsLoading(false);
      }
    };

    initAuth();

    return () => {
      cancelled = true;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Set up token refresh interval
  useEffect(() => {
    if (!user) return;

    const checkAndRefresh = async () => {
      if (isTokenExpiringSoon(120000)) { // 2 minutes before expiry
        await refreshAccessToken();
      }
    };

    const interval = setInterval(checkAndRefresh, 60000); // Check every minute
    return () => clearInterval(interval);
  }, [user, refreshAccessToken]);

  const login = useCallback(async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const state = generateState();

    storePKCE(verifier, state);

    const scopes = ADMIN_REQUIRED_SCOPES.join(' ');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: scopes,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${OAUTH_SERVER}/oauth/authorize?${params}`;
  }, []);

  const logout = useCallback(async () => {
    const token = getAccessToken();
    if (token) {
      try {
        await fetch(`${API_BASE}/oauth/revoke`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            token,
            client_id: CLIENT_ID,
          }),
        });
      } catch {
        // Ignore revoke errors
      }
    }

    clearAllTokens();
    clearPKCE();
    setUser(null);
    window.location.href = '/admin/login';
  }, []);

  const hasScope = useCallback(
    (scope: string) => tokenScopes.includes(scope) || tokenScopes.includes('admin'),
    [tokenScopes]
  );

  const hasAnyScope = useCallback(
    (scopes: string[]) => scopes.some((s) => hasScope(s)),
    [hasScope]
  );

  const hasAllScopes = useCallback(
    (scopes: string[]) => scopes.every((s) => hasScope(s)),
    [hasScope]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        hasScope,
        hasAnyScope,
        hasAllScopes,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// Export token exchange function for callback page
export async function exchangeCodeForTokens(code: string): Promise<{ success: boolean; error?: string }> {
  const { verifier, state: storedState } = getPKCE();

  if (!verifier) {
    return { success: false, error: 'Missing PKCE verifier' };
  }

  // Get state from URL
  const urlParams = new URLSearchParams(window.location.search);
  const urlState = urlParams.get('state');

  if (urlState !== storedState) {
    return { success: false, error: 'State mismatch - possible CSRF attack' };
  }

  try {
    const response = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: verifier,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      return { success: false, error: error.error_description || error.error || 'Token exchange failed' };
    }

    const data: TokenResponse = await response.json();
    setAccessToken(data.access_token, data.expires_in);
    if (data.refresh_token) {
      setRefreshToken(data.refresh_token);
    }
    clearPKCE();
    return { success: true };
  } catch (err) {
    return { success: false, error: 'Network error during token exchange' };
  }
}
