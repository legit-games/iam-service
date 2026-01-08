import { createContext } from 'react';

export interface AdminUser {
  id: string;
  username: string;
  displayName?: string;
  accountId: string;
  namespace?: string;
  scopes: string[];
}

export interface AuthContextValue {
  user: AdminUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  hasScope: (scope: string) => boolean;
  hasAnyScope: (scopes: string[]) => boolean;
  hasAllScopes: (scopes: string[]) => boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
