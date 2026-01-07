import { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './useAuth';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredScopes?: string[];
}

export function ProtectedRoute({ children, requiredScopes }: ProtectedRouteProps) {
  const { isAuthenticated, hasAllScopes } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredScopes && !hasAllScopes(requiredScopes)) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <h2>Access Denied</h2>
        <p>You do not have the required permissions to view this page.</p>
        <p>Required scopes: {requiredScopes.join(', ')}</p>
      </div>
    );
  }

  return <>{children}</>;
}
