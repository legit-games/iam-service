import { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react';
import { useNamespaces } from './useNamespaces';
import { Namespace } from '../api/types';

interface NamespaceContextValue {
  currentNamespace: string | null;
  namespaces: Namespace[];
  isLoading: boolean;
  setCurrentNamespace: (ns: string) => void;
}

const NamespaceContext = createContext<NamespaceContextValue | null>(null);

const NAMESPACE_STORAGE_KEY = 'admin_current_namespace';

export function NamespaceProvider({ children }: { children: ReactNode }) {
  const { data: namespaces = [], isLoading } = useNamespaces();
  const [currentNamespace, setCurrentNamespaceState] = useState<string | null>(() => {
    return localStorage.getItem(NAMESPACE_STORAGE_KEY);
  });

  // Set initial namespace when namespaces load
  useEffect(() => {
    if (namespaces.length > 0 && !currentNamespace) {
      const firstNs = namespaces[0].name;
      setCurrentNamespaceState(firstNs);
      localStorage.setItem(NAMESPACE_STORAGE_KEY, firstNs);
    }
  }, [namespaces, currentNamespace]);

  const setCurrentNamespace = useCallback((ns: string) => {
    setCurrentNamespaceState(ns);
    localStorage.setItem(NAMESPACE_STORAGE_KEY, ns);
  }, []);

  return (
    <NamespaceContext.Provider
      value={{
        currentNamespace,
        namespaces,
        isLoading,
        setCurrentNamespace,
      }}
    >
      {children}
    </NamespaceContext.Provider>
  );
}

export function useNamespaceContext(): NamespaceContextValue {
  const context = useContext(NamespaceContext);
  if (!context) {
    throw new Error('useNamespaceContext must be used within a NamespaceProvider');
  }
  return context;
}
