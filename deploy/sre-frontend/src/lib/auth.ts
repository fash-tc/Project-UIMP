'use client';

import { createContext, useContext, useState, useEffect, useCallback, ReactNode, createElement } from 'react';
import { UserProfile } from './types';

/** Read a cookie value from document.cookie */
export function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/** Get the authenticated username from the uip_user cookie */
export function getClientUsername(): string | null {
  return getCookie('uip_user') || null;
}

// ── Auth Context ────────────────────────────────────

interface AuthContextValue {
  user: UserProfile | null;
  permissions: string[];
  loading: boolean;
  hasPermission: (p: string) => boolean;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  permissions: [],
  loading: true,
  hasPermission: () => false,
  refresh: async () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/me', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setUser(data);
        setPermissions(data.permissions || []);
      } else {
        setUser(null);
        setPermissions([]);
      }
    } catch {
      setUser(null);
      setPermissions([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const hasPermission = useCallback((p: string) => permissions.includes(p), [permissions]);

  return createElement(
    AuthContext.Provider,
    { value: { user, permissions, loading, hasPermission, refresh } },
    children
  );
}
