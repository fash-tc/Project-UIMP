'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import type { UserProfile } from './types';

interface AuthState {
  user: UserProfile | null;
  permissions: string[];
  loading: boolean;
  hasPermission: (permission: string) => boolean;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  return children;
}

export function useAuth(): AuthState {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/me', { credentials: 'include' })
      .then(async (res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (cancelled) return;
        setUser(data);
        setPermissions(Array.isArray(data?.permissions) ? data.permissions : []);
      })
      .catch(() => {
        if (cancelled) return;
        setUser(null);
        setPermissions([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const hasPermission = useCallback((permission: string) => {
    return permissions.includes(permission) || permissions.includes('*');
  }, [permissions]);

  return { user, permissions, loading, hasPermission };
}

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
