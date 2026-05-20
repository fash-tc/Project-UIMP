'use client';

import { useAuth } from '@/lib/auth';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { ADMIN_TABS } from './_components/tabs';

export default function AdminIndex() {
  const { hasPermission, loading } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (loading) return;
    // Walk every tab in display order; first one the user can see wins.
    for (const tab of ADMIN_TABS) {
      if (hasPermission(tab.perm)) {
        router.replace(tab.href);
        return;
      }
    }
  }, [loading, hasPermission, router]);
  return <div className="p-8 text-muted">Loading admin…</div>;
}
