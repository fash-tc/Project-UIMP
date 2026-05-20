'use client';

import { useAuth } from '@/lib/auth';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ReactNode } from 'react';
import { ADMIN_TABS } from './_components/tabs';

export default function AdminLayout({ children }: { children: ReactNode }) {
  const { hasPermission, loading } = useAuth();
  const pathname = usePathname();

  if (loading) {
    return <div className="p-8 text-muted">Loading admin…</div>;
  }
  if (!hasPermission('view_admin')) {
    return <div className="p-8 text-red-400">Access denied. Admin permission required.</div>;
  }
  const allowed = ADMIN_TABS.filter((t) => hasPermission(t.perm));
  return (
    <div className="space-y-4">
      <nav className="border-b border-border">
        <ul className="flex gap-1 overflow-x-auto">
          {allowed.map((t) => {
            // Exact match OR strict subpath match (avoids /users matching /users-management)
            const active = pathname === t.href || pathname?.startsWith(t.href + '/');
            return (
              <li key={t.href}>
                <Link
                  href={t.href}
                  className={`inline-block px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
                    active
                      ? 'border-accent text-accent'
                      : 'border-transparent text-muted hover:text-text-bright'
                  }`}
                >
                  {t.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div>{children}</div>
    </div>
  );
}
