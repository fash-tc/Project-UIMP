'use client';

import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/lib/auth';

export default function UserMenu() {
  const [username, setUsername] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { hasPermission } = useAuth();

  useEffect(() => {
    const match = document.cookie.match(/(?:^|;\s*)uip_user=([^;]*)/);
    if (match) setUsername(decodeURIComponent(match[1]));
  }, []);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open]);

  if (!username) {
    return <div className="text-xs text-muted">Tucows Domains SRE</div>;
  }

  async function handleLogout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/portal/login';
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 text-xs text-muted hover:text-text-bright transition-colors"
      >
        <span className="w-6 h-6 rounded-full bg-accent/20 border border-accent/40 flex items-center justify-center text-accent font-bold text-[10px] uppercase">
          {username[0]}
        </span>
        <span>{username}</span>
        <svg className="w-3 h-3 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[140px] z-50">
          <a
            href="/portal/settings"
            className="block px-4 py-2 text-xs text-muted hover:text-text-bright hover:bg-surface-hover transition-colors"
          >
            Settings
          </a>
          {hasPermission('view_admin') && (
            <a
              href="/portal/admin"
              className="block px-4 py-2 text-xs text-muted hover:text-text-bright hover:bg-surface-hover transition-colors"
            >
              Admin
            </a>
          )}
          <button
            onClick={handleLogout}
            className="block w-full text-left px-4 py-2 text-xs text-muted hover:text-red hover:bg-surface-hover transition-colors"
          >
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
