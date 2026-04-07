import type { Metadata } from 'next';
import './globals.css';
import UserMenu from './UserMenu';
import { AuthProviderWrapper } from './AuthProviderWrapper';

export const metadata: Metadata = {
  title: 'UIP - SRE Command Center',
  description: 'Unified Incident Management Platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg">
        <AuthProviderWrapper>
          <nav className="border-b border-border bg-surface/80 backdrop-blur-sm sticky top-0 z-50">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex items-center justify-between h-14">
                <div className="flex items-center gap-6">
                  <a href="/" className="text-accent font-bold text-lg tracking-tight">
                    UIP
                  </a>
                  <NavBar />
                </div>
                <UserMenu />
              </div>
            </div>
          </nav>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {children}
          </main>
        </AuthProviderWrapper>
      </body>
    </html>
  );
}

function NavDropdown({ label, href, items }: { label: string; href: string; items: { href: string; label: string }[] }) {
  return (
    <div className="relative group">
      <a
        href={href}
        className="px-3 py-1.5 text-sm text-muted hover:text-text-bright hover:bg-surface-hover rounded-md transition-colors inline-flex items-center gap-1"
      >
        {label}
        <svg className="w-3 h-3 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
      </a>
      <div className="absolute left-0 top-full pt-1 hidden group-hover:block z-50">
        <div className="bg-surface border border-border rounded-lg shadow-xl py-1 min-w-[160px]">
          {items.map(item => (
            <a
              key={item.href}
              href={item.href}
              className="block px-4 py-2 text-sm text-muted hover:text-text-bright hover:bg-surface-hover transition-colors"
            >
              {item.label}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

function NavBar() {
  return (
    <div className="flex items-center gap-1">
      <NavDropdown label="Command Center" href="/portal/command-center" items={[
        { href: '/portal/command-center', label: 'Dashboard' },
        { href: '/portal/logs', label: 'Logs' },
        { href: '/portal/registry', label: 'Registry' },
        { href: '/portal/maintenance', label: 'Maintenance' },
        { href: '/portal/webhooks', label: 'Webhooks' },
      ]} />
      <NavDropdown label="Settings" href="/portal/settings" items={[
        { href: '/portal/settings', label: 'Settings' },
        { href: '/portal/health', label: 'Health' },
        { href: '/portal/ai-manage', label: 'AI Manage' },
      ]} />
      <a
        href="/portal/ai-chat"
        className="px-3 py-1.5 text-sm text-muted hover:text-text-bright hover:bg-surface-hover rounded-md transition-colors"
      >
        AI Chat
      </a>
    </div>
  );
}
