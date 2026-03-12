import type { Metadata } from 'next';
import './globals.css';
import UserMenu from './UserMenu';

export const metadata: Metadata = {
  title: 'UIP - SRE Command Center',
  description: 'Unified Incident Management Platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg">
        <nav className="border-b border-border bg-surface/80 backdrop-blur-sm sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-14">
              <div className="flex items-center gap-6">
                <a href="/" className="text-accent font-bold text-lg tracking-tight">
                  UIP
                </a>
                <div className="flex items-center gap-1">
                  <div className="relative group">
                    <a
                      href="/portal/command-center"
                      className="px-3 py-1.5 text-sm text-muted hover:text-text-bright hover:bg-surface-hover rounded-md transition-colors inline-flex items-center gap-1"
                    >
                      Command Center
                      <svg className="w-3 h-3 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </a>
                    <div className="absolute left-0 top-full pt-1 hidden group-hover:block z-50">
                      <div className="bg-surface border border-border rounded-md shadow-lg py-1 min-w-[160px]">
                        <a href="/portal/command-center" className="block px-4 py-2 text-sm text-muted hover:text-text-bright hover:bg-surface-hover transition-colors">
                          Dashboard
                        </a>
                        <a href="/portal/alerts" className="block px-4 py-2 text-sm text-muted hover:text-text-bright hover:bg-surface-hover transition-colors">
                          All Alerts
                        </a>
                        <a href="/portal/registry-contacts" className="block px-4 py-2 text-sm text-muted hover:text-text-bright hover:bg-surface-hover transition-colors">
                          Registry Contacts
                        </a>
                        <a href="/portal/logs" className="block px-4 py-2 text-sm text-muted hover:text-text-bright hover:bg-surface-hover transition-colors">
                          Logs
                        </a>
                      </div>
                    </div>
                  </div>
                  <NavLink href="/portal/maintenance">Maintenance</NavLink>
                  <NavLink href="/portal/health">Health</NavLink>
                  <NavLink href="/portal/ai-manage">AI Manage</NavLink>
                </div>
              </div>
              <UserMenu />
            </div>
          </div>
        </nav>
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          {children}
        </main>
      </body>
    </html>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      className="px-3 py-1.5 text-sm text-muted hover:text-text-bright hover:bg-surface-hover rounded-md transition-colors"
    >
      {children}
    </a>
  );
}
