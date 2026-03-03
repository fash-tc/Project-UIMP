import type { Metadata } from 'next';
import './globals.css';

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
                  <NavLink href="/portal/command-center">Command Center</NavLink>
                  <NavLink href="/portal/alerts">Alerts</NavLink>
                  <a
                    href="http://10.177.154.174/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 text-sm text-muted hover:text-text-bright hover:bg-surface-hover rounded-md transition-colors"
                  >
                    Maintenance Tracker
                  </a>
                </div>
              </div>
              <div className="text-xs text-muted">
                Tucows Domains SRE
              </div>
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
